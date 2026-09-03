"""Assembler IPC client — speaks the wire protocol from ``crates/haap-ipc``
(in ``hx_agent_crypto_core``).

Wire format (verified against ``crates/haap-ipc/src/framing.rs``):

    [msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]

``msg_len`` includes the ``msg_type`` byte (so on-wire bytes = 4 + msg_len).
``MAX_MESSAGE_SIZE`` is 64 KiB.

On connect, both sides exchange an ``IpcHandshake`` (msg_type 0x00) with payload
``[protocol_version: u16 BE][major: u16 BE][minor: u16 BE][patch: u16 BE][role: u8]``.
Per ``crates/haap-ipc/src/handshake.rs``, major version MUST match; minor
mismatches are logged warnings only.

Message types (CS v6.0.0 §39.7 channel allowlists, Agent ↔ Assembler):

- ``MSG_TOOL_CALL_REQUEST = 0x52``   — Agent → Assembler, JSON
- ``MSG_TOOL_CALL_RESPONSE = 0x53``  — Assembler → Agent, JSON
- ``MSG_REQUEST_REJECTED = 0x54``    — Assembler → Agent, JSON
- ``MSG_CLARIFICATION_ANSWER = 0x61``— Agent → Assembler, JSON (Profile E)

JSON schemas mirror the serde derives in
``crates/haap-ipc/src/messages/assembler.rs``.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import stat
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from hawcx_haap.errors import HandshakeError, IpcError, RequestRejected

# Default deadline for the Assembler connect + handshake.
#
# Was a hardcoded 5.0. On a supervisor-spawned agent the Assembler is still
# completing its own handshake when the agent dials, and 5s expires mid-flight:
# the agent reports a connect timeout while the Assembler reports nothing at
# all, which reads as "the socket is dead" rather than "we were early". 30s is
# long enough to cover a cold TQS/Authenticator start and short enough that a
# genuinely absent Assembler still fails the turn rather than hanging it.
#
# Env-overridable because the right value is deployment-shaped, not a constant:
# a laptop cold-start and a warm pod are minutes apart in what they need.
_DEFAULT_IPC_TIMEOUT = float(os.environ.get("HAAP_SDK_IPC_TIMEOUT_SECS", "30"))


# ── Protocol constants (mirror crates/haap-ipc/src/handshake.rs) ─────

PROTOCOL_VERSION: int = 1
SDK_VERSION_MAJOR: int = 0
SDK_VERSION_MINOR: int = 5
SDK_VERSION_PATCH: int = 0

ROLE_AGENT: int = 0x04
ROLE_ASSEMBLER: int = 0x05

MSG_TYPE_HANDSHAKE: int = 0x00
MSG_TOOL_CALL_REQUEST: int = 0x52
MSG_TOOL_CALL_RESPONSE: int = 0x53
MSG_REQUEST_REJECTED: int = 0x54
MSG_CLARIFICATION_ANSWER: int = 0x61

MAX_MESSAGE_SIZE: int = 64 * 1024


# ── Public types ────────────────────────────────────────────────────


class TokenTransport(str, Enum):
    """Per-call outbound transport selector.

    - ``http_header`` (default): token in ``Authorization: HAAP <b64>``
      HTTP header.
    - ``mcp_meta``: legacy v6.7.4 §34 carriage. Token placed at
      ``params._meta["haap/tbac"].token``. Retained for compatibility
      with MCP servers that have not yet negotiated v7.2.5; will be
      removed once every shipped server advertises
      ``experimental.hawcx-haap-v7-2-5``.
    - ``mcp_meta_v7_2_5``: current carriage per HAAP v7.2.5 §45.7.5.
      The Assembler places the HAAP token at
      ``params._meta.hawcx.haap_token`` and any OAuth bridging bearer
      at ``params._meta.hawcx.oauth_bearer``. RSV strip-on-egress
      semantics apply: the gateway MUST remove the ``_meta.hawcx``
      envelope before forwarding to the underlying tool. JSON-RPC
      error mapping per §45.7.5: rejection codes ``-32000`` …
      ``-32005`` with ``data.hawcx_reason_code`` carrying the Hawcx
      reason.

    Wire selector change (M-6, 2026-05-20): ``mcp_meta_v7_2_5`` is a
    new selector value; callers must opt in explicitly. The Assembler
    advertises support via the ``experimental.hawcx-haap-v7-2-5``
    capability at MCP ``initialize``; see
    :meth:`AssemblerClient.connect`'s ``experimental_capabilities``
    parameter for the connect-time advertisement.
    """

    HTTP_HEADER = "http_header"
    MCP_META = "mcp_meta"
    MCP_META_V7_2_5 = "mcp_meta_v7_2_5"


#: Capability tag advertised at MCP ``initialize`` time when the
#: Assembler offers the v7.2.5 ``_meta.hawcx`` envelope to an upstream
#: MCP server. Mirrored verbatim into the JSON-RPC initialize
#: ``experimental`` map.
HAWCX_HAAP_V7_2_5_CAPABILITY: str = "hawcx-haap-v7-2-5"


@dataclass
class ToolCallRequest:
    """Agent → Assembler request (msg_type 0x52).

    Mirrors ``haap_ipc::messages::assembler::ToolCallRequest``. The Assembler
    constructs the requested scope from ``tool``/``action``/``resource``/
    ``constraints`` per CS §39.7; the Python process does not see token
    material or session keys.

    ``acting_for_user`` is a v6.9.0-line-163 identity field: when set,
    the Assembler is expected to surface it as
    ``scope_json.user_principal_id`` so the gateway's Cedar policy can
    enforce ``context.user_principal_id == resource.owner_user_id``.
    The agent's pinned ``subject_user_id`` (set at enrollment via the
    AS) is NOT mutated by this field — only the per-call scope_json
    metadata. See CS v6.9.0 line 163 ("any future identity or
    correlation fields") and the CrewAI demo audit Q10/Q13.
    """

    request_id: str
    target_rs_url: str
    http_method: str
    headers: dict[str, str] = field(default_factory=dict)
    tool: str = ""
    # #370: the downstream MCP tool name (kebab route) that becomes the
    # JSON-RPC `params.name` on the `mcp_meta` flight. Distinct from
    # `tool`, which is the dotted TBAC id used for policy/scope matching.
    # `None` leaves the wire unchanged (Assembler falls back to `tool`).
    mcp_tool_name: str | None = None
    action: list[str] = field(default_factory=list)
    resource: str = "*"
    constraints: dict[str, Any] = field(default_factory=dict)
    plaintext_request_body: bytes | None = None
    claimed_intent_hash: str | None = None
    tool_arguments: Any = None
    content_type: str | None = None
    transport: TokenTransport | None = None
    acting_for_user: str | None = None
    # ASS-4: optional OAuth provider id (e.g. "slack") marking this call as
    # bound to an OAuth-protected destination. Mirrors
    # `haap_ipc::messages::assembler::ToolCallRequest.provider`; the Assembler
    # uses it to fetch the EIB bearer / route via the RSV OAuth proxy. `None`
    # leaves the wire unchanged (back-compatible with non-OAuth calls).
    provider: str | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "request_id": self.request_id,
            "target_rs_url": self.target_rs_url,
            "http_method": self.http_method,
            "headers": self.headers,
            "tool": self.tool,
            "action": self.action,
            "resource": self.resource,
            "constraints": self.constraints,
        }
        if self.mcp_tool_name is not None:
            out["mcp_tool_name"] = self.mcp_tool_name
        if self.plaintext_request_body is not None:
            out["plaintext_request_body"] = base64.b64encode(
                self.plaintext_request_body
            ).decode("ascii")
        if self.claimed_intent_hash is not None:
            out["claimed_intent_hash"] = self.claimed_intent_hash
        if self.tool_arguments is not None:
            out["tool_arguments"] = self.tool_arguments
        if self.content_type is not None:
            out["content_type"] = self.content_type
        if self.transport is not None:
            out["transport"] = self.transport.value
        if self.acting_for_user is not None:
            # Top-level wire field, NOT inside `constraints`. The
            # Assembler projects this into `scope_json.user_principal_id`
            # at token-mint time per CS v6.9.0 line 163.
            out["acting_for_user"] = self.acting_for_user
        if self.provider is not None:
            # ASS-4: OAuth provider id (e.g. "slack"). The Assembler uses it to
            # fetch the provider bearer and route the call to the RSV OAuth proxy.
            out["provider"] = self.provider
        return out


@dataclass
class ToolCallResponse:
    """Assembler → Agent response (msg_type 0x53).

    Mirrors ``haap_ipc::messages::assembler::ToolCallResponse``.
    """

    request_id: str
    http_status: int
    headers: dict[str, str]
    body: bytes

    @classmethod
    def from_wire(cls, obj: dict[str, Any]) -> ToolCallResponse:
        body_b64 = obj.get("body", "")
        body = base64.b64decode(body_b64) if body_b64 else b""
        return cls(
            request_id=obj["request_id"],
            http_status=int(obj["http_status"]),
            headers=dict(obj.get("headers") or {}),
            body=body,
        )


# ── Framing helpers (binary, used for handshake) ─────────────────────


def encode_frame(msg_type: int, payload: bytes) -> bytes:
    msg_len = 1 + len(payload)
    if msg_len > MAX_MESSAGE_SIZE:
        raise IpcError(
            f"frame too large: {msg_len} bytes (max {MAX_MESSAGE_SIZE})"
        )
    return struct.pack(">I", msg_len) + bytes([msg_type & 0xFF]) + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IpcError("IPC peer closed connection mid-message")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Read one ``[len: u32 BE][type: u8][payload]`` frame."""
    length_bytes = _recv_exact(sock, 4)
    msg_len = struct.unpack(">I", length_bytes)[0]
    if msg_len == 0:
        raise IpcError("frame length 0 (illegal)")
    if msg_len > MAX_MESSAGE_SIZE:
        raise IpcError(
            f"frame too large: {msg_len} bytes (max {MAX_MESSAGE_SIZE})"
        )
    body = _recv_exact(sock, msg_len)
    msg_type = body[0]
    payload = bytes(body[1:])
    return msg_type, payload


def write_frame(sock: socket.socket, msg_type: int, payload: bytes) -> None:
    sock.sendall(encode_frame(msg_type, payload))


# ── Handshake (mirrors crates/haap-ipc/src/handshake.rs) ─────────────


def _encode_handshake(role: int) -> bytes:
    return struct.pack(
        ">HHHHB",
        PROTOCOL_VERSION,
        SDK_VERSION_MAJOR,
        SDK_VERSION_MINOR,
        SDK_VERSION_PATCH,
        role & 0xFF,
    )


def _decode_handshake(payload: bytes) -> tuple[int, int, int, int, int]:
    if len(payload) < 9:
        raise IpcError(f"handshake payload too short: {len(payload)} (want >=9)")
    proto, major, minor, patch, role = struct.unpack(">HHHHB", payload[:9])
    return proto, major, minor, patch, role


def perform_handshake(sock: socket.socket, local_role: int = ROLE_AGENT) -> int:
    """Send local handshake, read peer handshake, validate major version.

    Returns the peer's role byte. Raises :class:`HandshakeError` on major
    version mismatch.
    """
    write_frame(sock, MSG_TYPE_HANDSHAKE, _encode_handshake(local_role))
    msg_type, payload = read_frame(sock)
    if msg_type != MSG_TYPE_HANDSHAKE:
        raise IpcError(
            f"expected handshake (0x00), got 0x{msg_type:02x}"
        )
    _proto, major, _minor, _patch, role = _decode_handshake(payload)
    if major != SDK_VERSION_MAJOR:
        raise HandshakeError(local_major=SDK_VERSION_MAJOR, remote_major=major)
    return role


# ── Platform-aware socket connect ────────────────────────────────────


def _validate_ipc_socket_path(socket_path: str) -> os.stat_result | None:
    """H-4 (2026-05-20) — validate UID + parent-dir mode before connect.

    Refuses sockets whose owner UID differs from
    ``HAAP_SDK_EXPECTED_PEER_UID`` (or the socket file's own uid when
    the env var is unset), and refuses parent directories whose owner
    UID differs from ``os.getuid()`` or whose mode has any group/other
    bit set (mask ``0o077``).

    The previous client connected to any socket the kernel let it
    ``connect(2)`` — which on a shared ``/tmp/hawcx/`` is "any process
    on the host". This pre-connect stat catches the cross-UID case
    before any handshake bytes are exchanged.

    No-op on Windows: Named Pipe ACLs are handled by the kernel at
    ``CreateFileW`` time and surface as ``OSError(EACCES)`` from the
    pipe-open path; nothing to stat here.

    INF-08: returns the validated ``stat_result`` so the caller can
    re-verify the connected peer (SO_PEERCRED) and/or re-stat the path to
    detect a TOCTOU swap between this check and ``connect``. Returns
    ``None`` on Windows.
    """
    if sys.platform == "win32":
        return None

    sock_path = Path(socket_path)
    try:
        sock_stat = sock_path.stat()
    except OSError as e:
        raise IpcError(f"stat {socket_path} failed: {e}") from e
    if not stat.S_ISSOCK(sock_stat.st_mode):
        raise IpcError(f"{socket_path} is not a Unix domain socket")

    expected_env = os.environ.get("HAAP_SDK_EXPECTED_PEER_UID")
    if expected_env is not None:
        try:
            expected_uid = int(expected_env, 10)
        except ValueError as e:
            raise IpcError(
                f"HAAP_SDK_EXPECTED_PEER_UID={expected_env!r} is not a valid uid"
            ) from e
    else:
        expected_uid = sock_stat.st_uid

    # H-4's inode-owner-vs-expected-peer comparison is REMOVED (Ravi, 2026-08-30).
    #
    # It compared a file OWNERSHIP stat against a peer-PROCESS expectation, and
    # `agent-assembler-N.sock` is the one socket where those are deliberately
    # different principals: root binds it, `bind_peer_owned_uds` fchowns it to
    # the LLM principal (ownership governs connect()), and the Assembler accepts
    # on the inherited fd as the CREDENTIAL principal -- which is what
    # HAAP_SDK_EXPECTED_PEER_UID names. See graph.rs:4318-4333 and 5781-5785.
    #
    # The comparison could never fire correctly:
    #   unset -> expected_uid = sock_stat.st_uid, so the test is `x != x`
    #   set   -> CAS deliberately makes the two differ: guaranteed false positive
    #
    # The surviving control is stronger and untouched: `_verify_peer_after_connect`
    # reads SO_PEERCRED off the CONNECTED socket and compares it to the credential
    # principal -- kernel-attested and immune to the path swap a pre-connect stat
    # can never catch. `expected_uid` is still resolved above because that
    # function reuses the same env resolution.
    #
    # This removes a check that was structurally incapable of working; it does
    # not loosen the peer-identity guarantee.

    parent = sock_path.parent
    try:
        parent_stat = parent.stat()
    except OSError as e:
        raise IpcError(f"stat parent dir {parent} failed: {e}") from e

    our_uid = os.getuid()
    # Root is a trusted creator, matching the Rust side's rule.
    #
    # `validate_socket_parent_dir` (haap-proc-hardening) requires every ancestor
    # to be "owned by this process's own euid (or root)". Dropping the root
    # allowance here makes the Python SDK strictly stricter than the Rust one in
    # a way that can never succeed under the shipping layout: the supervisor
    # creates <base>/<agent_id>/ as root before dropping to the per-agent uid, so
    # a supervisor-spawned agent ALWAYS sees a root-owned parent and refuses
    # every connect. A dir root created is not "created by another user" in the
    # sense this check exists to catch -- root is the one principal that could
    # subvert us anyway, and the mode check below still rejects group/other
    # write, so an unprivileged attacker cannot plant anything here.
    if parent_stat.st_uid not in (our_uid, 0):
        raise IpcError(
            f"IPC parent dir {parent} is owned by uid {parent_stat.st_uid}, "
            f"this process is uid {our_uid}; refusing to use a dir "
            "created by another user"
        )
    parent_perms = parent_stat.st_mode & 0o777
    # Group/other WRITE, not group/other anything -- again matching Rust.
    #
    # `validate_socket_parent_dir` requires the chain carry "no group/other
    # write bit" (0o022). Checking 0o077 additionally rejects the execute bit,
    # and execute is exactly what the supervisor's layout needs: <base>/<id>/ is
    # root-owned and mode 711 so the per-agent uid can TRAVERSE to the socket
    # without being able to list the directory. Demanding 700 is unsatisfiable
    # here -- a root-owned 700 dir is one the agent cannot enter at all, so the
    # stricter rule does not harden this path, it closes it.
    #
    # Write is the bit that matters: it is what would let another principal
    # plant or swap a socket. Execute-only traversal grants none of that.
    if parent_perms & 0o022 != 0:
        # INF-08: setting HAAP_SDK_ALLOW_TMP_IPC=1 relaxes the parent-dir MODE
        # requirement for the legacy /tmp/hawcx/ path. That REOPENS the
        # stat→connect TOCTOU window for that path, since a group/other-WRITABLE
        # parent lets another user swap the socket. The post-connect
        # SO_PEERCRED / re-stat check in _verify_peer_after_connect is the
        # backstop that still catches a swap on that opt-in path.
        #
        # It gates the mode branch ONLY -- not the owner check above. An earlier
        # version of this comment claimed "(and owner)", which is wrong and sends
        # an operator to set a flag that stops them one check earlier.
        if os.environ.get("HAAP_SDK_ALLOW_TMP_IPC") != "1":
            raise IpcError(
                f"IPC parent dir {parent} has mode {parent_perms:o}; "
                "refusing to use a dir that is group- or other-WRITABLE. "
                "Do NOT chmod 700 a supervisor-managed dir: the per-agent dir is "
                "deliberately 0711 so the agent principal can traverse it, 0700 "
                "makes every consumer fail with EACCES, and the supervisor resets "
                "it to 0711 on next launch. HAAP_SDK_ALLOW_TMP_IPC=1 opts into "
                "the legacy /tmp/hawcx/ path and does not apply here."
            )

    return sock_stat


def _verify_peer_after_connect(
    sock: socket.socket, pre_stat: os.stat_result, socket_path: str
) -> None:
    """INF-08: close the stat→connect TOCTOU window after ``connect``.

    Two complementary checks:

    1. ``SO_PEERCRED`` (Linux) — read the kernel-attested peer credentials
       of the *connected* socket and assert the peer UID equals the UID we
       validated. This is OS-enforced peer identity: it cannot be defeated
       by a path swap, because it reflects the process actually on the
       other end of *this* connection.
    2. A path re-stat fallback — on platforms without ``SO_PEERCRED``
       (e.g. macOS, where ``LOCAL_PEERCRED`` is not exposed by the stdlib
       ``socket`` module), re-stat the path and assert it still resolves to
       the same ``(st_dev, st_ino, st_uid)`` we validated. A swap changes
       the inode, so a replaced socket is rejected.

    Raises ``IpcError`` on any mismatch. The expected UID honours
    ``HAAP_SDK_EXPECTED_PEER_UID`` (same resolution as the pre-connect
    check), defaulting to the validated socket's own owner UID.
    """
    expected_env = os.environ.get("HAAP_SDK_EXPECTED_PEER_UID")
    expected_uid = int(expected_env, 10) if expected_env is not None else pre_stat.st_uid

    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; } — three native
        # ints. Read uid (the 2nd field) and compare.
        creds = sock.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
        _pid, peer_uid, _gid = struct.unpack("3i", creds)
        if peer_uid != expected_uid:
            sock.close()
            raise IpcError(
                f"IPC peer on {socket_path} has uid {peer_uid}, expected "
                f"{expected_uid} (SO_PEERCRED); refusing the connection"
            )
        return

    # No SO_PEERCRED (macOS): fall back to a post-connect path re-stat.
    try:
        post_stat = Path(socket_path).stat()
    except OSError as e:
        sock.close()
        raise IpcError(f"re-stat {socket_path} after connect failed: {e}") from e
    if (
        not stat.S_ISSOCK(post_stat.st_mode)
        or post_stat.st_dev != pre_stat.st_dev
        or post_stat.st_ino != pre_stat.st_ino
        or post_stat.st_uid != pre_stat.st_uid
    ):
        sock.close()
        raise IpcError(
            f"IPC socket {socket_path} changed identity between validation and "
            "connect (possible TOCTOU swap); refusing the connection"
        )


def _connect_unix(path: str, timeout_secs: float | None) -> socket.socket:
    pre_stat = _validate_ipc_socket_path(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if timeout_secs is not None:
        sock.settimeout(timeout_secs)
    sock.connect(path)
    # INF-08: pre_stat is None only on Windows, which never reaches this
    # AF_UNIX path; guard anyway for type-narrowing.
    if pre_stat is not None:
        _verify_peer_after_connect(sock, pre_stat, path)
    return sock


def _connect_named_pipe(path: str, timeout_secs: float | None) -> _WindowsPipeSocket:
    # Lazy import — Windows-only path. Implemented in pipe_win.py.
    from hawcx_haap import pipe_win  # noqa: WPS433

    return pipe_win.connect(path, timeout_secs=timeout_secs)


def connect_assembler(endpoint: str, *, timeout_secs: float | None = _DEFAULT_IPC_TIMEOUT) -> socket.socket:
    """Open a transport to the Assembler endpoint.

    On Unix, ``endpoint`` is a filesystem path to a UDS. On Windows, it is a
    Named Pipe path (``\\\\.\\pipe\\haap-<agent_id>-agent-assembler-<index>``).
    Returns a ``socket.socket``-compatible object (real ``socket`` on Unix; a
    file-handle-backed wrapper on Windows).
    """
    if sys.platform == "win32":
        return _connect_named_pipe(endpoint, timeout_secs)  # type: ignore[return-value]
    return _connect_unix(endpoint, timeout_secs)


# ── AssemblerClient ─────────────────────────────────────────────────


class AssemblerClient:
    """Synchronous client for the Assembler IPC channel.

    On construction, performs the version handshake (role = Agent). After that
    the connection is ready for ToolCallRequest / ToolCallResponse round-trips.
    """

    def __init__(
        self,
        sock: socket.socket,
        experimental_capabilities: tuple[str, ...] = (),
    ) -> None:
        self._sock = sock
        # Experimental MCP capabilities the SDK advertises on this
        # connection. The Assembler echoes these into the
        # ``experimental`` field of its outbound MCP ``initialize``
        # calls so the upstream MCP server can negotiate features.
        # Today the only entry is ``hawcx-haap-v7-2-5`` (M-6).
        self._experimental_capabilities = experimental_capabilities

    @classmethod
    def connect(
        cls,
        endpoint: str,
        *,
        timeout_secs: float | None = _DEFAULT_IPC_TIMEOUT,
        experimental_capabilities: tuple[str, ...] = (),
    ) -> AssemblerClient:
        """Connect, handshake, and return a client.

        ``experimental_capabilities`` is a tuple of capability tags the
        SDK advertises via the Assembler to upstream MCP servers (HAAP
        v7.2.5 §45.7.5). Pass ``(HAWCX_HAAP_V7_2_5_CAPABILITY,)`` to
        enable v7.2.5 payload carriage end-to-end. Empty tuple
        (default) means legacy v6.7.4 carriage only.
        """
        sock = connect_assembler(endpoint, timeout_secs=timeout_secs)
        try:
            peer_role = perform_handshake(sock, local_role=ROLE_AGENT)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise
        if peer_role != ROLE_ASSEMBLER:
            try:
                sock.close()
            except Exception:
                pass
            raise IpcError(
                f"expected peer role Assembler (0x05), got 0x{peer_role:02x}"
            )
        client = cls(sock, experimental_capabilities=experimental_capabilities)
        # Remember how we got here so `invoke` can re-dial. The Assembler
        # serves ONE request per accepted connection (its accept loop calls
        # `handle_agent_request`, which reads exactly one frame and returns,
        # dropping the stream), while this client holds `self._sock` for the
        # life of the object. Without the endpoint we cannot recover.
        client._endpoint = endpoint
        client._timeout_secs = timeout_secs
        return client

    def _reconnect(self) -> None:
        """Re-dial the Assembler and redo the handshake.

        Needed because the Assembler is single-request-per-connection: after
        it answers (or REJECTS) one ToolCallRequest it drops the stream, so
        the second `invoke` on the same client writes into a closed socket
        and raises BrokenPipeError. That looked like a transport fault for a
        long time; it is a protocol mismatch between the two sides.
        """
        if not getattr(self, "_endpoint", None):
            raise IpcError(
                "assembler connection is closed and this client has no endpoint "
                "to re-dial (it was constructed from a bare socket)"
            )
        try:
            self._sock.close()
        except Exception:
            pass
        fresh = type(self).connect(
            self._endpoint,
            timeout_secs=getattr(self, "_timeout_secs", _DEFAULT_IPC_TIMEOUT),
            experimental_capabilities=self._experimental_capabilities,
        )
        self._sock = fresh._sock

    def invoke(self, req: ToolCallRequest) -> ToolCallResponse:
        """Send a ToolCallRequest; await ToolCallResponse or RequestRejected.

        Raises :class:`RequestRejected` if the Assembler rejects.
        Raises :class:`IpcError` on framing / transport errors.

        Transparently re-dials once if the connection was already spent: the
        Assembler closes it after every request, so any call after the first
        would otherwise fail with a broken pipe rather than a verdict. A
        RequestRejected is a VERDICT and is raised, never retried — retrying a
        refusal would turn one denial into two attempts at the same action.
        """
        try:
            return self._invoke_once(req)
        except (BrokenPipeError, ConnectionResetError, EOFError):
            # The WRITE hit the closed socket.
            self._reconnect()
            return self._invoke_once(req)
        except IpcError as e:
            # The write landed in the socket buffer and the READ found the
            # peer gone: `read_frame` reports that as IpcError("IPC peer
            # closed connection mid-message"), not an OSError. Only that
            # shape is retried — a genuine framing violation (bad length,
            # unknown opcode, short handshake) is a protocol error and
            # must surface, not be papered over by a second attempt.
            if "closed connection" not in str(e):
                raise
            self._reconnect()
            return self._invoke_once(req)

    def _invoke_once(self, req: ToolCallRequest) -> ToolCallResponse:
        wire = req.to_wire()
        # Forward the connection-level experimental capability list on
        # every call so the Assembler can re-key its MCP initialize
        # when a new upstream server is contacted. Wire key matches
        # the Rust-side serde rename.
        if self._experimental_capabilities:
            wire["hawcx_experimental_capabilities"] = list(
                self._experimental_capabilities
            )
        payload = json.dumps(wire, separators=(",", ":")).encode("utf-8")
        write_frame(self._sock, MSG_TOOL_CALL_REQUEST, payload)

        msg_type, body = read_frame(self._sock)
        if msg_type == MSG_TOOL_CALL_RESPONSE:
            obj = json.loads(body.decode("utf-8"))
            return ToolCallResponse.from_wire(obj)
        if msg_type == MSG_REQUEST_REJECTED:
            obj = json.loads(body.decode("utf-8"))
            raise RequestRejected(
                request_id=obj.get("request_id", req.request_id),
                reason=obj.get("reason", ""),
            )
        raise IpcError(
            f"unexpected response msg_type 0x{msg_type:02x}; "
            "expected 0x53 (ToolCallResponse) or 0x54 (RequestRejected)"
        )

    def send_clarification_answer(
        self,
        pending_id: str,
        session_id: int,
        *,
        answer_index: int | None = None,
        answer_text: str | None = None,
    ) -> None:
        """Profile E first hop: send a clarification answer (msg_type 0x61).

        Per CS v6.7.4 §39.7 the answer is forwarded by the Assembler to the
        TQS as the second hop (0x5E).
        """
        obj: dict[str, Any] = {
            "pending_id": pending_id,
            "session_id": int(session_id),
        }
        if answer_index is not None:
            obj["answer_index"] = int(answer_index)
        if answer_text is not None:
            obj["answer_text"] = answer_text
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        write_frame(self._sock, MSG_CLARIFICATION_ANSWER, payload)

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass

    def __enter__(self) -> AssemblerClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# Forward declaration helper for type hints when pipe_win is missing on Unix.
class _WindowsPipeSocket:  # pragma: no cover — Windows-only
    """Shape placeholder; real impl in ``hawcx_haap.pipe_win``."""
