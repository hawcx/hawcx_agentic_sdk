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
import binascii
import json
import math
import os
import socket
import stat
import struct
import sys
import threading
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from hawcx_haap.errors import HandshakeError, HawcxError, IpcError, RequestRejected


def _validate_ipc_timeout(timeout_secs: float | None, name: str = "timeout_secs") -> float | None:
    if timeout_secs is None:
        return None
    if isinstance(timeout_secs, bool) or not (
        type(timeout_secs) is int or type(timeout_secs) is float
    ):
        raise TypeError(f"{name} must be float or None; got {type(timeout_secs).__name__}")
    val = float(timeout_secs)
    if math.isnan(val) or math.isinf(val) or val < 0:
        raise ValueError(f"{name} must be a finite non-negative number; got {timeout_secs!r}")
    return val


_FORBIDDEN_CONSTRAINT_AUTHORITY_KEYS: frozenset[str] = frozenset(
    {"user_principal_id", "acting_for_user", "user_subject"}
)


def _normalize_wire_key(key: str) -> str:
    nfkc = unicodedata.normalize("NFKC", key)
    cleaned = "".join(
        ch
        for ch in nfkc
        if not ch.isspace()
        and ord(ch) > 0x20
        and ord(ch) != 0x7F
        and not unicodedata.category(ch).startswith("C")
    )
    return cleaned.casefold()


def _scan_constraints_node(
    node: Any,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
    max_depth: int = 64,
) -> None:
    if _depth > max_depth:
        raise ValueError(f"constraints exceed maximum nesting depth ({max_depth})")
    if isinstance(node, dict):
        seen = _seen if _seen is not None else set()
        obj_id = id(node)
        if obj_id in seen:
            raise ValueError("cyclic container inside constraints")
        seen.add(obj_id)
        try:
            for k, v in node.items():
                if not isinstance(k, str):
                    raise TypeError("constraints keys must be strings")
                norm_k = _normalize_wire_key(k)
                if norm_k == "provider":
                    raise ValueError(
                        "ToolCallRequest.provider must be passed as the top-level `provider` "
                        "field, never nested inside `constraints` (FIX-017)"
                    )
                if norm_k in _FORBIDDEN_CONSTRAINT_AUTHORITY_KEYS:
                    raise HawcxError(
                        f"E_AUTHORITY_CLAIM (0x0058): authority field {k!r} is forbidden "
                        "inside constraints"
                    )
                if norm_k == "ciba_approved" and v is not False:
                    raise HawcxError(
                        "E_AUTHORITY_CLAIM (0x0058): ciba_approved in constraints must not "
                        "be set to a non-False value by the caller"
                    )
                _scan_constraints_node(v, _depth=_depth + 1, _seen=seen, max_depth=max_depth)
        finally:
            seen.discard(obj_id)
    elif isinstance(node, (list, tuple, set, frozenset)):
        seen = _seen if _seen is not None else set()
        obj_id = id(node)
        if obj_id in seen:
            raise ValueError("cyclic container inside constraints")
        seen.add(obj_id)
        try:
            for item in node:
                _scan_constraints_node(item, _depth=_depth + 1, _seen=seen, max_depth=max_depth)
        finally:
            seen.discard(obj_id)


def _validate_constraints(constraints: dict[str, Any] | None) -> dict[str, Any]:
    if constraints is None:
        return {}
    if not isinstance(constraints, dict):
        raise TypeError(
            f"constraints must be dict[str, Any] or None; got {type(constraints).__name__}"
        )
    _scan_constraints_node(constraints)
    if "max_requests" in constraints and constraints["max_requests"] is not None:
        max_req = constraints["max_requests"]
        if not (type(max_req) is int and not isinstance(max_req, bool)):
            raise TypeError(
                f"constraints['max_requests'] must be int; got {type(max_req).__name__}"
            )
        if not (0 <= max_req <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(f"constraints['max_requests'] out of u64 range: {max_req}")
    if "require_pop" in constraints and constraints["require_pop"] is not None:
        req_pop = constraints["require_pop"]
        if not isinstance(req_pop, bool):
            raise TypeError(
                f"constraints['require_pop'] must be bool; got {type(req_pop).__name__}"
            )
    return dict(constraints)


def _validate_tool_arguments(tool_arguments: Any) -> dict[str, Any] | None:
    if tool_arguments is None:
        return None
    if not isinstance(tool_arguments, dict):
        raise TypeError(
            f"tool_arguments must be dict[str, Any] or None; got {type(tool_arguments).__name__}"
        )
    if not all(isinstance(k, str) for k in tool_arguments):
        raise TypeError("tool_arguments keys must be strings")
    return dict(tool_arguments)


def _validate_provider(provider: str | None) -> str | None:
    if provider is None:
        return None
    if not isinstance(provider, str):
        raise TypeError(f"provider must be str or None; got {type(provider).__name__}")
    if (
        not provider
        or provider != provider.strip()
        or any(
            ord(c) < 0x20 or ord(c) == 0x7F or unicodedata.category(c).startswith("C")
            for c in provider
        )
    ):
        raise ValueError(
            "provider must be a non-empty string without leading/trailing whitespace "
            "or control characters"
        )
    return provider


def _validate_headers_i2(headers: dict[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise TypeError(f"headers must be dict[str, str] or None; got {type(headers).__name__}")
    parent_record_count = 0
    out: dict[str, str] = {}
    for k, v in headers.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError("header names and values must be strings")
        if (
            any(ch in k or ch in v for ch in ("\r", "\n", "\x00"))
            or not k.strip()
            or k != k.strip()
            or any(
                ch.isspace()
                or ch == ":"
                or ord(ch) < 0x20
                or ord(ch) == 0x7F
                or unicodedata.category(ch).startswith("C")
                for ch in k
            )
        ):
            raise ValueError(
                "header names and values must be valid HTTP header strings without CR, LF, or NUL"
            )
        if _normalize_wire_key(k) == "x-hawcx-parent-call-record":
            parent_record_count += 1
        out[k] = v
    if parent_record_count > 1:
        raise HawcxError(
            "E_AUTHORITY_CLAIM (0x0058): duplicate X-Hawcx-Parent-Call-Record header is forbidden"
        )
    return out

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

# Default deadline for a tool call's reply, once connected (#129).
#
# NOT the connect deadline above. A call held for human step-up (CIBA) gets no
# bytes until the hold resolves: the Assembler polls the JIT for up to 120s
# (`PENDING_ENTRY_DEFAULT_TTL_SECS`, hx_agent_client_auth_service
# haap-tqs-common/src/partial_token.rs) and then still makes the RS request
# (30s, `HAAP_ASSEMBLER_HTTP_TIMEOUT_MS`). When the connect deadline also
# governed this wait, macOS/Linux gave up on every held call at 30s while the
# human's approval was still open. 180s covers 120 + 30 with slack.
_DEFAULT_TOOL_CALL_TIMEOUT = float(os.environ.get("HAAP_SDK_TOOL_CALL_TIMEOUT_SECS", "180"))


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

# macOS / Darwin LOCAL_PEERCRED constants (<sys/un.h>, <sys/ucred.h>).
# CPython's stdlib `socket` exposes Linux `SO_PEERCRED` but omits Darwin's
# `SOL_LOCAL` / `LOCAL_PEERCRED`, so we pass the kernel ABI values directly to
# `sock.getsockopt(...)` with zero native extensions.
#
#   struct xucred {
#       u_int   cr_version;          /* XUCRED_VERSION == 0 */
#       uid_t   cr_uid;              /* effective user id */
#       short   cr_ngroups;          /* number of groups */
#       /* 2-byte native alignment pad */
#       gid_t   cr_groups[16];       /* groups */
#   };  /* sizeof == 76 bytes on arm64/x86_64 Darwin */
_SOL_LOCAL: int = 0
_LOCAL_PEERCRED: int = 0x001
_XUCRED_VERSION: int = 0
_XUCRED_FMT: str = "IIh16I"


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
        validated_headers = _validate_headers_i2(self.headers)
        validated_constraints = _validate_constraints(self.constraints)
        validated_tool_args = _validate_tool_arguments(self.tool_arguments)
        validated_provider = _validate_provider(self.provider)
        out: dict[str, Any] = {
            "request_id": self.request_id,
            "target_rs_url": self.target_rs_url,
            "http_method": self.http_method,
            "headers": validated_headers,
            "tool": self.tool,
            "action": self.action,
            "resource": self.resource,
            "constraints": validated_constraints,
        }
        if self.mcp_tool_name is not None:
            out["mcp_tool_name"] = self.mcp_tool_name
        if self.plaintext_request_body is not None:
            out["plaintext_request_body"] = base64.b64encode(
                self.plaintext_request_body
            ).decode("ascii")
        if self.claimed_intent_hash is not None:
            out["claimed_intent_hash"] = self.claimed_intent_hash
        if validated_tool_args is not None:
            out["tool_arguments"] = validated_tool_args
        if self.content_type is not None:
            out["content_type"] = self.content_type
        if self.transport is not None:
            out["transport"] = self.transport.value
        if self.acting_for_user is not None:
            # Top-level wire field, NOT inside `constraints`. The
            # Assembler projects this into `scope_json.user_principal_id`
            # at token-mint time per CS v6.9.0 line 163.
            out["acting_for_user"] = self.acting_for_user
        if validated_provider is not None:
            # ASS-4: OAuth provider id (e.g. "slack"). The Assembler uses it to
            # fetch the provider bearer and route the call to the RSV OAuth proxy.
            out["provider"] = validated_provider
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
        if not isinstance(obj, dict):
            raise IpcError(
                f"ToolCallResponse wire payload must be a JSON object; got {type(obj).__name__}"
            )
        if obj.get("reject_code") is not None or obj.get("error") is not None:
            raise IpcError("contradictory ToolCallResponse carries reject_code or error")
        request_id = obj.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise IpcError("ToolCallResponse.request_id must be a non-empty string")
        raw_status = obj.get("http_status")
        if not (type(raw_status) is int and not isinstance(raw_status, bool)) or not (
            0 <= raw_status <= 0xFFFF
        ):
            raise IpcError(
                f"ToolCallResponse.http_status must be an int in 0..65535; got {raw_status!r}"
            )
        raw_headers = obj.get("headers")
        if raw_headers is None:
            headers: dict[str, str] = {}
        elif isinstance(raw_headers, dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw_headers.items()
        ):
            headers = dict(raw_headers)
        else:
            raise IpcError(
                "ToolCallResponse.headers must be a JSON object of string keys and values"
            )
        body_b64 = obj.get("body", "")
        if not isinstance(body_b64, str):
            raise IpcError("ToolCallResponse.body must be a base64 string")
        try:
            body = base64.b64decode(body_b64, validate=True) if body_b64 else b""
        except (binascii.Error, ValueError) as e:
            raise IpcError(f"ToolCallResponse.body is not valid base64: {e}") from e
        return cls(
            request_id=request_id,
            http_status=raw_status,
            headers=headers,
            body=body,
        )


# ── Framing helpers (binary, used for handshake) ─────────────────────


def encode_frame(msg_type: int, payload: bytes) -> bytes:
    if not (type(msg_type) is int and not isinstance(msg_type, bool)) or not (
        0 <= msg_type <= 0xFF
    ):
        raise IpcError(f"invalid IPC msg_type: {msg_type!r}")
    msg_len = 1 + len(payload)
    if msg_len > MAX_MESSAGE_SIZE:
        raise IpcError(
            f"frame too large: {msg_len} bytes (max {MAX_MESSAGE_SIZE})"
        )
    return struct.pack(">I", msg_len) + bytes([msg_type]) + payload


class _PeerClosedError(IpcError):
    """Raised when the IPC peer cleanly closed the stream before frame start."""


def _recv_exact(
    sock: socket.socket, n: int, *, clean_eof_ok: bool = False
) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if clean_eof_ok and len(buf) == 0:
                raise _PeerClosedError("IPC peer closed connection mid-message")
            raise IpcError("IPC peer closed connection mid-message")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    """Read one ``[len: u32 BE][type: u8][payload]`` frame."""
    length_bytes = _recv_exact(sock, 4, clean_eof_ok=True)
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
    if not (type(role) is int and not isinstance(role, bool)) or not (0 <= role <= 0xFF):
        raise IpcError(f"invalid handshake role: {role!r}")
    return struct.pack(
        ">HHHHB",
        PROTOCOL_VERSION,
        SDK_VERSION_MAJOR,
        SDK_VERSION_MINOR,
        SDK_VERSION_PATCH,
        role,
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
    proto, major, _minor, _patch, role = _decode_handshake(payload)
    if proto != PROTOCOL_VERSION:
        raise IpcError(
            f"unsupported IPC protocol version {proto} (expected {PROTOCOL_VERSION})"
        )
    if major != SDK_VERSION_MAJOR:
        raise HandshakeError(local_major=SDK_VERSION_MAJOR, remote_major=major)
    return role


# ── Platform-aware socket connect ────────────────────────────────────


def _diagnosable_ipc_error(
    endpoint: str, op: str, timeout_secs: float | None, exc: BaseException
) -> IpcError:
    """Wrap a bare stdlib exception from ``op`` into an ``IpcError`` that
    names the endpoint, the operation, and the underlying exception TYPE.

    2026-09-21 UKG demo: ``str(TimeoutError())`` is exactly ``"timed out"`` --
    no endpoint, no operation, no type -- because ``sock.settimeout()``
    governs both ``connect()`` and the handshake ``recv()`` that follows it,
    and that bare exception propagated verbatim to the operator. A reader
    could not tell a stalled Assembler (accepts, never replies -- the
    supervisor spawns the agent before the Assembler, so the listener's
    backlog silently accepts a connect nobody is behind yet) from an absent
    one (no socket file at all) from the message alone. Including
    ``type(exc).__name__`` is what makes those cases distinguishable without
    a debugger: ``TimeoutError`` is a stall, ``FileNotFoundError`` /
    ``ConnectionRefusedError`` is absent, an ``IpcError`` (e.g. "peer closed
    connection mid-message") is a handshake that started and was abandoned.
    """
    deadline = f"{timeout_secs}s" if timeout_secs is not None else "no deadline"
    return IpcError(
        f"{op} to Assembler endpoint {endpoint!r} failed (deadline: {deadline}): "
        f"{type(exc).__name__}: {exc}"
    )


def _resolve_expected_peer_uid(sock_stat: os.stat_result) -> int:
    """Resolve the expected peer UID from ``HAAP_SDK_EXPECTED_PEER_UID`` or ``sock_stat.st_uid``."""
    expected_env = os.environ.get("HAAP_SDK_EXPECTED_PEER_UID")
    if expected_env is None:
        return sock_stat.st_uid
    stripped = expected_env.strip()
    if not stripped or not stripped.isdigit():
        raise IpcError(
            f"HAAP_SDK_EXPECTED_PEER_UID={expected_env!r} is not a valid uid"
        )
    expected_uid = int(stripped, 10)
    if expected_uid < 0 or expected_uid > 0xFFFFFFFF:
        raise IpcError(
            f"HAAP_SDK_EXPECTED_PEER_UID={expected_env!r} is not a valid uid"
        )
    return expected_uid


def _validate_ipc_socket_path(socket_path: str) -> os.stat_result | None:
    """H-4 (2026-05-20) — validate socket type, UID syntax, and parent-dir mode before connect.

    Validates ``HAAP_SDK_EXPECTED_PEER_UID`` (if set) before ``connect(2)``
    and refuses parent directories whose owner UID is neither ``os.getuid()``
    nor ``0`` (root), or whose mode has any group/other write bit set
    (mask ``0o022``) unless ``HAAP_SDK_ALLOW_TMP_IPC=1`` is set.

    No-op on Windows: Named Pipe ACLs are handled by the kernel at
    ``CreateFileW`` time and surface as ``OSError(EACCES)`` from the
    pipe-open path; nothing to stat here.

    INF-08: returns the validated ``stat_result`` so the caller can
    re-verify the connected peer (``SO_PEERCRED`` on Linux, ``LOCAL_PEERCRED``
    on macOS) in :func:`_verify_peer_after_connect`. Returns ``None`` on
    Windows.
    """
    if sys.platform == "win32":
        return None

    sock_path = Path(socket_path)
    try:
        sock_stat = sock_path.stat()
    except OSError as e:
        # The "socket absent" half of the stall-vs-absent distinction: a
        # missing socket file raises here as FileNotFoundError, named
        # explicitly so it reads as "absent", not "timed out" (see
        # _diagnosable_ipc_error).
        raise IpcError(f"stat {socket_path} failed: {type(e).__name__}: {e}") from e
    if not stat.S_ISSOCK(sock_stat.st_mode):
        raise IpcError(f"{socket_path} is not a Unix domain socket")

    # Validate HAAP_SDK_EXPECTED_PEER_UID syntax before connect(); the actual
    # kernel-attested peer-UID comparison runs in _verify_peer_after_connect.
    _resolve_expected_peer_uid(sock_stat)

    # H-4's inode-owner-vs-expected-peer comparison is REMOVED (Ravi, 2026-08-30).
    #
    # It compared a file OWNERSHIP stat against a peer-PROCESS expectation, and
    # `agent-assembler-N.sock` is the one socket where those are deliberately
    # different principals: root binds it, `bind_peer_owned_uds` fchowns it to
    # the LLM principal (ownership governs connect()), and the Assembler accepts
    # on the inherited fd as the CREDENTIAL principal -- which is what
    # HAAP_SDK_EXPECTED_PEER_UID names. See graph.rs:4318-4333 and 5781-5785.
    #
    # The surviving control is stronger and kernel-attested:
    # `_verify_peer_after_connect` reads SO_PEERCRED (Linux) or LOCAL_PEERCRED
    # (macOS) off the CONNECTED socket and compares it to the credential
    # principal -- immune to the path swap a pre-connect stat can never catch.

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

    Kernel-attested peer credential verification on the *connected* socket:

    1. ``SO_PEERCRED`` (Linux) — reads ``struct ucred`` via ``SOL_SOCKET`` /
       ``SO_PEERCRED`` and asserts ``peer_uid == expected_uid``.
    2. ``LOCAL_PEERCRED`` (macOS / Darwin) — reads ``struct xucred`` via
       ``SOL_LOCAL`` (0) / ``LOCAL_PEERCRED`` (0x001), verifies
       ``cr_version == 0``, and asserts ``cr_uid == expected_uid``.
    3. Other POSIX platforms without ``SO_PEERCRED`` / Darwin ``LOCAL_PEERCRED``:
       fails closed if ``HAAP_SDK_EXPECTED_PEER_UID`` is explicitly set;
       otherwise falls back to a post-connect path re-stat asserting
       ``(st_dev, st_ino, st_uid)`` did not change.

    Raises ``IpcError`` on any mismatch or syscall failure (closing ``sock``
    before raising). The expected UID honours ``HAAP_SDK_EXPECTED_PEER_UID``,
    defaulting to the validated socket's own owner UID.
    """
    expected_uid = _resolve_expected_peer_uid(pre_stat)

    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        # struct ucred { pid_t pid; uid_t uid; gid_t gid; }
        ucred_size = struct.calcsize("i2I")
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, so_peercred, ucred_size)
        except OSError as e:
            sock.close()
            raise IpcError(
                f"SO_PEERCRED lookup on {socket_path} failed: {e}; refusing the connection"
            ) from e
        if len(creds) != ucred_size:
            sock.close()
            raise IpcError(
                f"SO_PEERCRED on {socket_path} returned {len(creds)} bytes "
                f"(expected {ucred_size}); refusing the connection"
            )
        _pid, peer_uid, _gid = struct.unpack("i2I", creds)
        if peer_uid != expected_uid:
            sock.close()
            raise IpcError(
                f"IPC peer on {socket_path} has uid {peer_uid}, expected "
                f"{expected_uid} (SO_PEERCRED); refusing the connection"
            )
        return

    if sys.platform == "darwin":
        xucred_size = struct.calcsize(_XUCRED_FMT)
        try:
            raw = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, xucred_size)
        except OSError as e:
            sock.close()
            raise IpcError(
                f"LOCAL_PEERCRED lookup on {socket_path} failed: {e}; refusing the connection"
            ) from e
        if len(raw) != xucred_size:
            sock.close()
            raise IpcError(
                f"LOCAL_PEERCRED on {socket_path} returned {len(raw)} bytes "
                f"(expected {xucred_size}); refusing the connection"
            )
        fields = struct.unpack(_XUCRED_FMT, raw)
        cr_version, peer_uid = fields[0], fields[1]
        if cr_version != _XUCRED_VERSION:
            sock.close()
            raise IpcError(
                f"LOCAL_PEERCRED on {socket_path} returned unsupported xucred "
                f"version {cr_version} (expected {_XUCRED_VERSION}); refusing the connection"
            )
        if peer_uid != expected_uid:
            sock.close()
            raise IpcError(
                f"IPC peer on {socket_path} has uid {peer_uid}, expected "
                f"{expected_uid} (LOCAL_PEERCRED); refusing the connection"
            )
        return

    # Unsupported POSIX platform without SO_PEERCRED or Darwin LOCAL_PEERCRED.
    if os.environ.get("HAAP_SDK_EXPECTED_PEER_UID") is not None:
        sock.close()
        raise IpcError(
            f"cannot verify HAAP_SDK_EXPECTED_PEER_UID={expected_uid} on "
            f"{socket_path}: platform {sys.platform!r} exposes neither "
            "SO_PEERCRED nor LOCAL_PEERCRED; refusing the connection"
        )
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
    try:
        sock.connect(path)
    except OSError as e:
        sock.close()
        raise _diagnosable_ipc_error(path, "connect", timeout_secs, e) from e
    # INF-08: pre_stat is None only on Windows, which never reaches this
    # AF_UNIX path; guard anyway for type-narrowing.
    if pre_stat is not None:
        _verify_peer_after_connect(sock, pre_stat, path)
    return sock


def _connect_named_pipe(path: str, timeout_secs: float | None) -> _WindowsPipeSocket:
    # Lazy import — Windows-only path. Implemented in pipe_win.py.
    from hawcx_haap import pipe_win  # noqa: WPS433

    return pipe_win.connect(path, timeout_secs=timeout_secs)  # type: ignore[return-value]


def connect_assembler(
    endpoint: str, *, timeout_secs: float | None = _DEFAULT_IPC_TIMEOUT
) -> socket.socket:
    """Open a transport to the Assembler endpoint.

    On Unix, ``endpoint`` is a filesystem path to a UDS. On Windows, it is a
    Named Pipe path (``\\\\.\\pipe\\haap-<agent_id>-agent-assembler-<index>``).
    Returns a ``socket.socket``-compatible object (real ``socket`` on Unix; a
    file-handle-backed wrapper on Windows).
    """
    validated_timeout = _validate_ipc_timeout(timeout_secs, "timeout_secs")
    if sys.platform == "win32":
        return _connect_named_pipe(endpoint, validated_timeout)  # type: ignore[return-value]
    return _connect_unix(endpoint, validated_timeout)


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
        self._lock = threading.RLock()
        self._sock = sock
        self._closed = False
        # Set when a timed-out or corrupted call retired `_sock`; the next `invoke` re-dials.
        self._needs_redial = False
        self._endpoint: str | None = None
        self._timeout_secs: float | None = _DEFAULT_IPC_TIMEOUT
        self._tool_call_timeout_secs: float | None = _DEFAULT_TOOL_CALL_TIMEOUT
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
        tool_call_timeout_secs: float | None = _DEFAULT_TOOL_CALL_TIMEOUT,
    ) -> AssemblerClient:
        """Connect, handshake, and return a client.

        ``timeout_secs`` bounds the connect and handshake;
        ``tool_call_timeout_secs`` bounds each tool call after that (``None``:
        wait for the reply however long it takes).

        ``experimental_capabilities`` is a tuple of capability tags the
        SDK advertises via the Assembler to upstream MCP servers (HAAP
        v7.2.5 §45.7.5). Pass ``(HAWCX_HAAP_V7_2_5_CAPABILITY,)`` to
        enable v7.2.5 payload carriage end-to-end. Empty tuple
        (default) means legacy v6.7.4 carriage only.
        """
        validated_timeout = _validate_ipc_timeout(timeout_secs, "timeout_secs")
        validated_call_timeout = _validate_ipc_timeout(
            tool_call_timeout_secs, "tool_call_timeout_secs"
        )
        sock = connect_assembler(endpoint, timeout_secs=validated_timeout)
        try:
            peer_role = perform_handshake(sock, local_role=ROLE_AGENT)
        except HandshakeError:
            # Already a well-labeled protocol error (local/remote major
            # version, public attributes callers may inspect) -- pass
            # through unchanged rather than flattening it into a generic
            # wrap.
            try:
                sock.close()
            except Exception:
                pass
            raise
        except Exception as e:
            # Everything else here is a bare stdlib exception (TimeoutError
            # on a stalled Assembler, ConnectionResetError, ...) or an
            # under-labeled IpcError from read_frame (e.g. "peer closed
            # connection mid-message", which names the operation but not
            # the endpoint). Name endpoint + operation + exception type so
            # "stalled" and "absent" read apart from the message alone.
            try:
                sock.close()
            except Exception:
                pass
            raise _diagnosable_ipc_error(endpoint, "handshake-read", timeout_secs, e) from e
        if peer_role != ROLE_ASSEMBLER:
            try:
                sock.close()
            except Exception:
                pass
            raise IpcError(
                f"expected peer role Assembler (0x05), got 0x{peer_role:02x}"
            )
        sock.settimeout(validated_call_timeout)
        client = cls(sock, experimental_capabilities=experimental_capabilities)
        # Remember how we got here so `invoke` can re-dial. The Assembler
        # serves ONE request per accepted connection (its accept loop calls
        # `handle_agent_request`, which reads exactly one frame and returns,
        # dropping the stream), while this client holds `self._sock` for the
        # life of the object. Without the endpoint we cannot recover.
        client._endpoint = endpoint
        client._timeout_secs = validated_timeout
        client._tool_call_timeout_secs = validated_call_timeout
        return client

    def _retire_socket_for_redial(self) -> None:
        with self._lock:
            if not self._closed:
                self._needs_redial = True
            try:
                self._sock.close()
            except Exception:
                pass

    def _reconnect(self) -> None:
        """Re-dial the Assembler and redo the handshake.

        Needed because the Assembler is single-request-per-connection: after
        it answers (or REJECTS) one ToolCallRequest it drops the stream, so
        the second `invoke` on the same client writes into a closed socket
        and raises BrokenPipeError. That looked like a transport fault for a
        long time; it is a protocol mismatch between the two sides.
        """
        with self._lock:
            if self._closed:
                raise IpcError("assembler client already closed")
            endpoint = self._endpoint
            # Mark `_needs_redial = True` BEFORE closing `_sock` so any
            # transient failure in `connect(...)` leaves the client in
            # `NeedsRedial` rather than permanently wedging subsequent calls
            # with raw `OSError(EBADF)`.
            self._retire_socket_for_redial()
            if not endpoint:
                raise IpcError(
                    "assembler connection is closed and this client has no endpoint "
                    "to re-dial (it was constructed from a bare socket)"
                )
            fresh = type(self).connect(
                endpoint,
                timeout_secs=getattr(self, "_timeout_secs", _DEFAULT_IPC_TIMEOUT),
                experimental_capabilities=self._experimental_capabilities,
                tool_call_timeout_secs=getattr(
                    self, "_tool_call_timeout_secs", _DEFAULT_TOOL_CALL_TIMEOUT
                ),
            )
            self._sock = fresh._sock
            self._needs_redial = False

    def invoke(self, req: ToolCallRequest) -> ToolCallResponse:
        """Send a ToolCallRequest; await ToolCallResponse or RequestRejected.

        Raises :class:`RequestRejected` if the Assembler rejects.
        Raises :class:`IpcError` on framing / transport errors.

        Transparently re-dials once if the connection was already spent: the
        Assembler closes it after every request, so any call after the first
        would otherwise fail with a broken pipe rather than a verdict. A
        RequestRejected is a VERDICT and is raised, never retried — retrying a
        refusal would turn one denial into two attempts at the same action.

        Raises :class:`TimeoutError` if no reply arrives within
        ``tool_call_timeout_secs``; that call is abandoned, not retried.
        """
        with self._lock:
            if self._closed:
                raise IpcError("assembler client already closed")
            # Validate wire request before dialing or writing any IPC bytes.
            wire = req.to_wire()
            if self._needs_redial:
                self._reconnect()
            try:
                return self._invoke_once(req, _prevalidated_wire=wire)
            except (BrokenPipeError, ConnectionResetError, EOFError):
                # The WRITE hit the closed socket.
                self._reconnect()
                try:
                    return self._invoke_once(req, _prevalidated_wire=dict(wire))
                except TimeoutError:
                    raise
                except OSError as e:
                    raise IpcError(
                        f"Assembler IPC transport error: {type(e).__name__}: {e}"
                    ) from e
            except _PeerClosedError:
                # The write landed in the socket buffer and the READ found the
                # peer cleanly gone before any frame header byte was sent.
                self._reconnect()
                try:
                    return self._invoke_once(req, _prevalidated_wire=dict(wire))
                except TimeoutError:
                    raise
                except OSError as e:
                    raise IpcError(
                        f"Assembler IPC transport error: {type(e).__name__}: {e}"
                    ) from e
            except TimeoutError:
                raise
            except OSError as e:
                raise IpcError(
                    f"Assembler IPC transport error: {type(e).__name__}: {e}"
                ) from e

    def _invoke_once(
        self,
        req: ToolCallRequest,
        *,
        _prevalidated_wire: dict[str, Any] | None = None,
    ) -> ToolCallResponse:
        wire = dict(_prevalidated_wire) if _prevalidated_wire is not None else req.to_wire()
        # Forward the connection-level experimental capability list on
        # every call so the Assembler can re-key its MCP initialize
        # when a new upstream server is contacted. Wire key matches
        # the Rust-side serde rename.
        if self._experimental_capabilities:
            wire["hawcx_experimental_capabilities"] = list(
                self._experimental_capabilities
            )
        payload = json.dumps(wire, separators=(",", ":")).encode("utf-8")
        frame_bytes = encode_frame(MSG_TOOL_CALL_REQUEST, payload)
        try:
            self._sock.sendall(frame_bytes)
            msg_type, body = read_frame(self._sock)
        except TimeoutError:
            # The Assembler may still answer this call on this socket. Read by
            # the next invoke(), that late reply would be returned as the answer
            # to a different request, so the socket goes and the next call
            # re-dials.
            self._retire_socket_for_redial()
            raise
        except (OSError, IpcError):
            self._retire_socket_for_redial()
            raise
        if msg_type in (MSG_TOOL_CALL_RESPONSE, MSG_REQUEST_REJECTED):
            try:
                obj = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self._retire_socket_for_redial()
                raise IpcError(
                    f"malformed JSON in Assembler response 0x{msg_type:02x}: {e}"
                ) from e
            if not isinstance(obj, dict):
                self._retire_socket_for_redial()
                raise IpcError(
                    f"Assembler response 0x{msg_type:02x} must be a JSON object; "
                    f"got {type(obj).__name__}"
                )
            if msg_type == MSG_TOOL_CALL_RESPONSE:
                try:
                    resp = ToolCallResponse.from_wire(obj)
                except IpcError:
                    self._retire_socket_for_redial()
                    raise
                if resp.request_id != req.request_id:
                    self._retire_socket_for_redial()
                    raise IpcError(
                        f"Assembler response request_id mismatch: expected "
                        f"{req.request_id!r}, got {resp.request_id!r}"
                    )
                return resp
            raw_rej_req_id = obj.get("request_id")
            rej_reason = obj.get("reason", "")
            if raw_rej_req_id is not None and not isinstance(raw_rej_req_id, str):
                self._retire_socket_for_redial()
                raise IpcError("RequestRejected fields request_id and reason must be strings")
            if not isinstance(rej_reason, str):
                self._retire_socket_for_redial()
                raise IpcError("RequestRejected fields request_id and reason must be strings")
            if raw_rej_req_id and raw_rej_req_id != req.request_id:
                self._retire_socket_for_redial()
                raise IpcError(
                    f"Assembler RequestRejected request_id mismatch: expected "
                    f"{req.request_id!r}, got {raw_rej_req_id!r}"
                )
            rej_req_id = raw_rej_req_id if raw_rej_req_id else req.request_id
            raise RequestRejected(
                request_id=rej_req_id,
                reason=rej_reason,
            )
        self._retire_socket_for_redial()
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
        with self._lock:
            if self._closed:
                raise IpcError("assembler client already closed")
        if not isinstance(pending_id, str):
            raise TypeError(f"pending_id must be str; got {type(pending_id).__name__}")
        if not pending_id.strip():
            raise ValueError("pending_id must be a non-empty string")
        if not (type(session_id) is int and not isinstance(session_id, bool)):
            raise TypeError(f"session_id must be int; got {type(session_id).__name__}")
        if not (0 <= session_id <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError(f"session_id out of u64 range: {session_id}")
        obj: dict[str, Any] = {
            "pending_id": pending_id,
            "session_id": session_id,
        }
        if answer_index is not None:
            if not (type(answer_index) is int and not isinstance(answer_index, bool)):
                raise TypeError(
                    f"answer_index must be int or None; got {type(answer_index).__name__}"
                )
            if not (0 <= answer_index <= 0xFF):
                raise ValueError(f"answer_index out of u8 range: {answer_index}")
            obj["answer_index"] = answer_index
        if answer_text is not None:
            if not isinstance(answer_text, str):
                raise TypeError(
                    f"answer_text must be str or None; got {type(answer_text).__name__}"
                )
            obj["answer_text"] = answer_text
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        frame_bytes = encode_frame(MSG_CLARIFICATION_ANSWER, payload)
        with self._lock:
            if self._closed:
                raise IpcError("assembler client already closed")
            if self._needs_redial:
                self._reconnect()
            try:
                self._sock.sendall(frame_bytes)
            except (BrokenPipeError, ConnectionResetError, EOFError) as e:
                self._retire_socket_for_redial()
                if not self._endpoint:
                    raise IpcError(
                        f"Assembler IPC transport error: {type(e).__name__}: {e}"
                    ) from e
                self._reconnect()
                try:
                    self._sock.sendall(frame_bytes)
                except OSError as retry_err:
                    self._retire_socket_for_redial()
                    raise IpcError(
                        f"Assembler IPC transport error: {type(retry_err).__name__}: {retry_err}"
                    ) from retry_err
            except OSError as e:
                self._retire_socket_for_redial()
                raise IpcError(
                    f"Assembler IPC transport error: {type(e).__name__}: {e}"
                ) from e

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._needs_redial = False
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
