"""Assembler IPC client — speaks the wire protocol from ``hx_labs/crates/haap-ipc``.

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
import socket
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hawcx_haap.errors import HandshakeError, IpcError, RequestRejected

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
    action: list[str] = field(default_factory=list)
    resource: str = "*"
    constraints: dict[str, Any] = field(default_factory=dict)
    plaintext_request_body: bytes | None = None
    claimed_intent_hash: str | None = None
    tool_arguments: Any = None
    content_type: str | None = None
    transport: TokenTransport | None = None
    acting_for_user: str | None = None

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


def _connect_unix(path: str, timeout_secs: float | None) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if timeout_secs is not None:
        sock.settimeout(timeout_secs)
    sock.connect(path)
    return sock


def _connect_named_pipe(path: str, timeout_secs: float | None) -> _WindowsPipeSocket:
    # Lazy import — Windows-only path. Implemented in pipe_win.py.
    from hawcx_haap import pipe_win  # noqa: WPS433

    return pipe_win.connect(path, timeout_secs=timeout_secs)


def connect_assembler(endpoint: str, *, timeout_secs: float | None = 5.0) -> socket.socket:
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
        timeout_secs: float | None = 5.0,
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
        return cls(sock, experimental_capabilities=experimental_capabilities)

    def invoke(self, req: ToolCallRequest) -> ToolCallResponse:
        """Send a ToolCallRequest; await ToolCallResponse or RequestRejected.

        Raises :class:`RequestRejected` if the Assembler rejects.
        Raises :class:`IpcError` on framing / transport errors.
        """
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
