"""HAAP error types."""

from __future__ import annotations


class HawcxError(Exception):
    """Base class for all HAAP SDK errors."""


class IpcError(HawcxError):
    """IPC transport errors (connection refused, framing, oversized message)."""


class HandshakeError(IpcError):
    """Version handshake failed."""

    def __init__(self, local_major: int, remote_major: int) -> None:
        super().__init__(
            f"IPC handshake version mismatch: local major={local_major} "
            f"remote major={remote_major}"
        )
        self.local_major = local_major
        self.remote_major = remote_major


class RequestRejected(HawcxError):
    """The Assembler rejected the tool call (msg_type 0x54).

    Per ``crates/haap-ipc/src/messages/assembler.rs``, the rejection payload is
    a free-form reason string (no numeric reason-code enum). Callers can match
    on the reason text for known cases (e.g. ``"destination not in allowlist"``).
    """

    def __init__(self, request_id: str, reason: str) -> None:
        super().__init__(f"HAAP request {request_id!r} rejected: {reason}")
        self.request_id = request_id
        self.reason = reason
