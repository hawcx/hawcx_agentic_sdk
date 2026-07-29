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
            f"IPC handshake version mismatch: local major={local_major} remote major={remote_major}"
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


# ── Egress broker (ADR-0048) ───────────────────────────────────────────────
# Distinguishable exceptions for the SOCKS5-over-UDS egress transport. A SOCKS5
# reply code the caller cannot tell apart is an hour lost, so each failure mode
# is its own type. All subclass HawcxError and are importable without httpx.


class EgressError(HawcxError):
    """Base class for egress-broker transport errors (ADR-0048)."""


class EgressConfigError(EgressError):
    """Cannot use the egress transport: httpx extra missing, or no broker
    socket resolved. Never a silent fallback to the direct network."""


class EgressProtocolError(EgressError):
    """The broker spoke something other than the agreed SOCKS5 handshake:
    truncated/oversized/malformed reply, bad version, or a reply code that
    should be impossible for a correct shim (``0x07`` command- / ``0x08``
    address-type-not-supported both indicate a shim bug)."""


class EgressPolicyDenied(EgressError):
    """SOCKS5 ``REP=0x02`` — host:port is not in the agent's signed egress
    policy. The connection was refused by the ruleset, not by the network."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(
            f"egress denied by policy: {host}:{port} not in the agent's signed egress allowlist"
        )
        self.host = host
        self.port = port


class EgressHostUnreachable(EgressError):
    """SOCKS5 ``REP=0x04`` — host unreachable. Includes the broker's SSRF
    refusal (the name resolved to a private/loopback/link-local/metadata
    address outside the endpoint's ``allowed_ips``). Distinct from a policy
    denial: the host was allowed by name but the dial was refused."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(
            f"egress host unreachable (or SSRF-refused after resolution): {host}:{port}"
        )
        self.host = host
        self.port = port


class EgressPeerCredError(EgressError):
    """The broker closed the connection without sending any reply — the
    peer-credential (SO_PEERCRED) check failed. Surfaced distinctly from a
    generic connection reset so a UID/sandbox misconfig is debuggable."""
