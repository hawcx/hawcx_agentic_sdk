"""Authenticator control-socket IPC client — runtime agent-identity acquisition.

Per HAAP CS v7.2.6 §4.2 (Tier-2 Agent Enrollment) and §5.2 (X3DH Mode B),
the per-agent Authenticator process is the cryptographic principal that
mints IK_i and drives the X3DH handshake against the AS. The Authenticator
exposes a UDS / Named Pipe control socket for in-runtime registration
requests (the supervisor uses this; the SDK now does too).

Wire protocol (mirrors ``haap_ipc::framing`` in ``hx_agent_crypto_core``,
identical to the Assembler agent channel):

    [msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]

Message types (mirrors ``crates/haap-auth-bin/src/control_socket.rs``):

- ``MSG_REGISTER_REQ = 0x07``  — Agent runtime → Authenticator, JSON
- ``MSG_REGISTER_RESP = 0x08`` — Authenticator → Agent runtime, JSON

The Authenticator's control socket does NOT perform the version handshake
that the Assembler agent socket does — it accepts framed requests directly.
This matches the supervisor-relay client in
``haap-auth-bin/src/control_socket.rs::register_agent_via_control_socket``.

§4.2 compliance caveat
----------------------
The current Rust-side ``RegisterAgentRequest`` (``haap-ipc/v070.rs``) carries
``agent_class`` + ``subject_user_id`` + optional ``prepared_agent_id`` but
NOT ``org_token``. The supervisor pipeline obtains the org_token via the
CAA prepare-handshake and stores it in the Authenticator's session context
before invoking ``MSG_REGISTER_REQ``. The SDK adds ``org_token`` as an
additive top-level wire field so the Authenticator can adopt it in a
forward-compatible serde upgrade (TODO: ``hx_agent_crypto_core`` issue —
extend ``RegisterAgentRequest`` to carry the org_token and have the
Authenticator verify it matches the supervisor-pre-bound session).
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hawcx_haap.errors import HawcxError, IpcError
from hawcx_haap.ipc import (
    MAX_MESSAGE_SIZE,
    _validate_ipc_socket_path,
    read_frame,
    write_frame,
)

# ── Authenticator control socket opcodes (mirror Rust constants) ──────

MSG_REGISTER_REQ: int = 0x07
MSG_REGISTER_RESP: int = 0x08


# ── Public types ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class EnrollmentResult:
    """Successful agent enrollment — mirrors ``RegisterAgentResult::Enrolled``.

    Fields match ``haap_ipc::messages::v070::RegisterAgentResult`` (the
    ``Enrolled`` and ``AlreadyEnrolled`` variants). The ``trust_level``
    field is present only on the ``AlreadyEnrolled`` branch.
    """

    agent_instance_id: str
    client_id: str
    ik_fingerprint: str
    session_id: str
    already_enrolled: bool = False
    trust_level: str | None = None


class EnrollmentRejected(HawcxError):
    """The Authenticator rejected the enrollment (Degraded or error envelope).

    Carries the ``reason`` string from the Rust-side Result enum. For the
    ``Degraded`` branch, ``agent_instance_id`` is populated (the agent has
    identity but the TQS policy push failed — see §4.2.6); for the generic
    error branch, ``agent_instance_id`` is ``None``.
    """

    def __init__(self, reason: str, *, agent_instance_id: str | None = None) -> None:
        super().__init__(f"HAAP enrollment rejected: {reason}")
        self.reason = reason
        self.agent_instance_id = agent_instance_id


# ── Default control-socket path resolution ────────────────────────────


def default_auth_control_socket_for(
    agent_id: str,
    *,
    ipc_dir: Path | None = None,
) -> str:
    """Compute the canonical Authenticator control-socket path.

    Mirrors ``haap_supervisor::graph::auth_control_socket_path``:

    - **Unix:** ``{ipc_dir}/{agent_id}/auth-control.sock``
    - **Windows:** ``\\\\.\\pipe\\haap-{agent_id}-auth-control``

    On Unix the supervisor honors ``HAAP_AUTH_CONTROL_SOCK`` as an
    explicit override; the SDK respects the same env var so a single
    ``export`` flips both the Rust supervisor and the Python client to
    a non-default path.
    """
    override = os.environ.get("HAAP_AUTH_CONTROL_SOCK")
    if override:
        return override
    if sys.platform == "win32":
        return rf"\\.\pipe\haap-{agent_id}-auth-control"
    from hawcx_haap.agent import _default_ipc_dir  # circular-safe at call time

    base = ipc_dir or _default_ipc_dir()
    return str(base / agent_id / "auth-control.sock")


# ── AuthenticatorClient ──────────────────────────────────────────────


class AuthenticatorClient:
    """Synchronous client for the Authenticator's control socket.

    Unlike :class:`AssemblerClient`, the control socket does NOT perform
    an IPC version handshake on connect — it accepts framed requests
    directly. This matches the Rust supervisor-relay client.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock: socket.socket | None = sock

    @classmethod
    def connect(
        cls,
        endpoint: str,
        *,
        timeout_secs: float | None = 30.0,
    ) -> AuthenticatorClient:
        """Open the Authenticator control socket.

        ``timeout_secs`` defaults to 30s because enrollment drives a full
        X3DH ceremony against the AS (network round-trip), unlike a
        local tool-call which is ~milliseconds.
        """
        if sys.platform == "win32":
            from hawcx_haap import pipe_win  # noqa: WPS433

            sock = pipe_win.connect(endpoint, timeout_secs=timeout_secs)  # type: ignore[assignment]
        else:
            _validate_ipc_socket_path(endpoint)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if timeout_secs is not None:
                sock.settimeout(timeout_secs)
            sock.connect(endpoint)
        return cls(sock)

    def register_agent(
        self,
        *,
        agent_class: str,
        subject_user_id: str,
        org_token: str,
        prepared_agent_id: str | None = None,
    ) -> EnrollmentResult:
        """Send ``MSG_REGISTER_REQ`` and await the ``MSG_REGISTER_RESP``.

        The Authenticator drives §4.2 enrollment internally:

        1. Generate IK_i (Ristretto255), or reuse the prepared IK_i if
           ``prepared_agent_id`` matches a slot persisted by a prior
           ``MSG_REGISTER_PREPARE_REQ`` (CS v7.1.1 §4.6.3).
        2. Drive X3DH Mode B against the configured AS using the
           supervisor-bound org_token.
        3. Persist the resulting ``agent_instance_id`` + ``client_id``
           + ``session_id`` and return them.

        ``org_token`` is forwarded as an additive top-level wire field;
        the Rust-side ``RegisterAgentRequest`` currently uses the
        supervisor-pre-bound org_token from its session context (the
        wire field is ignored by the existing serde derive but is
        present for forward-compatible upgrade).

        Raises :class:`EnrollmentRejected` on Degraded or error envelopes.
        Raises :class:`IpcError` on framing / transport errors.
        """
        if self._sock is None:
            raise HawcxError("authenticator client already closed")

        payload: dict[str, Any] = {
            "agent_class": agent_class,
            "subject_user_id": subject_user_id,
            # TODO(hx_agent_crypto_core#TBD): extend RegisterAgentRequest
            # to carry `org_token` and have the Authenticator verify it
            # matches the supervisor-pre-bound session token. Until then,
            # this field is sent on-wire as a forward-compatible hint and
            # the Rust side relies on its pre-bound session for the
            # cryptographic ceremony.
            "org_token": org_token,
        }
        if prepared_agent_id is not None:
            payload["prepared_agent_id"] = prepared_agent_id

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) + 1 > MAX_MESSAGE_SIZE:
            raise IpcError(
                f"register payload too large: {len(body)} bytes "
                f"(max {MAX_MESSAGE_SIZE - 1})"
            )
        write_frame(self._sock, MSG_REGISTER_REQ, body)

        msg_type, resp_body = read_frame(self._sock)
        if msg_type != MSG_REGISTER_RESP:
            raise IpcError(
                f"unexpected response msg_type 0x{msg_type:02x}; "
                f"expected 0x{MSG_REGISTER_RESP:02x} (MSG_REGISTER_RESP)"
            )
        return _parse_register_response(resp_body)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> AuthenticatorClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ── Response parser ──────────────────────────────────────────────────


def _parse_register_response(body: bytes) -> EnrollmentResult:
    """Decode the JSON ``RegisterAgentResult`` enum into an EnrollmentResult.

    Raises :class:`EnrollmentRejected` for ``Degraded`` and generic-error
    envelopes (``{"error": "..."}``).
    """
    try:
        obj: dict[str, Any] = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise IpcError(f"malformed register response: {e}") from e

    # Generic error envelope from the control_socket handler (not the
    # serde-derived enum variant). Example:
    #   {"error": "invalid RegisterAgent payload: ..."}.
    if "error" in obj and "type" not in obj:
        raise EnrollmentRejected(str(obj["error"]))

    variant = obj.get("type")
    if variant == "Enrolled":
        return EnrollmentResult(
            agent_instance_id=str(obj["agent_instance_id"]),
            client_id=str(obj["client_id"]),
            ik_fingerprint=str(obj.get("ik_fingerprint", "")),
            session_id=str(obj["session_id"]),
            already_enrolled=False,
            trust_level=None,
        )
    if variant == "AlreadyEnrolled":
        trust_level = obj.get("trust_level")
        return EnrollmentResult(
            agent_instance_id=str(obj["agent_instance_id"]),
            client_id=str(obj["client_id"]),
            ik_fingerprint=str(obj.get("ik_fingerprint", "")),
            session_id=str(obj["session_id"]),
            already_enrolled=True,
            trust_level=(
                str(trust_level) if trust_level is not None else None
            ),
        )
    if variant == "Degraded":
        raise EnrollmentRejected(
            str(obj.get("reason", "policy push failed")),
            agent_instance_id=str(obj.get("agent_instance_id", "")) or None,
        )
    raise IpcError(
        f"unknown RegisterAgentResult variant: {variant!r} "
        f"(expected Enrolled / AlreadyEnrolled / Degraded)"
    )
