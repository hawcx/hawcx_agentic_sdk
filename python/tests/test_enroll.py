"""Tests for HawcxAgent.enroll() — runtime agent-identity acquisition (v7.2.6 §4.2)."""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import tempfile
import threading
import uuid
from collections.abc import Iterator

import pytest

from hawcx_haap import EnrollmentRejected, HawcxAgent, HawcxError
from hawcx_haap.auth_ipc import (
    MSG_REGISTER_REQ,
    MSG_REGISTER_RESP,
    default_auth_control_socket_for,
)

# Skip the whole module on Windows — the mock uses AF_UNIX. The Python
# enroll() codepath is exercised on Windows via the framing-level paths
# already covered in test_ipc.py.
if sys.platform == "win32":
    pytest.skip("AF_UNIX mock not portable on Windows", allow_module_level=True)


# ── Mock Authenticator control socket ────────────────────────────────


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("mock peer closed during recv")
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(conn: socket.socket) -> tuple[int, bytes]:
    (msg_len,) = struct.unpack(">I", _recv_exact(conn, 4))
    body = _recv_exact(conn, msg_len)
    return body[0], bytes(body[1:])


def _write_frame(conn: socket.socket, msg_type: int, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", 1 + len(payload)) + bytes([msg_type]) + payload)


class MockAuthenticator:
    """Single-connection mock that speaks the Authenticator control protocol.

    Records the inbound RegisterAgentRequest payload and replies with the
    configured RegisterAgentResult variant. No IPC version handshake (the
    real Authenticator control socket does not handshake either; see
    ``auth_ipc.py`` module docstring).
    """

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(1)
        self.received_payload: dict | None = None
        self._response: dict = {
            "type": "Enrolled",
            "agent_instance_id": "agent-instance-test-001",
            "client_id": "client-uuid-test-001",
            "ik_fingerprint": "a" * 64,
            "session_id": "sess-test-001",
        }
        self._thread: threading.Thread | None = None

    def respond_with(self, response: dict) -> None:
        self._response = response

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        try:
            msg_type, payload = _read_frame(conn)
            if msg_type != MSG_REGISTER_REQ:
                return
            self.received_payload = json.loads(payload.decode("utf-8"))
            body = json.dumps(self._response).encode("utf-8")
            _write_frame(conn, MSG_REGISTER_RESP, body)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self) -> None:
        try:
            self.server.close()
        except Exception:
            pass


# ── Mock Assembler (mirrors conftest fixture but reachable inside enroll) ──


class _MockAssembler:
    """Minimal Assembler echo that accepts the post-enroll connect call."""

    PROTOCOL_VERSION = 1
    SDK_VERSION_MAJOR = 0
    SDK_VERSION_MINOR = 5
    SDK_VERSION_PATCH = 0
    ROLE_ASSEMBLER = 0x05
    MSG_TYPE_HANDSHAKE = 0x00

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(1)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        try:
            _read_frame(conn)  # peer handshake
            _write_frame(
                conn,
                self.MSG_TYPE_HANDSHAKE,
                struct.pack(
                    ">HHHHB",
                    self.PROTOCOL_VERSION,
                    self.SDK_VERSION_MAJOR,
                    self.SDK_VERSION_MINOR,
                    self.SDK_VERSION_PATCH,
                    self.ROLE_ASSEMBLER,
                ),
            )
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self) -> None:
        try:
            self.server.close()
        except Exception:
            pass


# ── Shared short-path helpers (mirror conftest) ──────────────────────


def _short_dir(name: str) -> str:
    parent = tempfile.mkdtemp(prefix=f"hx-{name}-")
    os.chmod(parent, 0o700)
    return parent


@pytest.fixture
def enroll_env() -> Iterator[tuple[MockAuthenticator, _MockAssembler, str]]:
    """Set up a mock Authenticator and a mock Assembler under one ipc_dir.

    The Authenticator returns ``Enrolled{agent_instance_id="aid-001"}`` so
    the SDK then connects to ``{ipc_dir}/aid-001/agent-assembler-0.sock``,
    which the Assembler mock binds.
    """
    base = _short_dir("enroll")
    name = "researcher"
    aid = "aid-001"

    # Authenticator socket lives under {base}/{name}/auth-control.sock.
    os.makedirs(os.path.join(base, name), mode=0o700)
    auth_path = os.path.join(base, name, "auth-control.sock")
    auth = MockAuthenticator(auth_path)
    auth.respond_with(
        {
            "type": "Enrolled",
            "agent_instance_id": aid,
            "client_id": "client-001",
            "ik_fingerprint": "ab" * 32,
            "session_id": "sess-001",
        }
    )
    auth.start()

    # Assembler socket lives under {base}/{aid}/agent-assembler-0.sock.
    os.makedirs(os.path.join(base, aid), mode=0o700)
    asm_path = os.path.join(base, aid, "agent-assembler-0.sock")
    asm = _MockAssembler(asm_path)
    asm.start()

    try:
        yield auth, asm, base
    finally:
        auth.close()
        asm.close()
        for p in (auth_path, asm_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


# ── Tests ────────────────────────────────────────────────────────────


def test_default_auth_control_socket_for_unix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HAAP_AUTH_CONTROL_SOCK", raising=False)
    from pathlib import Path

    path = default_auth_control_socket_for("researcher", ipc_dir=Path("/var/run/haap"))
    assert path == "/var/run/haap/researcher/auth-control.sock"


def test_default_auth_control_socket_for_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HAAP_AUTH_CONTROL_SOCK", "/custom/path/auth.sock")
    path = default_auth_control_socket_for("ignored")
    assert path == "/custom/path/auth.sock"


def test_default_auth_control_socket_for_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HAAP_AUTH_CONTROL_SOCK", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    path = default_auth_control_socket_for("researcher")
    assert path == r"\\.\pipe\haap-researcher-auth-control"


def test_enroll_drives_authenticator_and_returns_agent(
    enroll_env: tuple[MockAuthenticator, _MockAssembler, str],
) -> None:
    """End-to-end: enroll() talks to the Authenticator and then connects."""
    from pathlib import Path

    auth, _asm, base = enroll_env
    agent = HawcxAgent.enroll(
        name="researcher",
        org_token="ot-test-token-XYZ",
        principal_allowlist=["alice"],
        ipc_dir=Path(base),
    )
    try:
        # The Authenticator received exactly the wire fields we expect.
        assert auth.received_payload is not None
        assert auth.received_payload["agent_class"] == "default"
        assert auth.received_payload["subject_user_id"] == "researcher"
        assert auth.received_payload["org_token"] == "ot-test-token-XYZ"
        assert auth.received_payload["prepared_agent_id"] == "researcher"

        # The returned agent carries the enrollment metadata.
        enrollment = agent.enrollment
        assert enrollment is not None
        assert enrollment.agent_instance_id == "aid-001"
        assert enrollment.session_id == "sess-001"
        assert enrollment.already_enrolled is False
    finally:
        agent.close()


def test_enroll_rejects_empty_name(tmp_path) -> None:
    with pytest.raises(HawcxError) as ei:
        HawcxAgent.enroll(
            name="",
            org_token="ot-x",
            principal_allowlist=[],
        )
    assert "name" in str(ei.value)


def test_enroll_rejects_empty_org_token(tmp_path) -> None:
    with pytest.raises(HawcxError) as ei:
        HawcxAgent.enroll(
            name="x",
            org_token="",
            principal_allowlist=[],
        )
    assert "org_token" in str(ei.value)


def test_enroll_requires_principal_allowlist() -> None:
    with pytest.raises(TypeError):
        HawcxAgent.enroll(  # type: ignore[call-arg]
            name="x",
            org_token="ot",
        )


def test_enroll_propagates_degraded_as_rejection(
    enroll_env: tuple[MockAuthenticator, _MockAssembler, str],
) -> None:
    """Degraded variant → EnrollmentRejected with reason + agent_instance_id."""
    from pathlib import Path

    auth, _asm, base = enroll_env
    auth.respond_with(
        {
            "type": "Degraded",
            "agent_instance_id": "aid-001",
            "client_id": "client-001",
            "ik_fingerprint": "ab" * 32,
            "session_id": "sess-001",
            "reason": "tqs policy push failed: connection refused",
        }
    )
    with pytest.raises(EnrollmentRejected) as ei:
        HawcxAgent.enroll(
            name="researcher",
            org_token="ot-test",
            principal_allowlist=[],
            ipc_dir=Path(base),
        )
    assert "tqs policy push" in ei.value.reason
    assert ei.value.agent_instance_id == "aid-001"


def test_enroll_propagates_generic_error_envelope(
    enroll_env: tuple[MockAuthenticator, _MockAssembler, str],
) -> None:
    """``{"error": "..."}`` envelope → EnrollmentRejected with no agent_instance_id."""
    from pathlib import Path

    auth, _asm, base = enroll_env
    auth.respond_with({"error": "invalid RegisterAgent payload: missing field"})
    with pytest.raises(EnrollmentRejected) as ei:
        HawcxAgent.enroll(
            name="researcher",
            org_token="ot-test",
            principal_allowlist=[],
            ipc_dir=Path(base),
        )
    assert "invalid" in ei.value.reason
    assert ei.value.agent_instance_id is None


def test_enroll_already_enrolled_returns_existing_identity(
    enroll_env: tuple[MockAuthenticator, _MockAssembler, str],
) -> None:
    """AlreadyEnrolled is a success path (idempotent re-enroll)."""
    from pathlib import Path

    auth, _asm, base = enroll_env
    auth.respond_with(
        {
            "type": "AlreadyEnrolled",
            "agent_instance_id": "aid-001",
            "client_id": "client-001",
            "ik_fingerprint": "ab" * 32,
            "session_id": "sess-001",
            "trust_level": "Enrolled",
            "scope_ceiling": {},
        }
    )
    agent = HawcxAgent.enroll(
        name="researcher",
        org_token="ot-test",
        principal_allowlist=[],
        ipc_dir=Path(base),
    )
    try:
        assert agent.enrollment is not None
        assert agent.enrollment.already_enrolled is True
        assert agent.enrollment.trust_level == "Enrolled"
    finally:
        agent.close()
