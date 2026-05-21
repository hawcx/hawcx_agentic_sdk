"""pytest fixtures including a mock Assembler that speaks the haap-ipc wire protocol.

The mock binds a Unix domain socket, performs the version handshake (role =
Assembler), parses one ``ToolCallRequest`` frame, and replies with either a
``ToolCallResponse`` echoing the body or a configurable ``RequestRejected``.

Skips on Windows (Named Pipe mock would require a separate WIN32 server impl;
the IPC client is exercised on Windows via the framing-level unit tests).
"""

from __future__ import annotations

import base64
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

PROTOCOL_VERSION = 1
SDK_VERSION_MAJOR = 0
SDK_VERSION_MINOR = 5
SDK_VERSION_PATCH = 0
ROLE_ASSEMBLER = 0x05

MSG_TYPE_HANDSHAKE = 0x00
MSG_TOOL_CALL_REQUEST = 0x52
MSG_TOOL_CALL_RESPONSE = 0x53
MSG_REQUEST_REJECTED = 0x54


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("mock peer closed during recv")
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(conn: socket.socket) -> tuple[int, bytes]:
    length_bytes = _recv_exact(conn, 4)
    msg_len = struct.unpack(">I", length_bytes)[0]
    body = _recv_exact(conn, msg_len)
    return body[0], bytes(body[1:])


def _write_frame(conn: socket.socket, msg_type: int, payload: bytes) -> None:
    msg_len = 1 + len(payload)
    conn.sendall(struct.pack(">I", msg_len) + bytes([msg_type]) + payload)


def _handshake_payload(role: int) -> bytes:
    return struct.pack(
        ">HHHHB",
        PROTOCOL_VERSION,
        SDK_VERSION_MAJOR,
        SDK_VERSION_MINOR,
        SDK_VERSION_PATCH,
        role,
    )


class MockAssembler:
    """One-connection echo Assembler for tests."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(1)
        self.received_request: dict | None = None
        self._reject_reason: str | None = None
        self._response_override: dict | None = None
        self._response_status: int = 200
        self._thread: threading.Thread | None = None

    def reject_with(self, reason: str) -> None:
        self._reject_reason = reason

    def respond_with(
        self,
        *,
        body: bytes,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._response_override = {
            "body": body,
            "status": status,
            "headers": headers or {},
        }

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        try:
            # Read peer handshake, write ours. If the test fixture is torn
            # down before a client connects (e.g. a test that takes the
            # fixture but never invokes), swallow the resulting close.
            msg_type, _payload = _read_frame(conn)
            assert msg_type == MSG_TYPE_HANDSHAKE
            _write_frame(conn, MSG_TYPE_HANDSHAKE, _handshake_payload(ROLE_ASSEMBLER))

            # Read ToolCallRequest.
            msg_type, payload = _read_frame(conn)
            if msg_type != MSG_TOOL_CALL_REQUEST:
                return
            self.received_request = json.loads(payload.decode("utf-8"))

            if self._reject_reason is not None:
                resp = {
                    "request_id": self.received_request.get("request_id", ""),
                    "reason": self._reject_reason,
                }
                _write_frame(conn, MSG_REQUEST_REJECTED, json.dumps(resp).encode("utf-8"))
                return

            if self._response_override is not None:
                body = self._response_override["body"]
                status = self._response_override["status"]
                headers = self._response_override["headers"]
            else:
                # Default echo: return the plaintext_request_body as the response body.
                body_b64 = self.received_request.get("plaintext_request_body") or ""
                body = base64.b64decode(body_b64) if body_b64 else b""
                status = 200
                headers = {}

            resp = {
                "request_id": self.received_request.get("request_id", ""),
                "http_status": status,
                "headers": headers,
                "body": base64.b64encode(body).decode("ascii"),
            }
            _write_frame(conn, MSG_TOOL_CALL_RESPONSE, json.dumps(resp).encode("utf-8"))
        except (ConnectionError, OSError):
            # Test torn down before the mock could complete; harmless.
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


def _short_socket_path(name: str = "mock") -> str:
    """Generate a short AF_UNIX path inside a 0o700 dir.

    Two constraints:

    1. macOS's ``sun_path`` is capped at 104 bytes — pytest's
       ``tmp_path`` is too deeply nested, hence the bare tempdir.
    2. H-4 (2026-05-20): the client validates that the socket's
       parent dir is owned by the current UID and has no group/other
       bits set. We create a fresh ``mkdtemp`` dir under
       ``tempfile.gettempdir()``, ``chmod 0o700`` it, and put the
       socket inside.
    """
    parent = tempfile.mkdtemp(prefix=f"hx-{name}-")
    os.chmod(parent, 0o700)
    return os.path.join(parent, f"{uuid.uuid4().hex[:8]}.sock")


@pytest.fixture
def mock_assembler() -> Iterator[MockAssembler]:
    if sys.platform == "win32":
        pytest.skip("Unix domain socket mock skipped on Windows")
    socket_path = _short_socket_path("asm")
    mock = MockAssembler(socket_path)
    mock.start()
    try:
        yield mock
    finally:
        mock.close()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass


@pytest.fixture
def mock_assembler_endpoint(mock_assembler: MockAssembler) -> str:
    return mock_assembler.socket_path


@pytest.fixture
def short_sock_path() -> Iterator[str]:
    """Return a temporary short AF_UNIX path that the test should manage.

    Skips on Windows: the path is consumed by raw ``socket.AF_UNIX``
    server sockets in callers (e.g. ``test_handshake_*``), and Python
    on the Windows GHA runner image does not expose ``socket.AF_UNIX``.
    Named-pipe parity for the Python binding's mock harness mirrors
    the Rust SDK's CS v7.2.5 §39.12.2 implementation and is tracked
    as a follow-up.
    """
    if sys.platform == "win32":
        pytest.skip("AF_UNIX-based mock not portable on Windows")
    path = _short_socket_path("t")
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
