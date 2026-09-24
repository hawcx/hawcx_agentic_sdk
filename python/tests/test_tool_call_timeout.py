"""A tool call's reply has its own deadline, enforced on every platform (#129).

A call held for human step-up (CIBA) gets no bytes from the Assembler until the
hold resolves, up to 120 s. The 30 s connect/handshake deadline used to govern
that wait as well: macOS/Linux gave up on every held call at 30 s, while
Windows enforced no deadline at all (``WindowsPipeSocket.settimeout`` stored the
value and ignored it). These run against a real UDS on Unix and a real named
pipe on Windows, because the bug is transport semantics, which a mock cannot
stand in for.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from hawcx_haap import ipc
from hawcx_haap.errors import IpcError
from hawcx_haap.ipc import AssemblerClient, ToolCallRequest

Handler = Callable[[dict[str, Any], Callable[[str], None]], None]


class _SyncPipe:
    """Server end of a named pipe, as the socket shape ``ipc`` frames over."""

    def __init__(self, handle: int) -> None:
        self._h = handle

    def recv(self, n: int) -> bytes:
        import _winapi

        return _winapi.ReadFile(self._h, n)[0]

    def sendall(self, data: bytes) -> None:
        import _winapi

        _winapi.WriteFile(self._h, data)


@pytest.fixture
def release() -> Iterator[threading.Event]:
    """Set at teardown: lets held sessions go."""
    ev = threading.Event()
    yield ev
    ev.set()


def _fake_assembler(sessions: int, handler: Handler | None, release: threading.Event) -> str:
    """Serve ``sessions`` connections as the Assembler does: handshake, read one
    ToolCallRequest, then pass it to ``handler(request, reply)``. With no
    handler the session accepts and holds, never handshaking. Returns the
    endpoint."""
    accepts: list[Callable[[], Any]]
    if sys.platform == "win32":
        import _winapi

        endpoint = rf"\\.\pipe\hawcx-sdk-tool-call-{os.getpid()}-{uuid.uuid4().hex[:8]}"

        def accept_on(h: int) -> _SyncPipe:
            try:
                _winapi.ConnectNamedPipe(h, False)
            except OSError as e:
                if e.winerror != 535:  # ERROR_PIPE_CONNECTED: the client beat us
                    raise
            return _SyncPipe(h)

        # Every instance exists before the client dials, so a re-dial finds one.
        handles = [
            _winapi.CreateNamedPipe(
                endpoint, _winapi.PIPE_ACCESS_DUPLEX, 0, _winapi.PIPE_UNLIMITED_INSTANCES,
                65536, 65536, 0, _winapi.NULL,
            )
            for _ in range(sessions)
        ]
        accepts = [lambda h=h: accept_on(h) for h in handles]
    else:
        import socket

        d = tempfile.mkdtemp(prefix="hx-tc-")
        os.chmod(d, 0o700)  # _validate_ipc_socket_path refuses a looser parent
        endpoint = os.path.join(d, "a.sock")
        lsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        lsock.bind(endpoint)
        lsock.listen(sessions)
        accepts = [lambda: lsock.accept()[0] for _ in range(sessions)]

    def session(accept: Callable[[], Any]) -> None:
        try:
            conn = accept()
            if handler is None:
                release.wait()
                return
            kind, _ = ipc.read_frame(conn)
            assert kind == ipc.MSG_TYPE_HANDSHAKE
            ipc.write_frame(conn, ipc.MSG_TYPE_HANDSHAKE, ipc._encode_handshake(ipc.ROLE_ASSEMBLER))
            kind, payload = ipc.read_frame(conn)
            assert kind == ipc.MSG_TOOL_CALL_REQUEST

            def reply(request_id: str) -> None:
                body = {"request_id": request_id, "http_status": 200, "headers": {}, "body": ""}
                ipc.write_frame(conn, ipc.MSG_TOOL_CALL_RESPONSE, json.dumps(body).encode())

            handler(json.loads(payload), reply)
            release.wait()  # hold the connection open, as a slow Assembler would
        except (OSError, IpcError):
            pass  # the client hung up; that is what several of these tests do

    for accept in accepts:
        threading.Thread(target=session, args=(accept,), daemon=True).start()
    return endpoint


def _within(secs: float, fn: Callable[[], Any]) -> Any:
    """Run ``fn``, failing rather than hanging if it is still blocked after
    ``secs`` (a Windows read with no deadline never returns)."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["ok"] = fn()
        except BaseException as e:  # noqa: BLE001 - re-raised below
            box["err"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(secs)
    assert not t.is_alive(), f"still blocked after {secs}s: the deadline was not enforced"
    if "err" in box:
        raise box["err"]
    return box["ok"]


def _req(request_id: str) -> ToolCallRequest:
    return ToolCallRequest(
        request_id=request_id, target_rs_url="https://rs.invalid/", http_method="POST"
    )


def test_the_default_tool_call_timeout_outlasts_a_ciba_hold() -> None:
    """The hold is up to 120 s (PENDING_ENTRY_DEFAULT_TTL_SECS), then the RS call."""
    default = AssemblerClient.connect.__kwdefaults__["tool_call_timeout_secs"]
    assert default is ipc._DEFAULT_TOOL_CALL_TIMEOUT
    assert default >= 120, "HAAP_SDK_TOOL_CALL_TIMEOUT_SECS set below the hold?"


def test_a_held_call_is_not_cut_off_by_the_connect_deadline(release: threading.Event) -> None:
    """Replies 1 s in; the connect deadline is 0.3 s. Unix used to raise at 0.3 s."""
    def handler(req: dict[str, Any], reply: Callable[[str], None]) -> None:
        time.sleep(1.0)
        reply(req["request_id"])

    endpoint = _fake_assembler(1, handler, release)
    client = AssemblerClient.connect(endpoint, timeout_secs=0.3, tool_call_timeout_secs=10)
    try:
        assert _within(10, lambda: client.invoke(_req("r1"))).request_id == "r1"
    finally:
        client.close()


def test_a_short_tool_call_timeout_fires(release: threading.Event) -> None:
    """Never replies. Windows used to wait forever."""
    endpoint = _fake_assembler(1, lambda req, reply: None, release)
    client = AssemblerClient.connect(endpoint, tool_call_timeout_secs=0.5)
    try:
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            _within(10, lambda: client.invoke(_req("r1")))
        assert 0.4 <= time.monotonic() - t0 < 5
    finally:
        client.close()


def test_a_stalled_handshake_times_out(release: threading.Event) -> None:
    """Accepts, never handshakes: the supervisor's spawn race. Windows used to
    wait forever here too; the connect deadline now bounds the handshake."""
    endpoint = _fake_assembler(1, None, release)
    with pytest.raises(IpcError, match="handshake-read.*TimeoutError"):
        _within(10, lambda: AssemblerClient.connect(endpoint, timeout_secs=0.3))


def test_a_late_reply_is_not_the_answer_to_the_next_call(release: threading.Event) -> None:
    """r1 times out; the Assembler then answers r1 on that connection. Kept
    open, the socket hands r1's reply to the next invoke() as r2's answer
    (measured before the fix: request_id "r1"). Closed on timeout, the next
    invoke() re-dials and gets its own."""
    timed_out, late_reply_sent = threading.Event(), threading.Event()

    def handler(req: dict[str, Any], reply: Callable[[str], None]) -> None:
        if req["request_id"] == "r1":
            timed_out.wait(10)
            try:
                reply("r1")
            finally:
                late_reply_sent.set()
        else:
            reply(req["request_id"])

    endpoint = _fake_assembler(2, handler, release)
    client = AssemblerClient.connect(endpoint, tool_call_timeout_secs=0.5)
    try:
        with pytest.raises(TimeoutError):
            _within(10, lambda: client.invoke(_req("r1")))
        timed_out.set()
        assert late_reply_sent.wait(5)
        assert _within(10, lambda: client.invoke(_req("r2"))).request_id == "r2"
    finally:
        client.close()
