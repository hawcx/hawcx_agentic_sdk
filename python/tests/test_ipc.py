"""Tests for hawcx_haap.ipc — framing, handshake, ToolCallRequest round-trip."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from hawcx_haap.errors import HandshakeError, IpcError, RequestRejected
from hawcx_haap.ipc import (
    MAX_MESSAGE_SIZE,
    AssemblerClient,
    TokenTransport,
    ToolCallRequest,
    encode_frame,
)


def test_encode_frame_layout() -> None:
    """Frame must be [len: u32 BE][msg_type: u8][payload]."""
    frame = encode_frame(0x52, b"hello")
    msg_len = struct.unpack(">I", frame[:4])[0]
    assert msg_len == 1 + len(b"hello")
    assert frame[4] == 0x52
    assert frame[5:] == b"hello"


def test_encode_frame_rejects_oversized() -> None:
    with pytest.raises(IpcError):
        encode_frame(0x52, b"x" * MAX_MESSAGE_SIZE)


def test_tool_call_request_to_wire_minimal() -> None:
    req = ToolCallRequest(
        request_id="r1",
        target_rs_url="https://api.example.com/x",
        http_method="GET",
        tool="search",
    )
    wire = req.to_wire()
    assert wire["request_id"] == "r1"
    assert wire["http_method"] == "GET"
    assert wire["resource"] == "*"
    assert wire["action"] == []
    assert "plaintext_request_body" not in wire
    assert "transport" not in wire
    assert "mcp_tool_name" not in wire  # omitted, never emitted as null


def test_tool_call_request_to_wire_full() -> None:
    req = ToolCallRequest(
        request_id="r2",
        target_rs_url="https://api.example.com/y",
        http_method="POST",
        headers={"X-Trace": "abc"},
        tool="write",
        mcp_tool_name="write-doc",
        action=["create", "update"],
        resource="*",
        plaintext_request_body=b'{"a":1}',
        claimed_intent_hash="0xdead",
        tool_arguments={"a": 1},
        content_type="application/json",
        transport=TokenTransport.MCP_META,
    )
    wire = req.to_wire()
    assert wire["plaintext_request_body"] == "eyJhIjoxfQ=="  # base64 of {"a":1}
    assert wire["transport"] == "mcp_meta"
    assert wire["claimed_intent_hash"] == "0xdead"
    assert wire["mcp_tool_name"] == "write-doc"
    assert wire["tool"] == "write"  # dotted TBAC id stays distinct from the kebab route


def test_assembler_client_round_trip(mock_assembler_endpoint: str) -> None:
    client = AssemblerClient.connect(mock_assembler_endpoint)
    try:
        resp = client.invoke(
            ToolCallRequest(
                request_id="req-1",
                target_rs_url="https://api.example.com/echo",
                http_method="POST",
                tool="echo",
                plaintext_request_body=b"hello",
            )
        )
        assert resp.request_id == "req-1"
        assert resp.http_status == 200
        assert resp.body == b"hello"
    finally:
        client.close()


def test_assembler_client_rejection(mock_assembler, mock_assembler_endpoint: str) -> None:
    mock_assembler.reject_with("destination not in allowlist")
    client = AssemblerClient.connect(mock_assembler_endpoint)
    try:
        with pytest.raises(RequestRejected) as ei:
            client.invoke(
                ToolCallRequest(
                    request_id="req-r1",
                    target_rs_url="https://forbidden.example.com/",
                    http_method="GET",
                    tool="oops",
                )
            )
        assert ei.value.request_id == "req-r1"
        assert "allowlist" in ei.value.reason
    finally:
        client.close()


def test_handshake_role_validation(short_sock_path: str) -> None:
    """If the server claims a non-Assembler role, connect() must reject."""
    import socket as _sock
    import struct as _struct
    import threading

    socket_path = short_sock_path
    server = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)

    def serve() -> None:
        conn, _ = server.accept()
        try:
            # Read peer handshake frame.
            length_bytes = conn.recv(4)
            msg_len = _struct.unpack(">I", length_bytes)[0]
            _ = conn.recv(msg_len)
            # Write back a handshake claiming role = Supervisor (0x01).
            payload = _struct.pack(">HHHHB", 1, 0, 5, 0, 0x01)
            frame_len = 1 + len(payload)
            conn.sendall(_struct.pack(">I", frame_len) + b"\x00" + payload)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with pytest.raises(IpcError, match="Assembler"):
            AssemblerClient.connect(socket_path)
    finally:
        server.close()


def test_handshake_version_mismatch(short_sock_path: str) -> None:
    import socket as _sock
    import struct as _struct
    import threading

    socket_path = short_sock_path
    server = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)

    def serve() -> None:
        conn, _ = server.accept()
        try:
            length_bytes = conn.recv(4)
            msg_len = _struct.unpack(">I", length_bytes)[0]
            _ = conn.recv(msg_len)
            payload = _struct.pack(">HHHHB", 1, 99, 0, 0, 0x05)
            frame_len = 1 + len(payload)
            conn.sendall(_struct.pack(">I", frame_len) + b"\x00" + payload)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with pytest.raises(HandshakeError):
            AssemblerClient.connect(socket_path)
    finally:
        server.close()


# ── Diagnosability: connect/handshake failures must name themselves ─────────
#
# 2026-09-21 UKG demo (see ipc.py's _diagnosable_ipc_error docstring): the
# supervisor spawns the agent workload before the Assembler exists, so on
# Unix the agent's connect() to the not-yet-accepting listener succeeds (it
# queues in the backlog) and the SAME settimeout() deadline that covers
# connect() then governs the handshake recv(). That recv() blocks until the
# deadline and raises a bare TimeoutError, whose str() is exactly "timed
# out" -- no endpoint, no operation, no type. These tests prove the fix with
# real AF_UNIX sockets (the bug is socket semantics, not something a mock
# can stand in for), in BOTH directions, and prove the two directions are
# actually distinguishable from each other -- not just "an exception was
# raised", which is the shape of assertion that let the bare message ship.


def _accept_and_never_reply(
    server: socket.socket, ready: threading.Event, stop: threading.Event
) -> None:
    """Mock 'Assembler' that accepts the connection (so connect() succeeds,
    exactly like the real race) and then holds it open, reading and sending
    nothing, until told to stop. This must NOT read the client's handshake
    write and NOT close the connection on its own -- either would let the
    client's read return (EOF) instead of actually blocking until its
    deadline, which would silently turn this into a "peer closed early" test
    instead of the stall this is meant to reproduce."""
    conn, _ = server.accept()
    ready.set()
    stop.wait(5)
    conn.close()


def test_connect_absent_socket_names_endpoint_and_is_distinguishable_as_absent(
    short_sock_path: str,
) -> None:
    """short_sock_path reserves a path inside a real 0o700 dir but does not
    create a socket there. The absent-socket half of the discrimination
    table: FileNotFoundError, named explicitly, not "timed out"."""
    with pytest.raises(IpcError) as ei:
        AssemblerClient.connect(short_sock_path, timeout_secs=0.3)
    msg = str(ei.value)
    assert short_sock_path in msg, "message must name the endpoint"
    assert "FileNotFoundError" in msg, "must be distinguishable as ABSENT, not a bare message"
    assert "TimeoutError" not in msg


def test_connect_stall_names_endpoint_operation_and_is_distinguishable_as_stalled(
    short_sock_path: str,
) -> None:
    """A listener that accepts and never replies -- the actual race. The
    message must name the endpoint, the operation (it fails during the
    handshake read, not the connect), and TimeoutError specifically."""
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(short_sock_path)
    server.listen(1)
    accepted = threading.Event()
    stop = threading.Event()
    t = threading.Thread(
        target=_accept_and_never_reply, args=(server, accepted, stop), daemon=True
    )
    t.start()
    try:
        with pytest.raises(IpcError) as ei:
            AssemblerClient.connect(short_sock_path, timeout_secs=0.3)
        assert accepted.wait(2), "server never accepted -- test setup is broken, not the SDK"
        msg = str(ei.value)
        assert short_sock_path in msg, "message must name the endpoint"
        assert "handshake-read" in msg, "must name the OPERATION that failed"
        assert "TimeoutError" in msg, "must be distinguishable as STALLED, not a bare message"
        assert "FileNotFoundError" not in msg
    finally:
        stop.set()
        server.close()
        t.join(timeout=2)


def test_stall_and_absent_are_distinguishable_from_each_other(short_sock_path: str) -> None:
    """The control this bug needed and never had: the two failure modes must
    not collapse to the same string. Asserting only "an IpcError was raised"
    is worthless here -- that was already true before the fix, and the whole
    defect was that the message said nothing useful once raised."""
    with pytest.raises(IpcError) as absent_ei:
        AssemblerClient.connect(short_sock_path, timeout_secs=0.3)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(short_sock_path)
    server.listen(1)
    accepted = threading.Event()
    stop = threading.Event()
    t = threading.Thread(
        target=_accept_and_never_reply, args=(server, accepted, stop), daemon=True
    )
    t.start()
    try:
        with pytest.raises(IpcError) as stall_ei:
            AssemblerClient.connect(short_sock_path, timeout_secs=0.3)
        assert accepted.wait(2)
    finally:
        stop.set()
        server.close()
        t.join(timeout=2)

    absent_msg, stall_msg = str(absent_ei.value), str(stall_ei.value)
    assert absent_msg != stall_msg
    assert "FileNotFoundError" in absent_msg and "TimeoutError" not in absent_msg
    assert "TimeoutError" in stall_msg and "FileNotFoundError" not in stall_msg


def test_connect_refused_names_endpoint_and_operation(short_sock_path: str) -> None:
    """A socket file exists but nothing is listen()ing on it -- ECONNREFUSED
    fires inside sock.connect() itself, the OTHER failure site
    _diagnosable_ipc_error wraps (as opposed to the handshake-read site the
    stall tests above exercise)."""
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(short_sock_path)
    server.close()  # bound, never listened -- connect() must be refused
    with pytest.raises(IpcError) as ei:
        AssemblerClient.connect(short_sock_path, timeout_secs=0.3)
    msg = str(ei.value)
    assert short_sock_path in msg, "message must name the endpoint"
    assert "connect" in msg, "must name the OPERATION that failed"
    assert "ConnectionRefusedError" in msg
