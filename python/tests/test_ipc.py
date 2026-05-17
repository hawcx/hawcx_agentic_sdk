"""Tests for hawcx_haap.ipc — framing, handshake, ToolCallRequest round-trip."""

from __future__ import annotations

import struct

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


def test_tool_call_request_to_wire_full() -> None:
    req = ToolCallRequest(
        request_id="r2",
        target_rs_url="https://api.example.com/y",
        http_method="POST",
        headers={"X-Trace": "abc"},
        tool="write",
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
