"""V-17 wire, principal, header, and I3 bool-is-int / fail-closed parser tests.

Covers all 10 Python integer/wire/timeout/status boundaries across ``agent.py``,
``ipc.py``, ``egress.py``, ``mcp_caller.py``, ``auth_ipc.py``, ``pipe_win.py``,
and ``submit.py``, plus ``HawcxAgent.invoke_for(..., provider=...)`` and ``I2``
duplicate ``X-Hawcx-Parent-Call-Record`` header screening.
"""

from __future__ import annotations

import base64
import io
import json
import os
import socket
import struct
import threading
import urllib.error
import urllib.request
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from hawcx_haap import Caller, HawcxAgent, McpTool, egress, pipe_win
from hawcx_haap import submit as submit_mod
from hawcx_haap.agent import default_endpoint_for
from hawcx_haap.auth_ipc import (
    AuthenticatorClient,
    _parse_register_response,
    default_auth_control_socket_for,
)
from hawcx_haap.bundle import BundleError, build_bundle
from hawcx_haap.cli import main as cli_main
from hawcx_haap.egress import _connect_request
from hawcx_haap.errors import (
    EgressError,
    EgressProtocolError,
    HawcxError,
    IpcError,
    RequestRejected,
)
from hawcx_haap.extract import ExtractError, extract_from_mcp_tools_list, extract_from_names
from hawcx_haap.ipc import (
    MSG_CLARIFICATION_ANSWER,
    MSG_REQUEST_REJECTED,
    MSG_TOOL_CALL_REQUEST,
    MSG_TOOL_CALL_RESPONSE,
    MSG_TYPE_HANDSHAKE,
    ROLE_ASSEMBLER,
    SDK_VERSION_MAJOR,
    SDK_VERSION_MINOR,
    SDK_VERSION_PATCH,
    AssemblerClient,
    ToolCallRequest,
    ToolCallResponse,
    _encode_handshake,
    encode_frame,
    perform_handshake,
    read_frame,
)
from hawcx_haap.mcp_caller import _classify
from hawcx_haap.submit import SubmitError, _validate_console_url, submit_template
from hypothesis import given, settings
from hypothesis import strategies as st

# ── HawcxAgent.invoke_for(..., provider=...) & I2 header/principal guards ────


def test_invoke_for_forwards_provider_to_top_level_wire(
    mock_assembler: Any, mock_assembler_endpoint: str
) -> None:
    with HawcxAgent.connect(
        mock_assembler_endpoint, principal_allowlist=["alice@example.com"]
    ) as agent:
        resp = agent.invoke_for(
            "alice@example.com",
            target_rs_url="https://api.example.com/v1/chat",
            tool="chat.postMessage",
            action=["write"],
            provider="slack",
            body=b'{"text":"hi"}',
        )
    assert resp.http_status == 200
    assert mock_assembler.received_request is not None
    assert mock_assembler.received_request["acting_for_user"] == "alice@example.com"
    assert mock_assembler.received_request["provider"] == "slack"
    assert "provider" not in mock_assembler.received_request["constraints"]


def test_invoke_for_empty_principal_error_mentions_acting_for_user_none(
    mock_assembler_endpoint: str,
) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint, principal_allowlist=["alice"]) as agent:
        with pytest.raises(ValueError, match="acting_for_user=None"):
            agent.invoke_for("", target_rs_url="https://api.example.com/x", tool="x")


@pytest.mark.parametrize("bad_principal", [123, True, False, ["alice"], {"sub": "alice"}])
def test_agent_rejects_non_str_principal_without_attribute_error(
    mock_assembler: Any, mock_assembler_endpoint: str, bad_principal: Any
) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint, principal_allowlist=["alice"]) as agent:
        with pytest.raises(TypeError):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="x",
                acting_for_user=bad_principal,
            )
        with pytest.raises(TypeError):
            agent.invoke_for(
                bad_principal,
                target_rs_url="https://api.example.com/x",
                tool="x",
            )
    assert mock_assembler.received_request is None


@pytest.mark.parametrize(
    ("bad_provider", "expected_exc"),
    [
        ("", ValueError),
        ("   ", ValueError),
        (" slack", ValueError),
        ("slack ", ValueError),
        ("slack\x00", ValueError),
        ("slack\r\n", ValueError),
        ("\u202eslack", ValueError),
        (123, TypeError),
        (True, TypeError),
        (["slack"], TypeError),
    ],
)
def test_agent_rejects_invalid_provider(
    mock_assembler: Any,
    mock_assembler_endpoint: str,
    bad_provider: Any,
    expected_exc: type[Exception],
) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint, principal_allowlist=["alice"]) as agent:
        with pytest.raises(expected_exc):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="x",
                acting_for_user=None,
                provider=bad_provider,
            )
        with pytest.raises(expected_exc):
            agent.invoke_for(
                "alice",
                target_rs_url="https://api.example.com/x",
                tool="x",
                provider=bad_provider,
            )
    assert mock_assembler.received_request is None


def test_invoke_rejects_duplicate_mixed_case_parent_call_record_header(
    mock_assembler: Any, mock_assembler_endpoint: str
) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint, principal_allowlist=["alice"]) as agent:
        with pytest.raises(HawcxError, match=r"E_AUTHORITY_CLAIM.*0x0058"):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="x",
                acting_for_user=None,
                headers={
                    "X-Hawcx-Parent-Call-Record": "rec-1",
                    "x-hawcx-parent-call-record": "rec-2",
                },
            )
        # CRLF / NUL injection in headers also fails closed before IPC.
        with pytest.raises(ValueError):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="x",
                acting_for_user=None,
                headers={"X-Custom": "val\r\nInjected: 1"},
            )
    assert mock_assembler.received_request is None


def test_invoke_allows_single_parent_call_record_header(
    mock_assembler: Any, mock_assembler_endpoint: str
) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint, principal_allowlist=[]) as agent:
        resp = agent.invoke(
            target_rs_url="https://api.example.com/x",
            tool="x",
            acting_for_user=None,
            headers={"X-Hawcx-Parent-Call-Record": "rec-valid"},
        )
    assert resp.http_status == 200
    assert mock_assembler.received_request is not None
    assert mock_assembler.received_request["headers"]["X-Hawcx-Parent-Call-Record"] == "rec-valid"


# ── ToolCallResponse.from_wire & AssemblerClient._invoke_once (I3) ───────────


@pytest.mark.parametrize(
    "bad_wire",
    [
        None,
        [],
        "ok",
        123,
        True,
        {"request_id": "r1", "http_status": True, "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": False, "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": "200", "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": 200.5, "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": None, "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": -1, "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": 65536, "headers": {}, "body": ""},
        {"request_id": "", "http_status": 200, "headers": {}, "body": ""},
        {"request_id": None, "http_status": 200, "headers": {}, "body": ""},
        {"request_id": True, "http_status": 200, "headers": {}, "body": ""},
        {"request_id": 123, "http_status": 200, "headers": {}, "body": ""},
        {"request_id": "r1", "http_status": 200, "headers": ["bad"], "body": ""},
        {"request_id": "r1", "http_status": 200, "headers": {"k": 1}, "body": ""},
        {"request_id": "r1", "http_status": 200, "headers": {}, "body": 123},
        {"request_id": "r1", "http_status": 200, "headers": {}, "body": "not-valid-base64!!!"},
    ],
)
def test_tool_call_response_from_wire_rejects_bool_and_malformed_types(bad_wire: Any) -> None:
    with pytest.raises(IpcError):
        ToolCallResponse.from_wire(bad_wire)


@pytest.mark.parametrize(
    ("resp_opcode", "raw_payload"),
    [
        (MSG_TOOL_CALL_RESPONSE, b"\xff\xfe"),
        (MSG_TOOL_CALL_RESPONSE, b"{not json"),
        (MSG_TOOL_CALL_RESPONSE, b"[]"),
        (MSG_TOOL_CALL_RESPONSE, b"null"),
        (
            MSG_TOOL_CALL_RESPONSE,
            json.dumps(
                {
                    "request_id": "r1",
                    "http_status": 200,
                    "headers": {},
                    "body": "",
                    "reject_code": "0x0057",
                }
            ).encode("utf-8"),
        ),
        (
            MSG_TOOL_CALL_RESPONSE,
            json.dumps(
                {
                    "request_id": "r1",
                    "http_status": True,
                    "headers": {},
                    "body": "",
                }
            ).encode("utf-8"),
        ),
        (MSG_REQUEST_REJECTED, b"\xff\xfe"),
        (MSG_REQUEST_REJECTED, b"[]"),
        (MSG_REQUEST_REJECTED, b'{"request_id": true, "reason": "x"}'),
        (MSG_REQUEST_REJECTED, b'{"request_id": "r1", "reason": 123}'),
    ],
)
def test_assembler_invoke_once_rejects_malformed_and_contradictory_frames(
    short_sock_path: str, resp_opcode: int, raw_payload: bytes
) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.settimeout(3.0)
    server.bind(short_sock_path)
    server.listen(1)

    def serve() -> None:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        try:
            conn.settimeout(2.0)
            _, _ = read_frame(conn)
            hs = struct.pack(
                ">HHHHB",
                1,
                SDK_VERSION_MAJOR,
                SDK_VERSION_MINOR,
                SDK_VERSION_PATCH,
                ROLE_ASSEMBLER,
            )
            conn.sendall(encode_frame(MSG_TYPE_HANDSHAKE, hs))
            req_type, _ = read_frame(conn)
            assert req_type == MSG_TOOL_CALL_REQUEST
            header = struct.pack(">I", 1 + len(raw_payload)) + bytes([resp_opcode])
            conn.sendall(header + raw_payload)
        except OSError:
            pass
        finally:
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        client = AssemblerClient.connect(short_sock_path, timeout_secs=2.0)
        try:
            with pytest.raises(IpcError):
                client.invoke(
                    ToolCallRequest(
                        request_id="r1",
                        target_rs_url="https://api.example.com/x",
                        http_method="POST",
                        tool="x",
                    )
                )
        finally:
            client.close()
    finally:
        server.close()
        t.join(timeout=2)


# ── Framing, Handshake proto!=1, and Clarification Answer (I3) ───────────────


@pytest.mark.parametrize("bad_opcode", [True, False, -1, 256, "82", 1.5, None])
def test_encode_frame_and_handshake_reject_bool_and_invalid_ints(bad_opcode: Any) -> None:
    with pytest.raises(IpcError):
        encode_frame(bad_opcode, b"{}")
    with pytest.raises(IpcError):
        _encode_handshake(bad_opcode)


@pytest.mark.parametrize("bad_proto", [0, 2, 99])
def test_perform_handshake_rejects_unsupported_protocol_version(
    short_sock_path: str, bad_proto: int
) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.settimeout(3.0)
    server.bind(short_sock_path)
    server.listen(1)

    def serve() -> None:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        try:
            conn.settimeout(2.0)
            _, _ = read_frame(conn)
            hs = struct.pack(
                ">HHHHB",
                bad_proto,
                SDK_VERSION_MAJOR,
                SDK_VERSION_MINOR,
                SDK_VERSION_PATCH,
                ROLE_ASSEMBLER,
            )
            conn.sendall(encode_frame(MSG_TYPE_HANDSHAKE, hs))
        except OSError:
            pass
        finally:
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        with pytest.raises(IpcError, match="protocol version"):
            AssemblerClient.connect(short_sock_path, timeout_secs=2.0)
    finally:
        server.close()
        t.join(timeout=2)


def test_perform_handshake_rejects_bool_local_role() -> None:
    a, b = socket.socketpair()
    a.settimeout(0.5)
    try:
        with pytest.raises(IpcError):
            perform_handshake(a, local_role=True)
        with pytest.raises(IpcError):
            perform_handshake(a, local_role=False)
    finally:
        a.close()
        b.close()


def test_send_clarification_answer_valid_and_bool_rejections() -> None:
    a, b = socket.socketpair()
    try:
        client = AssemblerClient(a)
        client.send_clarification_answer("pend-1", 42, answer_index=1, answer_text="yes")
        msg_type, payload = read_frame(b)
        assert msg_type == MSG_CLARIFICATION_ANSWER
        assert json.loads(payload.decode("utf-8")) == {
            "pending_id": "pend-1",
            "session_id": 42,
            "answer_index": 1,
            "answer_text": "yes",
        }

        for bad_sess in (True, False, "42", 1.5, None):
            with pytest.raises(TypeError):
                client.send_clarification_answer("pend-1", bad_sess)  # type: ignore[arg-type]
        for out_sess in (-1, 2**64):
            with pytest.raises(ValueError):
                client.send_clarification_answer("pend-1", out_sess)
        for bad_idx in (True, False, "0", 1.5):
            with pytest.raises(TypeError):
                client.send_clarification_answer("pend-1", 1, answer_index=bad_idx)  # type: ignore[arg-type]
        for out_idx in (-1, 256):
            with pytest.raises(ValueError):
                client.send_clarification_answer("pend-1", 1, answer_index=out_idx)
        for bad_pid in ("", "   "):
            with pytest.raises(ValueError):
                client.send_clarification_answer(bad_pid, 1)
        for non_str_pid in (None, True, 123):
            with pytest.raises(TypeError):
                client.send_clarification_answer(non_str_pid, 1)  # type: ignore[arg-type]
        for non_str_txt in (True, 123):
            with pytest.raises(TypeError):
                client.send_clarification_answer("pend-1", 1, answer_text=non_str_txt)  # type: ignore[arg-type]
    finally:
        a.close()
        b.close()


# ── egress._connect_request bool port rejection ──────────────────────────────


@pytest.mark.parametrize("bad_port", [True, False, -1, 65536, "443", 443.0, None])
def test_egress_connect_request_rejects_bool_port(bad_port: Any) -> None:
    with pytest.raises(EgressProtocolError):
        _connect_request("example.com", bad_port)


# ── mcp_caller._classify bool status/code, non-2xx & contradiction ───────────


def test_mcp_caller_classify_rejects_bool_status_code_non_2xx_and_contradiction() -> None:
    ok_json = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'

    class _FakeResp:
        def __init__(self, status: Any, body: bytes) -> None:
            self.request_id = "r-test"
            self.http_status = status
            self.body = body

    # 1. Boolean status MUST fail closed (never coerce True -> 1 -> allowed=True).
    for bad_status in (True, False, "200", 500, 502, 404, 199, 302):
        dec = _classify("mail.read", "alice", _FakeResp(bad_status, ok_json))
        assert dec.allowed is False

    # 2. Boolean JSON-RPC error.code MUST fail closed and NEVER be treated as a valid int code.
    for bool_code in (True, False):
        err_body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": bool_code, "message": "x"}}
        ).encode("utf-8")
        dec_err = _classify("mail.read", "alice", _FakeResp(200, err_body))
        assert dec_err.allowed is False
        assert dec_err.reason_code is None

    # 3. Contradictory envelope (decision == "allow" + reject_code, or unknown decision) denies.
    contradictory = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "decision": "allow", "reject_code": "0x0057", "result": {}}
    ).encode("utf-8")
    assert _classify("mail.read", "alice", _FakeResp(200, contradictory)).allowed is False

    unknown_dec = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "decision": "maybe", "result": {}}
    ).encode("utf-8")
    assert _classify("mail.read", "alice", _FakeResp(200, unknown_dec)).allowed is False

    # 4. Positive control: HTTP 200 valid JSON-RPC document still allows.
    good = _classify("mail.read", "alice", _FakeResp(200, ok_json))
    assert good.allowed is True
    assert good.http_status == 200

    # 5. Caller integration sanity check with McpTool.
    tool = McpTool(tool_id="mail.read", url="https://mcp.example.invalid/s", name="list")
    assert Caller(provider="microsoft").invoke_kwargs(tool, "alice")["provider"] == "microsoft"


# ── auth_ipc._parse_register_response strict dict & str checks ───────────────


@pytest.mark.parametrize(
    "bad_body",
    [
        b"null",
        b"[]",
        b"123",
        b'"Enrolled"',
        b"true",
        json.dumps(
            {"type": "Enrolled", "agent_instance_id": True, "client_id": "c", "session_id": "s"}
        ).encode(),
        json.dumps(
            {"type": "Enrolled", "agent_instance_id": "a", "client_id": False, "session_id": "s"}
        ).encode(),
        json.dumps(
            {"type": "Enrolled", "agent_instance_id": "a", "client_id": "c", "session_id": 123}
        ).encode(),
        json.dumps(
            {"type": "Enrolled", "agent_instance_id": "", "client_id": "c", "session_id": "s"}
        ).encode(),
        json.dumps({"type": "Enrolled", "client_id": "c", "session_id": "s"}).encode(),
        json.dumps(
            {
                "type": "AlreadyEnrolled",
                "agent_instance_id": "a",
                "client_id": "c",
                "session_id": "s",
                "trust_level": True,
            }
        ).encode(),
    ],
)
def test_auth_ipc_parse_register_response_rejects_non_dict_and_bool_fields(
    bad_body: bytes,
) -> None:
    with pytest.raises(IpcError):
        _parse_register_response(bad_body)


# ── Index, timeouts, WindowsPipeSocket & submit_template I3 guards ───────────


def test_endpoint_index_timeouts_and_windows_pipe_reject_bool() -> None:
    for bad_index in (True, False, "0", 1.5, None):
        with pytest.raises(TypeError):
            default_endpoint_for("agent-1", index=bad_index)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        default_endpoint_for("agent-1", index=-1, ipc_dir=Path("/var/run/haap"))

    for bad_timeout in (True, False, "5"):
        with pytest.raises(TypeError):
            HawcxAgent.connect(
                "/nonexistent.sock",
                principal_allowlist=[],
                timeout_secs=bad_timeout,  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            AssemblerClient.connect("/nonexistent.sock", timeout_secs=bad_timeout)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AssemblerClient.connect("/nonexistent.sock", tool_call_timeout_secs=bad_timeout)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            AuthenticatorClient.connect("/nonexistent.sock", timeout_secs=bad_timeout)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            HawcxAgent.enroll(
                name="n",
                org_token="ot",
                principal_allowlist=[],
                connect_timeout_secs=bad_timeout,  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            HawcxAgent.enroll(
                name="n",
                org_token="ot",
                principal_allowlist=[],
                enroll_timeout_secs=bad_timeout,  # type: ignore[arg-type]
            )
        with pytest.raises(TypeError):
            pipe_win.WindowsPipeSocket(1).settimeout(bad_timeout)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            pipe_win.connect(r"\\.\pipe\x", timeout_secs=bad_timeout)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            submit_template(
                {},
                console_url="http://console.example.com",
                api_key="hx_k",
                timeout=bad_timeout,  # type: ignore[arg-type]
            )

    for bad_float in (-1.0, float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            HawcxAgent.connect("/nonexistent.sock", principal_allowlist=[], timeout_secs=bad_float)
        with pytest.raises(ValueError):
            pipe_win.WindowsPipeSocket(1).settimeout(bad_float)
        with pytest.raises(ValueError):
            submit_template(
                {},
                console_url="http://console.example.com",
                api_key="hx_k",
                timeout=bad_float,
            )

    with pytest.raises(TypeError):
        pipe_win.WindowsPipeSocket(True)
    with pytest.raises(TypeError):
        pipe_win.WindowsPipeSocket(False)


def test_submit_template_2xx_rejects_malformed_json_and_error_envelopes() -> None:
    class _RawHandler(BaseHTTPRequestHandler):
        raw_body: bytes = b""

        def do_POST(self) -> None:  # noqa: N802
            _ = self.rfile.read(int(self.headers.get("content-length", "0")))
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(type(self).raw_body)))
            self.end_headers()
            self.wfile.write(type(self).raw_body)

        def log_message(self, *_args: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), _RawHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        for bad_200 in (
            b"<html>not json</html>",
            b"[]",
            b'"scalar"',
            b'{"error": "unexpected_failure"}',
            b'{"decision": "allow", "reject_code": "0x0057"}',
        ):
            _RawHandler.raw_body = bad_200
            with pytest.raises(SubmitError):
                submit_template({"name": "x"}, console_url=url, api_key="hx_k")
    finally:
        srv.shutdown()


# ── Seeded Hypothesis fuzz tests across wire parsers (derandomized) ──────────

_ANY_JSON = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**65), max_value=2**65),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=32),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=16), children, max_size=5),
    ),
    max_leaves=12,
)


@settings(derandomize=True, max_examples=100)
@given(arbitrary=_ANY_JSON)
def test_prop_wire_parsers_never_accept_bool_or_crash(arbitrary: Any) -> None:
    # 1. ToolCallResponse.from_wire: strict int status or raise IpcError.
    try:
        resp = ToolCallResponse.from_wire(arbitrary)
    except IpcError:
        pass
    else:
        assert type(resp.http_status) is int
        assert 0 <= resp.http_status <= 0xFFFF
        assert isinstance(resp.request_id, str)
        assert len(resp.request_id) > 0

    # 2. _parse_register_response: raise (IpcError, HawcxError) or strict str IDs.
    raw = json.dumps(arbitrary).encode("utf-8")
    try:
        enr = _parse_register_response(raw)
    except (IpcError, HawcxError):
        pass
    else:
        assert isinstance(enr.agent_instance_id, str) and len(enr.agent_instance_id) > 0
        assert isinstance(enr.client_id, str) and len(enr.client_id) > 0
        assert isinstance(enr.session_id, str) and len(enr.session_id) > 0

    # 3. mcp_caller._classify: never raises, and never allows boolean/non-2xx status.
    class _R:
        request_id = "r-prop"
        http_status = arbitrary if isinstance(arbitrary, (int, str, type(None))) else 200
        body = raw

    dec = _classify("tool.x", "alice", _R())
    assert isinstance(dec.allowed, bool)
    assert not (dec.allowed and isinstance(_R.http_status, bool))

    # Also test valid base64 ToolCallResponse round-trip property.
    valid_wire = {
        "request_id": "req-prop",
        "http_status": 200,
        "headers": {"x-k": "v"},
        "body": base64.b64encode(b"ok").decode("ascii"),
    }
    parsed = ToolCallResponse.from_wire(valid_wire)
    assert parsed.http_status == 200
    assert parsed.body == b"ok"


# ── Iteration-2 Challenger Remediation Tests (C1, C3, C4, C5, C6) ────────────


def test_c1_assembler_rejects_mismatched_response_and_rejection_request_id(
    short_sock_path: str,
) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.settimeout(5.0)
    server.bind(short_sock_path)
    server.listen(4)

    scripted_replies: list[tuple[int, dict[str, Any]]] = [
        # 1st connection: mismatched 0x53 request_id -> must fail closed and mark _needs_redial
        (
            MSG_TOOL_CALL_RESPONSE,
            {
                "request_id": "TOTALLY-DIFFERENT-REQ-ID",
                "http_status": 200,
                "headers": {},
                "body": base64.b64encode(b"spoofed").decode("ascii"),
            },
        ),
        # 2nd connection: matching 0x53 request_id -> proves client re-dialed fresh socket
        (
            MSG_TOOL_CALL_RESPONSE,
            {
                "request_id": "req-expected-2",
                "http_status": 200,
                "headers": {},
                "body": base64.b64encode(b"genuine").decode("ascii"),
            },
        ),
        # 3rd connection: mismatched non-empty 0x54 RequestRejected request_id -> IpcError
        (
            MSG_REQUEST_REJECTED,
            {"request_id": "SPOOFED-REJECTION-ID", "reason": "denied"},
        ),
        # 4th connection: empty request_id on 0x54 -> still raises RequestRejected cleanly
        (
            MSG_REQUEST_REJECTED,
            {"request_id": "", "reason": "policy denied"},
        ),
    ]

    def serve() -> None:
        for opcode, payload_obj in scripted_replies:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                conn.settimeout(2.0)
                _, _ = read_frame(conn)
                hs = struct.pack(
                    ">HHHHB",
                    1,
                    SDK_VERSION_MAJOR,
                    SDK_VERSION_MINOR,
                    SDK_VERSION_PATCH,
                    ROLE_ASSEMBLER,
                )
                conn.sendall(encode_frame(MSG_TYPE_HANDSHAKE, hs))
                req_type, _ = read_frame(conn)
                assert req_type == MSG_TOOL_CALL_REQUEST
                raw = json.dumps(payload_obj).encode("utf-8")
                conn.sendall(encode_frame(opcode, raw))
            except OSError:
                pass
            finally:
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        client = AssemblerClient.connect(short_sock_path, timeout_secs=2.0)
        try:
            with pytest.raises(IpcError, match="request_id"):
                client.invoke(
                    ToolCallRequest(
                        request_id="req-expected-1",
                        target_rs_url="https://api.example.com/x",
                        http_method="POST",
                        tool="x",
                    )
                )
            assert client._needs_redial is True

            ok_resp = client.invoke(
                ToolCallRequest(
                    request_id="req-expected-2",
                    target_rs_url="https://api.example.com/x",
                    http_method="POST",
                    tool="x",
                )
            )
            assert ok_resp.request_id == "req-expected-2"
            assert ok_resp.body == b"genuine"

            # Force spend/redial for 3rd scripted connection
            client._needs_redial = True
            with pytest.raises(IpcError, match="request_id"):
                client.invoke(
                    ToolCallRequest(
                        request_id="req-expected-3",
                        target_rs_url="https://api.example.com/x",
                        http_method="POST",
                        tool="x",
                    )
                )
            assert client._needs_redial is True

            with pytest.raises(RequestRejected, match="policy denied") as rej_ei:
                client.invoke(
                    ToolCallRequest(
                        request_id="req-expected-4",
                        target_rs_url="https://api.example.com/x",
                        http_method="POST",
                        tool="x",
                    )
                )
            assert rej_ei.value.request_id == "req-expected-4"
        finally:
            client.close()
    finally:
        server.close()
        t.join(timeout=2)


def test_c3_constraints_reject_provider_authority_claims_and_bad_types(
    mock_assembler: Any, mock_assembler_endpoint: str
) -> None:
    # 1. Provider nested/cased/confusable inside constraints MUST raise ValueError.
    for bad_provider_constraints in (
        {"provider": "evil"},
        {"PROVIDER": "evil"},
        {" provider ": "evil"},
        {"meta": {"provider": "evil"}},
    ):
        with pytest.raises(ValueError, match="provider"):
            ToolCallRequest(
                "r1",
                "https://x",
                "POST",
                tool="t",
                provider="slack",
                constraints=bad_provider_constraints,
            ).to_wire()

    # 2. Authority keys inside constraints MUST raise HawcxError (0x0058).
    for bad_auth_constraints in (
        {"user_principal_id": "bob@example.com"},
        {"acting_for_user": "bob@example.com"},
        {"user_subject": "bob@example.com"},
        {"ciba_approved": True},
        {"ciba_approved": 1},
        {"ciba_approved": None},
        {"nested": [{"user_principal_id": "bob@example.com"}]},
    ):
        with pytest.raises(HawcxError, match="0x0058"):
            ToolCallRequest(
                "r1",
                "https://x",
                "POST",
                tool="t",
                constraints=bad_auth_constraints,
            ).to_wire()

    # 3. Non-dict constraints & invalid max_requests / require_pop types.
    for bad_type_constraints in (
        [("max_requests", 5)],
        "invalid",
        123,
        {"max_requests": True},
        {"max_requests": False},
        {"max_requests": "5"},
        {"require_pop": 1},
        {"require_pop": "true"},
    ):
        with pytest.raises(TypeError):
            ToolCallRequest(
                "r1",
                "https://x",
                "POST",
                tool="t",
                constraints=bad_type_constraints,  # type: ignore[arg-type]
            ).to_wire()

    for out_of_range_constraints in (
        {"max_requests": -1},
        {"max_requests": 2**64},
    ):
        with pytest.raises(ValueError):
            ToolCallRequest(
                "r1",
                "https://x",
                "POST",
                tool="t",
                constraints=out_of_range_constraints,
            ).to_wire()

    # 4. Live HawcxAgent.invoke & invoke_for enforce all constraints guards BEFORE IPC.
    with HawcxAgent.connect(
        mock_assembler_endpoint, principal_allowlist=["alice@example.com"]
    ) as agent:
        with pytest.raises(ValueError, match="provider"):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="t",
                acting_for_user=None,
                constraints={"provider": "evil_shadow"},
            )
        with pytest.raises(ValueError, match="provider"):
            agent.invoke_for(
                "alice@example.com",
                target_rs_url="https://api.example.com/x",
                tool="t",
                provider="slack",
                constraints={"provider": "evil"},
            )
        with pytest.raises(HawcxError, match="0x0058"):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="t",
                acting_for_user=None,
                constraints={"ciba_approved": True},
            )
        with pytest.raises(TypeError):
            agent.invoke(
                target_rs_url="https://api.example.com/x",
                tool="t",
                acting_for_user=None,
                constraints=[("a", 1)],  # type: ignore[arg-type]
            )
        assert mock_assembler.received_request is None

        # Positive control: valid constraints + ciba_approved=False allowed.
        resp = agent.invoke_for(
            "alice@example.com",
            target_rs_url="https://api.example.com/x",
            tool="t",
            provider="slack",
            constraints={"max_requests": 10, "require_pop": True, "ciba_approved": False},
        )
        assert resp.http_status == 200
        assert mock_assembler.received_request is not None
        assert mock_assembler.received_request["provider"] == "slack"
        assert mock_assembler.received_request["constraints"]["max_requests"] == 10


def test_c3_tool_arguments_rejects_non_dict_fail_closed(
    mock_assembler: Any, mock_assembler_endpoint: str
) -> None:
    for bad_args in ([1, 2], "not-an-object", 123, True, {1: "non-str-key"}):
        with pytest.raises(TypeError):
            ToolCallRequest(
                "r1", "https://x", "POST", tool="t", tool_arguments=bad_args
            ).to_wire()

    with HawcxAgent.connect(mock_assembler_endpoint, principal_allowlist=[]) as agent:
        for bad_args in ([1, 2], "not-an-object", 123, True):
            with pytest.raises(TypeError):
                agent.invoke(
                    target_rs_url="https://api.example.com/x",
                    tool="t",
                    acting_for_user=None,
                    tool_arguments=bad_args,
                )
    assert mock_assembler.received_request is None


def test_c3_agent_id_and_enroll_name_reject_traversal_and_control_chars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HAAP_AUTH_CONTROL_SOCK", raising=False)
    for bad_seg in (
        "",
        "   ",
        " research ",
        ".",
        "..",
        "../../etc/passwd",
        "ag..1",
        "ag/1",
        "ag\\1",
        "ag\x001",
        "ag\r\n1",
        "\u202eag",
    ):
        with pytest.raises(ValueError):
            default_endpoint_for(bad_seg, ipc_dir=Path("/var/run/haap"))
        with pytest.raises(ValueError):
            default_auth_control_socket_for(bad_seg, ipc_dir=Path("/var/run/haap"))
        with pytest.raises(HawcxError):
            HawcxAgent.enroll(name=bad_seg, org_token="ot-valid", principal_allowlist=[])

    for non_str_seg in (123, True, None, ["ag"]):
        with pytest.raises(TypeError):
            default_endpoint_for(non_str_seg, ipc_dir=Path("/var/run/haap"))  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            default_auth_control_socket_for(non_str_seg, ipc_dir=Path("/var/run/haap"))  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            HawcxAgent.enroll(
                name=non_str_seg,  # type: ignore[arg-type]
                org_token="ot-valid",
                principal_allowlist=[],
            )


def test_c4_submit_template_url_apikey_200_deny_and_500_non_dict_json() -> None:
    for bad_url in (
        "",
        "   ",
        " https://console.example.com",
        "https://console.example.com\r\n",
        "https://console.example.com\x00",
        "ftp://localhost:21",
        "file:///etc/passwd",
        "http://localhost:0",
        "https://console.example.com:0",
        "https://console.example.com:abc",
        "https://user:pass@console.example.com",
        "https://console.example.com\\evil",
        "https://console.example.com?x=1",
        "https://console.example.com#frag",
        "https://.example.com",
        "https://example..com",
        "https://console.example.com/subpath",
        "https://169.254.169.254",
        "https://0.0.0.0",
        "https://[::]",
        "https://[fe80::1]",
        "https://[fd00:ec2::254]",
        "https://[::ffff:127.0.0.1]",
        "https://metadata.google.internal",
        "https://metadata.goog",
        "https://instance-data",
        "http://console.example.com",
    ):
        with pytest.raises(SubmitError):
            submit_template({"name": "x"}, console_url=bad_url, api_key="hx_valid")

    for bad_key in ("", "   ", " hx_k", "hx_k\r\n", "hx_k\x00", "hx_k space"):
        with pytest.raises(SubmitError):
            submit_template(
                {"name": "x"}, console_url="https://console.example.com", api_key=bad_key
            )

    class _DynamicReplyHandler(BaseHTTPRequestHandler):
        status_code: int = 200
        raw_body: bytes = b"{}"

        def do_POST(self) -> None:  # noqa: N802
            _ = self.rfile.read(int(self.headers.get("content-length", "0")))
            self.send_response(type(self).status_code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(type(self).raw_body)))
            self.end_headers()
            self.wfile.write(type(self).raw_body)

        def log_message(self, *_args: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), _DynamicReplyHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        # HTTP 200 deny / non-null reject_code MUST raise SubmitError.
        for bad_200 in (
            b'{"decision": "deny", "reject_code": "0x0057"}',
            b'{"decision": "deny"}',
            b'{"reject_code": "0x0058"}',
        ):
            _DynamicReplyHandler.status_code = 200
            _DynamicReplyHandler.raw_body = bad_200
            with pytest.raises(SubmitError):
                submit_template({"name": "x"}, console_url=url, api_key="hx_k")

        # HTTP 500 non-dict JSON MUST raise SubmitError (never AttributeError).
        for bad_500 in (
            b"[]",
            b"null",
            b"123",
            b'"Internal Server Error"',
            b'{"error": "fail", "errors": "not-a-list"}',
            b'{"error": "fail", "errors": [123]}',
        ):
            _DynamicReplyHandler.status_code = 500
            _DynamicReplyHandler.raw_body = bad_500
            with pytest.raises(SubmitError) as ei:
                submit_template({"name": "x"}, console_url=url, api_key="hx_k")
            assert ei.value.status == 500
            assert isinstance(ei.value.errors, list)
    finally:
        srv.shutdown()


def test_c4_cli_submit_handles_malformed_errors_field_without_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid_tpl = tmp_path / "tpl.json"
    valid_tpl.write_text(
        json.dumps(
            {
                "template": "hawcx/agent-template/v1",
                "name": "o365-group-assistant",
                "version": "0.1.0",
                "framework": {"kind": "langchain"},
                "tools": [{"id": "o365.mail.read", "actions": ["read"], "risk": "read_internal"}],
            }
        ),
        encoding="utf-8",
    )

    class _Err500Handler(BaseHTTPRequestHandler):
        raw_body: bytes = b'{"error":"fail","errors":"not-a-list"}'

        def do_POST(self) -> None:  # noqa: N802
            _ = self.rfile.read(int(self.headers.get("content-length", "0")))
            self.send_response(500)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(type(self).raw_body)))
            self.end_headers()
            self.wfile.write(type(self).raw_body)

        def log_message(self, *_args: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), _Err500Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("HAWCX_CONSOLE_URL", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setenv("HAWCX_API_KEY", "hx_testkey")
    try:
        for body in (
            b'{"error":"fail","errors":"not-a-list"}',
            b'{"error":"fail","errors":[123, null, {"code":"E_X","path":"$.tools"}]}',
        ):
            _Err500Handler.raw_body = body
            rc = cli_main(["submit", str(valid_tpl), "--org", "ukg"])
            assert rc == 1
    finally:
        srv.shutdown()


async def test_c5_egress_rejects_bool_nan_inf_negative_timeouts_and_non_bool_http2(
    short_sock_path: str,
) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(short_sock_path)
    server.listen(8)
    try:
        for bad_type_timeout in (True, False, "5"):
            with pytest.raises(EgressError) as ei_sync:
                egress._socks5_connect_sync(
                    short_sock_path, "example.com", 443, bad_type_timeout  # type: ignore[arg-type]
                )
            assert isinstance(ei_sync.value, TypeError)

            with pytest.raises(EgressError) as ei_async:
                await egress._socks5_connect_async(
                    short_sock_path, "example.com", 443, bad_type_timeout  # type: ignore[arg-type]
                )
            assert isinstance(ei_async.value, TypeError)

            with pytest.raises(EgressError) as ei_cli:
                egress.client(
                    socket_path=short_sock_path,
                    flavor="stdlib",
                    timeout=bad_type_timeout,
                )
            assert isinstance(ei_cli.value, TypeError)

        for bad_val_timeout in (-1.0, float("nan"), float("inf"), float("-inf")):
            with pytest.raises(EgressError) as ei_v_sync:
                egress._socks5_connect_sync(short_sock_path, "example.com", 443, bad_val_timeout)
            assert isinstance(ei_v_sync.value, ValueError)

            with pytest.raises(EgressError) as ei_v_async:
                await egress._socks5_connect_async(
                    short_sock_path, "example.com", 443, bad_val_timeout
                )
            assert isinstance(ei_v_async.value, ValueError)

            with pytest.raises(EgressError) as ei_v_cli:
                egress.client(socket_path=short_sock_path, flavor="stdlib", timeout=bad_val_timeout)
            assert isinstance(ei_v_cli.value, ValueError)

        for bad_http2 in (1, 0, "true", None):
            with pytest.raises(EgressError) as ei_h2:
                egress.client(
                    socket_path=short_sock_path,
                    flavor="stdlib",
                    http2=bad_http2,  # type: ignore[arg-type]
                )
            assert isinstance(ei_h2.value, TypeError)
    finally:
        server.close()


def test_c6_auth_ipc_rejects_contradictory_enrolled_with_error_or_reject_code() -> None:
    for contradictory in (
        {
            "type": "Enrolled",
            "agent_instance_id": "a",
            "client_id": "c",
            "session_id": "s",
            "error": "boom",
        },
        {
            "type": "Enrolled",
            "agent_instance_id": "a",
            "client_id": "c",
            "session_id": "s",
            "reject_code": "0x0058",
        },
        {
            "type": "AlreadyEnrolled",
            "agent_instance_id": "a",
            "client_id": "c",
            "session_id": "s",
            "error": "boom",
        },
        {
            "type": "AlreadyEnrolled",
            "agent_instance_id": "a",
            "client_id": "c",
            "session_id": "s",
            "reject_code": "0x0057",
        },
    ):
        with pytest.raises(IpcError):
            _parse_register_response(json.dumps(contradictory).encode("utf-8"))


def test_c6_int_subclass_str_enum_rejected_across_all_int_surfaces() -> None:
    class StrIntEnum(int, Enum):
        ZERO = 0
        ONE = 1
        OP = 0x52
        OK = 200
        PORT = 443

        def __str__(self) -> str:
            return "EVIL/../../sock"

    with pytest.raises(TypeError):
        default_endpoint_for("ag1", index=StrIntEnum.ZERO, ipc_dir=Path("/run/haap"))
    with pytest.raises(IpcError):
        ToolCallResponse.from_wire(
            {"request_id": "r1", "http_status": StrIntEnum.OK, "headers": {}, "body": ""}
        )
    with pytest.raises(IpcError):
        encode_frame(StrIntEnum.OP, b"{}")
    with pytest.raises(IpcError):
        _encode_handshake(StrIntEnum.ONE)
    with pytest.raises(EgressProtocolError):
        _connect_request("example.com", StrIntEnum.PORT)
    with pytest.raises(EgressProtocolError):
        egress._mux_request("example.com", StrIntEnum.PORT)
    with pytest.raises(EgressError):
        egress.resolve_broker_handle(StrIntEnum.ONE)
    with pytest.raises(TypeError):
        pipe_win.WindowsPipeSocket(StrIntEnum.ONE)

    class _EnumStatusResp:
        request_id = "r-enum"
        http_status = StrIntEnum.OK
        body = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'

    assert _classify("mail.read", "alice", _EnumStatusResp()).allowed is False

    a, b = socket.socketpair()
    try:
        client = AssemblerClient(a)
        with pytest.raises(TypeError):
            client.send_clarification_answer("pend-1", StrIntEnum.ONE)
        with pytest.raises(TypeError):
            client.send_clarification_answer("pend-1", 1, answer_index=StrIntEnum.ZERO)
    finally:
        a.close()
        b.close()


def test_c6_windows_pipe_socket_handle_bounds_and_recv_validation() -> None:
    for invalid_handle in (-1, 0, 2**64, 0xFFFFFFFFFFFFFFFF, pipe_win.INVALID_HANDLE_VALUE):
        with pytest.raises(ValueError):
            pipe_win.WindowsPipeSocket(invalid_handle)  # type: ignore[arg-type]

    sock = pipe_win.WindowsPipeSocket(1)
    assert sock.recv(0) == b""
    for bool_n in (True, False):
        with pytest.raises(TypeError):
            sock.recv(bool_n)
    with pytest.raises(ValueError):
        sock.recv(-1)


def test_c6_extract_handles_result_list_and_rejects_null_or_non_str_inputs() -> None:
    rep = extract_from_mcp_tools_list({"result": [{"name": "get_user"}]}, namespace="ns")
    assert [t["id"] for t in rep.tools] == ["ns.get_user"]

    for bad_payload in ({"result": None}, {"result": 123}, {"result": "bad"}, 42, None):
        with pytest.raises(ExtractError):
            extract_from_mcp_tools_list(bad_payload, namespace="ns")

    for bad_ns in (None, 123, True, ["ns"]):
        with pytest.raises(ExtractError):
            extract_from_names(["get_user"], namespace=bad_ns)  # type: ignore[arg-type]
        with pytest.raises(ExtractError):
            extract_from_mcp_tools_list([{"name": "get_user"}], namespace=bad_ns)  # type: ignore[arg-type]

    with pytest.raises(ExtractError):
        extract_from_names("get_user", namespace="ns")  # type: ignore[arg-type]

    mixed = extract_from_names(["get_user", 123, None], namespace="ns")  # type: ignore[list-item]
    assert [t["id"] for t in mixed.tools] == ["ns.get_user"]
    assert len(mixed.refused) == 2


def test_c6_bundle_rejects_newline_and_control_chars_in_interpreter(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "__main__.py").write_text("print('ok')\n", encoding="utf-8")
    out = tmp_path / "out.pyz"

    for bad_interp in (
        "/usr/bin/env python3\n# injected line",
        "/usr/bin/env python3\r\n# injected",
        "/usr/bin/python3\x00",
        "",
        "   ",
        " /usr/bin/env python3 ",
        "\u202e/usr/bin/python3",
        None,
        123,
        True,
    ):
        with pytest.raises(BundleError):
            build_bundle(proj, out, interpreter=bad_interp)  # type: ignore[arg-type]
        assert not out.exists()


# ── Iteration-3 Challenger Remediation Tests (D1 & D2) ───────────────────────


def test_d1_validate_console_url_rejects_non_canonical_ipv4_and_allows_valid_hosts() -> None:
    for non_canonical_or_hostile_url in (
        "https://2852039166",
        "https://0xa9fea9fe",
        "https://0XA9FEA9FE",
        "https://0251.0376.0251.0376",
        "https://169.254.43518",
        "https://169.254.0xa9fe",
        "https://0",
        "https://0.0",
        "https://0.0.0",
        "https://127.1",
        "https://2130706433",
        "https://0x7f000001",
        "https://[0xa9fea9fe]",
        "https://[127.0.0.1]",
        "https://[::ffff:0251.0376.0251.0376]",
        "https://[unclosed",
        "https://169\u3002254\u3002169\u3002254",
        "https://metadata\u3002google\u3002internal",
        "https://2852039166%25lo0",
    ):
        with pytest.raises(SubmitError):
            _validate_console_url(non_canonical_or_hostile_url)

    # Positive controls: canonical hostnames and loopback origins continue to succeed.
    assert _validate_console_url("https://console.example.com") == "https://console.example.com"
    assert (
        _validate_console_url("https://console-01.corp.example:8443/")
        == "https://console-01.corp.example:8443"
    )
    assert _validate_console_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert _validate_console_url("http://localhost:3000") == "http://localhost:3000"
    assert _validate_console_url("http://[::1]:8080") == "http://[::1]:8080"


def test_d1_submit_template_refuses_all_http_redirects_without_leaking_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_hits: list[tuple[str, str, str | None]] = []

    class _TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            target_hits.append((self.command, self.path, self.headers.get("Authorization")))
            blob = b'{"status":"draft","id":"spoofed-ssrf"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def do_POST(self) -> None:  # noqa: N802
            self.do_GET()

        def log_message(self, *_args: Any) -> None:
            pass

    s_tgt = HTTPServer(("127.0.0.1", 0), _TargetHandler)
    threading.Thread(target=s_tgt.serve_forever, daemon=True).start()
    tgt_port = s_tgt.server_address[1]

    class _RedirectHandler(BaseHTTPRequestHandler):
        redirect_code: int = 302
        location_url: str = f"http://0.0.0.0:{tgt_port}/latest/meta-data/iam"

        def do_POST(self) -> None:  # noqa: N802
            _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(type(self).redirect_code)
            self.send_header("Location", type(self).location_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            pass

    s_red = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    threading.Thread(target=s_red.serve_forever, daemon=True).start()
    red_url = f"http://127.0.0.1:{s_red.server_address[1]}"

    try:
        for code in (301, 302, 303, 307, 308):
            _RedirectHandler.redirect_code = code
            _RedirectHandler.location_url = f"http://0.0.0.0:{tgt_port}/latest/meta-data/iam"
            with pytest.raises(SubmitError, match=rf"refusing HTTP {code} redirect") as ei:
                submit_template({"name": "x"}, console_url=red_url, api_key="hx_super_secret")
            assert ei.value.status == code
            assert target_hits == []

        # Malformed bracketed Location on 302 MUST also raise SubmitError cleanly.
        _RedirectHandler.redirect_code = 302
        _RedirectHandler.location_url = "http://[bad-ipv6]/evil"
        with pytest.raises(SubmitError, match="refusing HTTP 302 redirect") as ei_mal:
            submit_template({"name": "x"}, console_url=red_url, api_key="hx_super_secret")
        assert ei_mal.value.status == 302
        assert target_hits == []

        # Direct _NoRedirectHandler.redirect_request probe (HTTPS -> HTTP same-host downgrade).
        handler_cls = submit_mod._NoRedirectHandler
        req = urllib.request.Request(
            "https://console.example.com/api/agent-templates",
            headers={"Authorization": "Bearer hx_super_secret"},
            method="POST",
        )
        fp = io.BytesIO(b"")
        with pytest.raises(urllib.error.HTTPError, match="refusing HTTP 302 redirect") as http_ei:
            handler_cls().redirect_request(
                req,
                fp,
                302,
                "Found",
                {"Location": "http://console.example.com/api/agent-templates"},
                "http://console.example.com/api/agent-templates",
            )
        assert http_ei.value.code == 302

        # Positive control: unit-test monkeypatching of hawcx_haap.submit.urlopen still works.
        seen_urls: list[str] = []

        class _FakeResp:
            status = 200

            def __enter__(self) -> _FakeResp:
                return self

            def __exit__(self, *_a: Any) -> None:
                return None

            def read(self) -> bytes:
                return b'{"id":"mp-ok","status":"draft"}'

        def _fake_urlopen(r: urllib.request.Request, timeout: float = 30) -> _FakeResp:
            seen_urls.append(r.full_url)
            return _FakeResp()

        monkeypatch.setattr(submit_mod, "urlopen", _fake_urlopen)
        out = submit_template(
            {"name": "x"}, console_url="https://console.example.com", api_key="hx_mp"
        )
        assert out["id"] == "mp-ok"
        assert seen_urls == ["https://console.example.com/api/agent-templates"]
    finally:
        s_red.shutdown()
        s_tgt.shutdown()


def test_d2_assembler_client_recovers_after_transient_outage_and_close_raises_ipc_error(
    short_sock_path: str,
) -> None:
    def _serve_single_call(sock_path: str, reply_body: bytes) -> threading.Thread:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.settimeout(5.0)
        srv.bind(sock_path)
        srv.listen(1)

        def _run() -> None:
            try:
                conn, _ = srv.accept()
            except OSError:
                srv.close()
                return
            try:
                conn.settimeout(2.0)
                _, _ = read_frame(conn)
                hs = struct.pack(
                    ">HHHHB",
                    1,
                    SDK_VERSION_MAJOR,
                    SDK_VERSION_MINOR,
                    SDK_VERSION_PATCH,
                    ROLE_ASSEMBLER,
                )
                conn.sendall(encode_frame(MSG_TYPE_HANDSHAKE, hs))
                opcode, raw_req = read_frame(conn)
                assert opcode == MSG_TOOL_CALL_REQUEST
                req_obj = json.loads(raw_req.decode("utf-8"))
                resp_obj = {
                    "request_id": req_obj["request_id"],
                    "http_status": 200,
                    "headers": {},
                    "body": base64.b64encode(reply_body).decode("ascii"),
                }
                conn.sendall(
                    encode_frame(MSG_TOOL_CALL_RESPONSE, json.dumps(resp_obj).encode("utf-8"))
                )
            finally:
                conn.close()
                srv.close()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t

    t1 = _serve_single_call(short_sock_path, b"call-1-ok")
    agent = HawcxAgent.connect(
        short_sock_path,
        principal_allowlist=["alice@example.com", "bob@example.com"],
        timeout_secs=1.0,
    )
    try:
        # Call 1 succeeds; single-request server closes connection afterwards.
        r1 = agent.invoke_for(
            "alice@example.com",
            target_rs_url="https://api.example.com/one",
            tool="doc.read",
        )
        t1.join(timeout=2)
        assert r1.http_status == 200
        assert r1.body == b"call-1-ok"

        # Simulate transient Assembler outage (unlink socket before Call 2 redials).
        os.unlink(short_sock_path)
        with pytest.raises(IpcError) as outage_ei_1:
            agent.invoke_for(
                "bob@example.com",
                target_rs_url="https://api.example.com/two",
                tool="doc.read",
            )
        assert isinstance(outage_ei_1.value, HawcxError)
        assert agent._client is not None
        assert agent._client._needs_redial is True
        assert agent._client._closed is False

        # Second attempt while still down MUST ALSO raise IpcError (NEVER raw OSError/EBADF!).
        with pytest.raises(IpcError) as outage_ei_2:
            agent.invoke_for(
                "alice@example.com",
                target_rs_url="https://api.example.com/two-b",
                tool="doc.read",
            )
        assert isinstance(outage_ei_2.value, HawcxError)
        assert agent._client._needs_redial is True

        # Bring fresh Assembler listener back up at the same path -> Call 3 MUST recover cleanly!
        t2 = _serve_single_call(short_sock_path, b"call-3-recovered")
        r3 = agent.invoke_for(
            "bob@example.com",
            target_rs_url="https://api.example.com/three",
            tool="doc.read",
        )
        t2.join(timeout=2)
        assert r3.http_status == 200
        assert r3.body == b"call-3-recovered"
        assert agent._client._needs_redial is False
    finally:
        agent.close()

    # Permanent AssemblerClient.close() MUST raise IpcError on subsequent invoke / clarification.
    a, b = socket.socketpair()
    try:
        cli = AssemblerClient(a)
        cli.close()
        assert cli._closed is True
        assert cli._needs_redial is False
        with pytest.raises(IpcError, match="already closed"):
            cli.invoke(ToolCallRequest("r-closed", "https://x", "POST", tool="t"))
        with pytest.raises(IpcError, match="already closed"):
            cli.send_clarification_answer("pend-1", 1, answer_text="no")
    finally:
        a.close()
        b.close()


def test_d2_assembler_invoke_once_retires_corrupted_stream_zero_leftover_read(
    short_sock_path: str,
) -> None:
    # 1. Bare socketpair: malformed ToolCallResponse.from_wire + pipelined b"LEFTOVER".
    a1, b1 = socket.socketpair()
    try:
        cli1 = AssemblerClient(a1)

        def _peer_leftover() -> None:
            _ = read_frame(b1)
            b1.sendall(
                encode_frame(
                    MSG_TOOL_CALL_RESPONSE,
                    b'{"request_id":"r1","http_status":true,"headers":{},"body":""}',
                )
            )
            b1.sendall(
                encode_frame(
                    MSG_TOOL_CALL_RESPONSE,
                    json.dumps(
                        {
                            "request_id": "r2",
                            "http_status": 200,
                            "headers": {},
                            "body": base64.b64encode(b"LEFTOVER").decode("ascii"),
                        }
                    ).encode("utf-8"),
                )
            )

        tp1 = threading.Thread(target=_peer_leftover, daemon=True)
        tp1.start()
        with pytest.raises(IpcError, match="http_status"):
            cli1.invoke(ToolCallRequest("r1", "https://x", "POST", tool="t"))
        assert cli1._needs_redial is True
        assert cli1._closed is False

        with pytest.raises(IpcError, match="no endpoint"):
            cli1.invoke(ToolCallRequest("r2", "https://x", "POST", tool="t"))
        tp1.join(timeout=2)
    finally:
        a1.close()
        b1.close()

    # 2. Bare socketpair: oversized 70,000-byte frame header leaving unread payload in buffer.
    a2, b2 = socket.socketpair()
    try:
        cli2 = AssemblerClient(a2)

        def _peer_oversized() -> None:
            _ = read_frame(b2)
            b2.sendall(struct.pack(">I", 70000) + bytes([MSG_TOOL_CALL_RESPONSE]) + b"G" * 1024)

        tp2 = threading.Thread(target=_peer_oversized, daemon=True)
        tp2.start()
        with pytest.raises(IpcError, match="frame too large"):
            cli2.invoke(ToolCallRequest("r-big", "https://x", "POST", tool="t"))
        assert cli2._needs_redial is True
        with pytest.raises(IpcError, match="no endpoint"):
            cli2.invoke(ToolCallRequest("r-next", "https://x", "POST", tool="t"))
        tp2.join(timeout=2)
    finally:
        a2.close()
        b2.close()

    # 3. Endpoint-backed AF_UNIX server: corrupted stream retired -> Call 2 redials fresh socket,
    #    AND spoofed request_id containing "closed connection" is NEVER mis-retried!
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.settimeout(5.0)
    srv.bind(short_sock_path)
    srv.listen(3)
    conn_count = 0

    def _serve_three() -> None:
        nonlocal conn_count
        for idx in range(3):
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn_count += 1
            try:
                conn.settimeout(2.0)
                _, _ = read_frame(conn)
                hs = struct.pack(
                    ">HHHHB",
                    1,
                    SDK_VERSION_MAJOR,
                    SDK_VERSION_MINOR,
                    SDK_VERSION_PATCH,
                    ROLE_ASSEMBLER,
                )
                conn.sendall(encode_frame(MSG_TYPE_HANDSHAKE, hs))
                _, raw_req = read_frame(conn)
                req_obj = json.loads(raw_req.decode("utf-8"))
                if idx == 0:
                    conn.sendall(
                        encode_frame(
                            MSG_TOOL_CALL_RESPONSE,
                            b'{"request_id":"r1","http_status":true,"headers":{},"body":""}',
                        )
                    )
                    conn.sendall(
                        encode_frame(
                            MSG_TOOL_CALL_RESPONSE,
                            json.dumps(
                                {
                                    "request_id": "r2",
                                    "http_status": 200,
                                    "headers": {},
                                    "body": base64.b64encode(b"LEFTOVER").decode("ascii"),
                                }
                            ).encode("utf-8"),
                        )
                    )
                elif idx == 1:
                    conn.sendall(
                        encode_frame(
                            MSG_TOOL_CALL_RESPONSE,
                            json.dumps(
                                {
                                    "request_id": req_obj["request_id"],
                                    "http_status": 200,
                                    "headers": {},
                                    "body": base64.b64encode(b"FRESH-CONN-2").decode("ascii"),
                                }
                            ).encode("utf-8"),
                        )
                    )
                else:
                    conn.sendall(
                        encode_frame(
                            MSG_TOOL_CALL_RESPONSE,
                            json.dumps(
                                {
                                    "request_id": "spoofed closed connection",
                                    "http_status": 200,
                                    "headers": {},
                                    "body": "",
                                }
                            ).encode("utf-8"),
                        )
                    )
            except OSError:
                pass
            finally:
                conn.close()

    ts = threading.Thread(target=_serve_three, daemon=True)
    ts.start()
    try:
        client = AssemblerClient.connect(short_sock_path, timeout_secs=2.0)
        try:
            with pytest.raises(IpcError, match="http_status"):
                client.invoke(ToolCallRequest("r1", "https://x", "POST", tool="t"))
            assert client._needs_redial is True

            resp2 = client.invoke(ToolCallRequest("r2", "https://x", "POST", tool="t"))
            assert resp2.body == b"FRESH-CONN-2"
            assert conn_count == 2

            with pytest.raises(IpcError, match="request_id mismatch"):
                client.invoke(ToolCallRequest("r3", "https://x", "POST", tool="t"))
            assert conn_count == 3
        finally:
            client.close()
    finally:
        srv.close()
        ts.join(timeout=2)


def test_d2_direct_tool_call_request_to_wire_enforces_i2_headers_and_provider() -> None:
    for dup_headers in (
        {
            "X-Hawcx-Parent-Call-Record": "rec-1",
            "x-hawcx-parent-call-record": "rec-2",
        },
        {
            "X-Hawcx-Parent-Call-Record": "rec-1",
            "\uff38-hawcx-parent-call-record": "rec-2",
        },
    ):
        with pytest.raises(HawcxError, match="0x0058"):
            ToolCallRequest("r1", "https://x", "POST", headers=dup_headers, tool="t").to_wire()

    for crlf_or_bad_headers in (
        {"X-Evil": "val\r\nInjected: 1"},
        {"X-Bad\nName": "val"},
        {"X-Nul": "a\x00b"},
        {"Bad:Name": "val"},
        {"Bad Name": "val"},
        {"": "val"},
        {"   ": "val"},
    ):
        with pytest.raises(ValueError):
            ToolCallRequest(
                "r1", "https://x", "POST", headers=crlf_or_bad_headers, tool="t"
            ).to_wire()

    for non_str_headers in ({"X-Int": 123}, ["not-a-dict"]):
        with pytest.raises(TypeError):
            ToolCallRequest(
                "r1",
                "https://x",
                "POST",
                headers=non_str_headers,  # type: ignore[arg-type]
                tool="t",
            ).to_wire()

    for bad_provider in ("", " slack ", "slack\r\n"):
        with pytest.raises(ValueError):
            ToolCallRequest(
                "r1", "https://x", "POST", tool="t", provider=bad_provider
            ).to_wire()
    with pytest.raises(TypeError):
        ToolCallRequest(
            "r1",
            "https://x",
            "POST",
            tool="t",
            provider=True,  # type: ignore[arg-type]
        ).to_wire()

    # Verify direct AssemblerClient.invoke rejects bad headers BEFORE writing any IPC bytes.
    a, b = socket.socketpair()
    b.setblocking(False)
    try:
        cli = AssemblerClient(a)
        with pytest.raises(HawcxError, match="0x0058"):
            cli.invoke(
                ToolCallRequest(
                    "r1",
                    "https://x",
                    "POST",
                    headers={
                        "X-Hawcx-Parent-Call-Record": "rec-1",
                        "x-hawcx-parent-call-record": "rec-2",
                    },
                    tool="t",
                )
            )
        with pytest.raises(BlockingIOError):
            _ = b.recv(16)
    finally:
        a.close()
        b.close()

    # Positive control: single valid X-Hawcx-Parent-Call-Record + provider serializes cleanly.
    ok_wire = ToolCallRequest(
        "r-ok",
        "https://api.example.com/v1",
        "POST",
        headers={"X-Hawcx-Parent-Call-Record": "rec-valid", "X-Trace": "t1"},
        tool="slack.post",
        provider="slack",
    ).to_wire()
    assert ok_wire["headers"]["X-Hawcx-Parent-Call-Record"] == "rec-valid"
    assert ok_wire["provider"] == "slack"


