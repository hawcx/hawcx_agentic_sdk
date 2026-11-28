"""Unit, real-socket integration, and property tests for ``hawcx_crewai.HawcxTool`` (V-17).

Covers:
1. Top-level ``ToolCallRequest.provider`` routing (never inside ``constraints``) across
   ``HawcxTool``, ``make_search_tool``, ``make_document_tool``, and ``.for_user(...)``
   (including preserving ``_DocumentTool`` subclass behavior on ``.for_user(...)``).
2. Explicit ``acting_for_user=None`` on unprincipled calls verified via both
   ``create_autospec(HawcxAgent, instance=True)`` and real Unix-socket ``HawcxAgent`` +
   ``MockAssembler`` wire frames.
3. Fail-closed ``E_AUTHORITY_CLAIM`` (``0x0058``) rejection on untrusted LLM tool-call
   ``kwargs`` (``user_principal_id``, ``acting_for_user``, ``ciba_approved``,
   ``user_subject``, case-insensitive, via both ``_run`` and ``run``) with 0 IPC frames
   sent and zero untrusted principal echo/leakage, plus construction-time ``args_schema``
   rejection.
4. ``_DocumentTool._run`` path-traversal and URL-injection rejection (``0x002B``) on
   ``document_id`` with 0 IPC frames sent.
5. Bare-Python ``BaseTool`` fallback shim when ``crewai`` is not installed.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, create_autospec

import pytest
from hawcx_crewai import HawcxTool, make_document_tool, make_search_tool
from hawcx_haap import HawcxAgent, ToolCallResponse
from hawcx_haap.errors import HawcxError, RequestRejected
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import AliasChoices, AliasPath, BaseModel, Field


def _autospec_agent() -> MagicMock:
    """Strict signature-enforcing mock of ``HawcxAgent``."""
    agent: MagicMock = create_autospec(HawcxAgent, instance=True)
    agent.invoke.return_value = ToolCallResponse(
        request_id="req-test",
        http_status=200,
        headers={"Content-Type": "application/json"},
        body=b'{"result": "ok"}',
    )
    agent.invoke_for.return_value = ToolCallResponse(
        request_id="req-test",
        http_status=200,
        headers={"Content-Type": "application/json"},
        body=b'{"result": "ok"}',
    )
    return agent


class SearchArgs(BaseModel):
    query: str = Field(description="Search query.")


# ── Real Unix-socket multi-request MockAssembler for wire-level tests ────────

_PROTOCOL_VERSION = 1
_SDK_VERSION_MAJOR = 0
_SDK_VERSION_MINOR = 5
_SDK_VERSION_PATCH = 0
_ROLE_ASSEMBLER = 0x05
_MSG_HANDSHAKE = 0x00
_MSG_TOOL_CALL_REQUEST = 0x52
_MSG_TOOL_CALL_RESPONSE = 0x53


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(conn: socket.socket) -> tuple[int, bytes]:
    (msg_len,) = struct.unpack(">I", _recv_exact(conn, 4))
    body = _recv_exact(conn, msg_len)
    return body[0], bytes(body[1:])


def _write_frame(conn: socket.socket, msg_type: int, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", 1 + len(payload)) + bytes([msg_type]) + payload)


class _MultiSessionMockAssembler:
    """Serves real ``haap-ipc`` handshakes + ``0x52``/``0x53`` tool calls over AF_UNIX."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(8)
        self.requests: list[dict[str, Any]] = []
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            try:
                msg_type, _ = _read_frame(conn)
                if msg_type != _MSG_HANDSHAKE:
                    conn.close()
                    continue
                hs = struct.pack(
                    ">HHHHB",
                    _PROTOCOL_VERSION,
                    _SDK_VERSION_MAJOR,
                    _SDK_VERSION_MINOR,
                    _SDK_VERSION_PATCH,
                    _ROLE_ASSEMBLER,
                )
                _write_frame(conn, _MSG_HANDSHAKE, hs)
                try:
                    req_type, payload = _read_frame(conn)
                except (ConnectionError, OSError):
                    continue
                if req_type != _MSG_TOOL_CALL_REQUEST:
                    continue
                wire = json.loads(payload.decode("utf-8"))
                self.requests.append(wire)
                resp = {
                    "request_id": wire["request_id"],
                    "http_status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": base64.b64encode(b'{"result":"live-ok"}').decode("ascii"),
                }
                _write_frame(conn, _MSG_TOOL_CALL_RESPONSE, json.dumps(resp).encode("utf-8"))
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self) -> None:
        self._stop = True
        try:
            self.server.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


@pytest.fixture
def live_assembler() -> Iterator[_MultiSessionMockAssembler]:
    if sys.platform == "win32":
        pytest.skip("AF_UNIX socket integration skipped on Windows")
    # AF_UNIX sun_path is <=104 bytes on macOS; use /var/tmp or short parent if TMPDIR is deep.
    base_tmp = tempfile.gettempdir()
    if len(base_tmp) > 60 and os.path.isdir("/var/tmp"):
        base_tmp = "/var/tmp"
    parent = tempfile.mkdtemp(prefix="hx-cw-", dir=base_tmp)
    os.chmod(parent, 0o700)
    sock_path = os.path.join(parent, f"{uuid.uuid4().hex[:8]}.sock")
    asm = _MultiSessionMockAssembler(sock_path)
    asm.start()
    try:
        yield asm
    finally:
        asm.close()
        shutil.rmtree(parent, ignore_errors=True)


# ── Construction & schema hardening ──────────────────────────────────────────


def test_construct_basic() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="nim_search",
        description="Search via NIM.",
        hawcx_agent=agent,
        provider="nim",
        tool_id="nim-search-v1",
        endpoint="https://api.nim.nvidia.com/v1/search",
    )
    assert tool.name == "nim_search"
    assert tool.provider == "nim"
    assert tool.tool_id == "nim-search-v1"
    assert tool.endpoint == "https://api.nim.nvidia.com/v1/search"
    assert tool.method == "POST"
    assert tool.action == ["invoke"]
    assert tool.default_user_principal_id is None


def test_construct_rejects_missing_agent() -> None:
    with pytest.raises(TypeError, match="hawcx_agent"):
        HawcxTool(
            name="x",
            description="x",
            provider="nim",
            tool_id="x",
            endpoint="https://x",
        )


def test_construct_rejects_wrong_agent_type() -> None:
    with pytest.raises(TypeError, match="HawcxAgent"):
        HawcxTool(
            name="x",
            description="x",
            hawcx_agent="not-an-agent",
            provider="nim",
            tool_id="x",
            endpoint="https://x",
        )


@pytest.mark.parametrize(
    ("field_name", "bad_val"),
    [
        ("provider", ""),
        ("provider", "   "),
        ("provider", " nim"),
        ("provider", "nim\x00"),
        ("provider", "nim\r\n"),
        ("provider", "\u202enim"),
        ("provider", 123),
        ("provider", True),
        ("tool_id", ""),
        ("tool_id", "  "),
        ("tool_id", "tool\x00"),
        ("endpoint", ""),
        ("endpoint", "   "),
        ("endpoint", "https://x\r\n"),
        ("method", ""),
        ("method", "POST\x00"),
        ("resource", ""),
        ("resource", "res\x00"),
        ("default_user_principal_id", ""),
        ("default_user_principal_id", "   "),
        ("default_user_principal_id", " alice@example.com "),
        ("default_user_principal_id", "alice\x00@example.com"),
        ("default_user_principal_id", True),
        ("default_user_principal_id", 123),
    ],
)
def test_construct_rejects_invalid_routing_fields(field_name: str, bad_val: Any) -> None:
    agent = _autospec_agent()
    kwargs: dict[str, Any] = {
        "name": "x",
        "description": "x",
        "hawcx_agent": agent,
        "provider": "nim",
        "tool_id": "nim-v1",
        "endpoint": "https://api.example.com/v1",
    }
    kwargs[field_name] = bad_val
    with pytest.raises((ValueError, TypeError)):
        HawcxTool(**kwargs)


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "user_principal_id",
        "acting_for_user",
        "ciba_approved",
        "user_subject",
        "USER_PRINCIPAL_ID",
    ],
)
def test_construct_rejects_args_schema_exposing_authority_claim(forbidden_field: str) -> None:
    agent = _autospec_agent()
    bad_schema = type(
        "BadSchema",
        (BaseModel,),
        {"__annotations__": {"query": str, forbidden_field: str}},
    )
    with pytest.raises(ValueError, match=r"E_AUTHORITY_CLAIM.*0x0058"):
        HawcxTool(
            name="x",
            description="x",
            hawcx_agent=agent,
            provider="nim",
            tool_id="x",
            endpoint="https://x",
            args_schema=bad_schema,
        )


# ── Top-level provider & explicit acting_for_user=None (autospec) ────────────


def test_run_routes_provider_top_level_never_in_constraints() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="nim_search",
        description="Search via NIM.",
        hawcx_agent=agent,
        provider="nim",
        tool_id="nim-search-v1",
        endpoint="https://api.nim.nvidia.com/v1/search",
        action=["read"],
        args_schema=SearchArgs,
    )

    out = tool._run(query="agent auth")
    assert out == '{"result": "ok"}'

    agent.invoke.assert_called_once()
    kwargs = agent.invoke.call_args.kwargs
    assert kwargs["acting_for_user"] is None
    assert kwargs["provider"] == "nim"
    assert "provider" not in (kwargs.get("constraints") or {})
    assert kwargs["target_rs_url"] == "https://api.nim.nvidia.com/v1/search"
    assert kwargs["http_method"] == "POST"
    assert kwargs["tool"] == "nim-search-v1"
    assert kwargs["action"] == ["read"]
    assert kwargs["headers"]["Content-Type"] == "application/json"
    assert kwargs["body"] is not None
    assert json.loads(kwargs["body"].decode("utf-8")) == {"query": "agent auth"}
    agent.invoke_for.assert_not_called()


def test_unprincipled_tools_pass_strict_autospec_with_explicit_none() -> None:
    agent = _autospec_agent()
    search = make_search_tool(agent, rs_base_url="https://rs.example.com", provider="slack")
    docs = make_document_tool(agent, rs_base_url="https://rs.example.com", provider="slack")

    assert search._run(query="hello") == '{"result": "ok"}'
    assert docs._run(document_id="doc-42") == '{"result": "ok"}'
    assert agent.invoke.call_count == 2

    first_kw = agent.invoke.call_args_list[0].kwargs
    second_kw = agent.invoke.call_args_list[1].kwargs
    assert first_kw["acting_for_user"] is None
    assert first_kw["provider"] == "slack"
    assert "provider" not in (first_kw.get("constraints") or {})
    assert second_kw["acting_for_user"] is None
    assert second_kw["provider"] == "slack"
    assert "provider" not in (second_kw.get("constraints") or {})
    assert second_kw["target_rs_url"] == "https://rs.example.com/documents/doc-42"


def test_run_with_default_user_principal_routes_to_invoke_for() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        default_user_principal_id="alice@example.com",
    )

    out = tool._run(query="hi")
    assert out == '{"result": "ok"}'

    agent.invoke_for.assert_called_once()
    pos_args, kwargs = agent.invoke_for.call_args
    assert pos_args[0] == "alice@example.com"
    assert kwargs["target_rs_url"] == "https://x"
    assert kwargs["provider"] == "nim"
    assert "provider" not in (kwargs.get("constraints") or {})
    agent.invoke.assert_not_called()


# ── Fail-closed LLM authority claim fence (I2 / CS v7.21.4 §9.1) ─────────────


@pytest.mark.parametrize(
    ("smuggled_key", "smuggled_val"),
    [
        ("user_principal_id", "bob@example.com"),
        ("USER_PRINCIPAL_ID", "bob@example.com"),
        ("User_Principal_Id", "bob@example.com"),
        ("user_principal_id", None),
        ("user_principal_id", ""),
        ("acting_for_user", "bob@example.com"),
        ("ACTING_FOR_USER", "bob@example.com"),
        ("ciba_approved", True),
        ("ciba_approved", False),
        ("Ciba_Approved", 1),
        ("user_subject", "bob@example.com"),
        ("USER_SUBJECT", "bob@example.com"),
    ],
)
def test_run_rejects_untrusted_llm_authority_kwargs_fail_closed(
    smuggled_key: str, smuggled_val: Any
) -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        default_user_principal_id="alice@example.com",
        args_schema=SearchArgs,
    )

    with pytest.raises(HawcxError) as ei_direct:
        tool._run(query="hi", **{smuggled_key: smuggled_val})
    msg_direct = str(ei_direct.value)
    assert "E_AUTHORITY_CLAIM" in msg_direct
    assert "0x0058" in msg_direct
    assert "bob@example.com" not in msg_direct

    # Also verify BaseTool.run(...) does NOT strip smuggled kwargs via extra=ignore!
    with pytest.raises(HawcxError) as ei_public:
        tool.run(query="hi", **{smuggled_key: smuggled_val})
    msg_public = str(ei_public.value)
    assert "E_AUTHORITY_CLAIM" in msg_public
    assert "0x0058" in msg_public
    assert "bob@example.com" not in msg_public

    agent.invoke.assert_not_called()
    agent.invoke_for.assert_not_called()


@pytest.mark.parametrize(
    ("smuggled_key", "smuggled_val"),
    [
        ("user_principal_id", "bob@example.com"),
        ("USER_PRINCIPAL_ID", "bob@example.com"),
        ("user_principal_id", None),
        ("user_principal_id", ""),
        ("acting_for_user", "bob@example.com"),
        ("ciba_approved", True),
        ("user_subject", "bob@example.com"),
    ],
)
def test_make_document_tool_rejects_untrusted_llm_authority_kwargs(
    smuggled_key: str, smuggled_val: Any
) -> None:
    agent = _autospec_agent()
    doc_tool = make_document_tool(
        agent,
        rs_base_url="https://rs.example.com",
        default_user_principal_id="alice@example.com",
    )

    with pytest.raises(HawcxError) as ei_direct:
        doc_tool._run(document_id="doc-42", **{smuggled_key: smuggled_val})
    msg = str(ei_direct.value)
    assert "E_AUTHORITY_CLAIM" in msg
    assert "0x0058" in msg
    assert "bob@example.com" not in msg

    with pytest.raises(HawcxError) as ei_public:
        doc_tool.run(document_id="doc-42", **{smuggled_key: smuggled_val})
    assert "0x0058" in str(ei_public.value)

    agent.invoke.assert_not_called()
    agent.invoke_for.assert_not_called()


# ── _DocumentTool path-traversal / URL-injection guard (I1 / I4) ─────────────


@pytest.mark.parametrize(
    "bad_doc_id",
    [
        "",
        "   ",
        " doc ",
        ".",
        "..",
        "../admin",
        "a..b",
        "a/b",
        "a\\b",
        "doc?x=1",
        "doc#frag",
        "doc%2f..",
        "doc\x00id",
        "doc\r\nid",
        "\u202edoc",
        None,
        True,
        123,
    ],
)
def test_make_document_tool_rejects_path_traversal_and_url_injection(bad_doc_id: Any) -> None:
    agent = _autospec_agent()
    doc_tool = make_document_tool(agent, rs_base_url="https://rs.example.com")
    with pytest.raises(HawcxError, match="0x002B"):
        doc_tool._run(document_id=bad_doc_id)
    agent.invoke.assert_not_called()
    agent.invoke_for.assert_not_called()


# ── Body, error mapping, for_user & factories ────────────────────────────────


def test_run_empty_kwargs_no_body() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    tool._run()

    kwargs = agent.invoke.call_args.kwargs
    assert kwargs["body"] is None
    assert "Content-Type" not in kwargs["headers"]


def test_run_request_rejected_returns_string() -> None:
    agent = _autospec_agent()
    agent.invoke.side_effect = RequestRejected(
        request_id="req-1", reason="0x002D ToolCredentialNotBound"
    )
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    out = tool._run(query="x")
    assert "hawcx rejected" in out
    assert "0x002D ToolCredentialNotBound" in out


def test_run_hawcx_error_returns_string() -> None:
    agent = _autospec_agent()
    agent.invoke.side_effect = HawcxError("agent already closed")
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    out = tool._run(query="x")
    assert "hawcx error" in out


def test_run_non_2xx_returns_diagnostic_string() -> None:
    agent = _autospec_agent()
    agent.invoke.return_value = ToolCallResponse(
        request_id="req-1",
        http_status=503,
        headers={},
        body=b"upstream busy",
    )
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    out = tool._run(query="x")
    assert "hawcx HTTP 503" in out
    assert "upstream busy" in out


def test_for_user_returns_sibling_tool_with_pinned_principal() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        args_schema=SearchArgs,
    )

    alice_tool = tool.for_user("alice@example.com")
    assert alice_tool.default_user_principal_id == "alice@example.com"
    assert tool.default_user_principal_id is None
    assert alice_tool.args_schema is SearchArgs

    alice_tool._run(query="hi")
    agent.invoke_for.assert_called_once()
    assert agent.invoke_for.call_args.args[0] == "alice@example.com"
    assert agent.invoke_for.call_args.kwargs["provider"] == "nim"


@pytest.mark.parametrize(
    "bad_principal",
    ["", "   ", " alice@example.com ", "alice\x00", True, False, 123, None],
)
def test_for_user_rejects_invalid_principal(bad_principal: Any) -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )
    with pytest.raises((ValueError, TypeError)):
        tool.for_user(bad_principal)


def test_make_search_tool_schema_and_host_principal_contract() -> None:
    agent = _autospec_agent()
    tool = make_search_tool(
        agent,
        rs_base_url="https://rs.example.com",
        default_user_principal_id="alice@example.com",
    )
    assert tool.name == "hawcx_search"
    assert tool.endpoint == "https://rs.example.com/search"
    assert set(tool.args_schema.model_fields.keys()) == {"query"}
    assert "user_principal_id" not in tool.description

    tool.run(query="policy retention")
    agent.invoke_for.assert_called_once()
    assert agent.invoke_for.call_args.args[0] == "alice@example.com"
    assert agent.invoke_for.call_args.kwargs["provider"] == "generic-bearer"
    assert "provider" not in (agent.invoke_for.call_args.kwargs.get("constraints") or {})


def test_make_document_tool_for_user_preserves_document_subclass_and_wire_contract() -> None:
    agent = _autospec_agent()
    base_doc_tool = make_document_tool(agent, rs_base_url="https://rs.example.com")
    assert base_doc_tool.name == "hawcx_get_document"
    assert set(base_doc_tool.args_schema.model_fields.keys()) == {"document_id"}
    assert "user_principal_id" not in base_doc_tool.description

    alice_doc_tool = base_doc_tool.for_user("alice@example.com")
    assert type(alice_doc_tool) is type(base_doc_tool)
    assert alice_doc_tool.default_user_principal_id == "alice@example.com"
    assert base_doc_tool.default_user_principal_id is None

    out = alice_doc_tool.run(document_id="doc-42")
    assert out == '{"result": "ok"}'
    agent.invoke_for.assert_called_once()
    assert agent.invoke_for.call_args.args[0] == "alice@example.com"
    kwargs = agent.invoke_for.call_args.kwargs
    assert kwargs["target_rs_url"] == "https://rs.example.com/documents/doc-42"
    assert kwargs["http_method"] == "GET"
    assert kwargs["resource"] == "doc-42"
    assert kwargs["provider"] == "generic-bearer"
    assert "provider" not in (kwargs.get("constraints") or {})


def test_make_document_tool_404_returns_friendly_string() -> None:
    agent = _autospec_agent()
    agent.invoke.return_value = ToolCallResponse(
        request_id="req-1", http_status=404, headers={}, body=b""
    )
    tool = make_document_tool(agent)
    out = tool._run(document_id="missing")
    assert "not found" in out


def test_args_schema_attached() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        args_schema=SearchArgs,
    )
    assert tool.args_schema is SearchArgs


def test_run_single_invoke_per_call() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    tool._run(query="hi")
    tool._run(query="bye")
    assert agent.invoke.call_count == 2


def test_prototype_keys_and_benign_subject_in_kwargs_serialize_safely() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )
    payload = {
        "query": "hi",
        "top_k": 5,
        "subject": "Quarterly report",
        "__proto__": "safe",
        "constructor": "safe",
        "hasOwnProperty": "safe",
    }
    tool._run(**payload)
    kwargs = agent.invoke.call_args.kwargs
    assert kwargs["tool_arguments"] == payload
    assert json.loads(kwargs["body"].decode("utf-8")) == payload


# ── Real Unix-socket integration tests (HawcxAgent + MockAssembler) ──────────


def test_real_socket_hawcx_tool_unprincipled_and_for_user_wire_contract(
    live_assembler: _MultiSessionMockAssembler,
) -> None:
    with HawcxAgent.connect(
        live_assembler.socket_path,
        principal_allowlist=["alice@example.com"],
    ) as agent:
        base_tool = HawcxTool(
            name="nim_search",
            description="Search via NIM.",
            hawcx_agent=agent,
            provider="nim",
            tool_id="nim-search-v1",
            endpoint="https://api.nim.nvidia.com/v1/search",
            action=["read"],
            args_schema=SearchArgs,
        )

        # 1. Negative control first: untrusted LLM authority injection sends 0 IPC frames.
        with pytest.raises(HawcxError, match="0x0058"):
            base_tool._run(query="secret", user_principal_id="alice@example.com")
        assert len(live_assembler.requests) == 0

        # 2. Unprincipled call: top-level provider, empty constraints, no acting_for_user.
        res1 = base_tool._run(query="public-topic")
        assert res1 == '{"result":"live-ok"}'
        assert len(live_assembler.requests) == 1
        wire1 = live_assembler.requests[0]
        assert wire1["provider"] == "nim"
        assert wire1["constraints"] == {}
        assert "acting_for_user" not in wire1
        assert wire1["tool"] == "nim-search-v1"

        # 3. Host-bound .for_user() call: top-level provider + acting_for_user.
        alice_tool = base_tool.for_user("alice@example.com")
        res2 = alice_tool.run(query="alice-topic")
        assert res2 == '{"result":"live-ok"}'
        assert len(live_assembler.requests) == 2
        wire2 = live_assembler.requests[1]
        assert wire2["provider"] == "nim"
        assert wire2["constraints"] == {}
        assert wire2["acting_for_user"] == "alice@example.com"

        # 4. Document tool .for_user() + traversal negative control.
        doc_tool = make_document_tool(
            agent,
            rs_base_url="https://rs.example.com",
            provider="generic-bearer",
        ).for_user("alice@example.com")
        with pytest.raises(HawcxError, match="0x002B"):
            doc_tool._run(document_id="../secret")
        assert len(live_assembler.requests) == 2

        res3 = doc_tool.run(document_id="doc-99")
        assert res3 == '{"result":"live-ok"}'
        assert len(live_assembler.requests) == 3
        wire3 = live_assembler.requests[2]
        assert wire3["provider"] == "generic-bearer"
        assert wire3["constraints"] == {}
        assert wire3["acting_for_user"] == "alice@example.com"
        assert wire3["target_rs_url"] == "https://rs.example.com/documents/doc-99"

        # 5. Out-of-allowlist host principal returns redacted error with 0 new IPC frames.
        mallory_tool = base_tool.for_user("mallory@example.com")
        res4 = mallory_tool._run(query="mallory-topic")
        assert res4.startswith("[hawcx error:")
        assert "mallory@example.com" not in res4
        assert "fingerprint=" in res4
        assert len(live_assembler.requests) == 3


# ── Seeded Hypothesis property test (derandomized) ───────────────────────────

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10_000, max_value=10_000),
    st.text(max_size=40),
    st.lists(st.text(max_size=10), max_size=3),
)


@settings(derandomize=True, max_examples=100)
@given(
    base_key=st.sampled_from(
        ["user_principal_id", "acting_for_user", "ciba_approved", "user_subject"]
    ),
    upper_mask=st.lists(st.booleans(), min_size=20, max_size=20),
    smuggled_val=_JSON_SCALARS,
    extra_args=st.dictionaries(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_"
            ),
            min_size=1,
            max_size=16,
        ).filter(
            lambda k: k.lower()
            not in {
                "user_principal_id",
                "acting_for_user",
                "ciba_approved",
                "user_subject",
                "document_id",
            }
        ),
        _JSON_SCALARS,
        max_size=4,
    ),
)
def test_prop_llm_authority_kwargs_always_rejected_zero_ipc(
    base_key: str,
    upper_mask: list[bool],
    smuggled_val: Any,
    extra_args: dict[str, Any],
) -> None:
    cased_key = "".join(
        ch.upper() if upper_mask[i % len(upper_mask)] else ch.lower()
        for i, ch in enumerate(base_key)
    )
    agent = _autospec_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        default_user_principal_id="alice@example.com",
    )
    doc_tool = make_document_tool(
        agent,
        rs_base_url="https://rs.example.com",
        default_user_principal_id="alice@example.com",
    )

    call_kwargs = dict(extra_args)
    call_kwargs[cased_key] = smuggled_val

    with pytest.raises(HawcxError, match=r"E_AUTHORITY_CLAIM.*0x0058"):
        tool._run(**call_kwargs)
    with pytest.raises(HawcxError, match=r"E_AUTHORITY_CLAIM.*0x0058"):
        doc_tool._run(document_id="doc-1", **call_kwargs)

    assert agent.invoke.call_count == 0
    assert agent.invoke_for.call_count == 0


# ── Bare-Python BaseTool fallback test (simulates crewai uninstalled) ────────


def test_bare_fallback_without_crewai_installed() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(repo_root / "python-crewai" / "src"), str(repo_root / "python" / "src")]
    )
    code = """
import sys
from unittest.mock import create_autospec
sys.modules["crewai"] = None
sys.modules["crewai.tools"] = None

from hawcx_haap import HawcxAgent, ToolCallResponse
from hawcx_haap.errors import HawcxError
from hawcx_crewai import HawcxTool, make_document_tool, make_search_tool

agent = create_autospec(HawcxAgent, instance=True)
agent.invoke.return_value = ToolCallResponse(
    request_id="r1", http_status=200, headers={}, body=b"fallback-ok"
)
agent.invoke_for.return_value = ToolCallResponse(
    request_id="r2", http_status=200, headers={}, body=b"fallback-user-ok"
)

s = make_search_tool(agent, rs_base_url="https://rs.example.com")
assert s.run(query="hello") == "fallback-ok"
assert s.run({"query": "pos-hello"}) == "fallback-ok"
assert s.run(tool_input={"query": "kw-hello"}) == "fallback-ok"
d = make_document_tool(agent, rs_base_url="https://rs.example.com").for_user("alice@example.com")
assert d.run(document_id="doc-7") == "fallback-user-ok"
assert d.run({"document_id": "doc-8"}) == "fallback-user-ok"
for bad_call in (
    lambda: s.run(query="hello", user_principal_id="bob@example.com"),
    lambda: s.run({"query": "hello", "user_principal_id": "bob@example.com"}),
    lambda: s.run(tool_input={"query": "hello", "user_principal_id": "bob@example.com"}),
    lambda: s.run('{"query": "hello", "ciba_approved": true}'),
):
    try:
        bad_call()
    except HawcxError as exc:
        assert "0x0058" in str(exc)
    else:
        raise AssertionError("expected HawcxError on smuggled authority claim")
"""
    proc = subprocess.run(
        [sys.executable, "-B", "-c", code],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, f"stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}"


# ── Iteration-2 Challenger Remediation Tests (C1 & C2) ───────────────────────


class _ConcurrentPerUserMockAssembler:
    """Multi-threaded AF_UNIX Assembler serving 1 request per connection with staggered delay."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(64)
        self._stop = False
        self._workers: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> None:
        self._accept_thread.start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            msg_type, _ = _read_frame(conn)
            if msg_type != _MSG_HANDSHAKE:
                return
            hs = struct.pack(
                ">HHHHB",
                _PROTOCOL_VERSION,
                _SDK_VERSION_MAJOR,
                _SDK_VERSION_MINOR,
                _SDK_VERSION_PATCH,
                _ROLE_ASSEMBLER,
            )
            _write_frame(conn, _MSG_HANDSHAKE, hs)
            req_type, payload = _read_frame(conn)
            if req_type != _MSG_TOOL_CALL_REQUEST:
                return
            wire = json.loads(payload.decode("utf-8"))
            principal = wire.get("acting_for_user") or "unprincipled"
            args_obj = wire.get("tool_arguments") or {}
            query_tag = args_obj.get("query", "")
            # Stagger delays so overlapping threads race on _sock / _reconnect if unlocked.
            delay = 0.006 if principal.startswith("alice") else 0.001
            time.sleep(delay)
            secret_body = f"SECRET-FOR-{principal}:{query_tag}".encode()
            resp = {
                "request_id": wire["request_id"],
                "http_status": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": base64.b64encode(secret_body).decode("ascii"),
            }
            _write_frame(conn, _MSG_TOOL_CALL_RESPONSE, json.dumps(resp).encode("utf-8"))
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            worker = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            self._workers.append(worker)
            worker.start()

    def close(self) -> None:
        self._stop = True
        try:
            self.server.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2)
        for w in self._workers:
            w.join(timeout=1)


def test_c1_concurrent_for_user_shared_agent_zero_cross_tenant_swap_or_ebadf() -> None:
    if sys.platform == "win32":
        pytest.skip("AF_UNIX socket concurrency test skipped on Windows")
    base_tmp = tempfile.gettempdir()
    if len(base_tmp) > 60 and os.path.isdir("/var/tmp"):
        base_tmp = "/var/tmp"
    parent = tempfile.mkdtemp(prefix="hx-c1-", dir=base_tmp)
    os.chmod(parent, 0o700)
    sock_path = os.path.join(parent, f"{uuid.uuid4().hex[:8]}.sock")
    asm = _ConcurrentPerUserMockAssembler(sock_path)
    asm.start()
    try:
        with HawcxAgent.connect(
            sock_path,
            principal_allowlist=["alice@example.com", "bob@example.com"],
        ) as shared_agent:
            base_tool = make_search_tool(
                shared_agent,
                rs_base_url="https://rs.example.com",
                provider="nim",
            )
            alice_tool = base_tool.for_user("alice@example.com")
            bob_tool = base_tool.for_user("bob@example.com")

            total_threads = 36
            barrier = threading.Barrier(total_threads)
            results: list[tuple[str, str, str]] = []
            unhandled: list[BaseException] = []
            results_lock = threading.Lock()

            def worker(idx: int) -> None:
                is_alice = idx % 2 == 0
                expected_user = "alice@example.com" if is_alice else "bob@example.com"
                tool_ref = alice_tool if is_alice else bob_tool
                q = f"item-{idx}"
                try:
                    barrier.wait(timeout=5.0)
                    out = tool_ref.run(query=q)
                    with results_lock:
                        results.append((expected_user, q, out))
                except BaseException as exc:  # noqa: BLE001
                    with results_lock:
                        unhandled.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(total_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15.0)

            assert unhandled == []
            assert len(results) == total_threads
            for expected_user, q, out in results:
                assert out == f"SECRET-FOR-{expected_user}:{q}"
    finally:
        asm.close()
        shutil.rmtree(parent, ignore_errors=True)


def test_c2_args_schema_rejects_field_aliases_and_nested_schema_defs() -> None:
    agent = _autospec_agent()

    class BadAlias(BaseModel):
        query: str
        uid: str = Field(alias="user_principal_id")

    class BadSerializationAlias(BaseModel):
        query: str
        uid: str = Field(serialization_alias="acting_for_user")

    class BadValidationChoices(BaseModel):
        query: str
        uid: str = Field(validation_alias=AliasChoices("safe_id", "user_principal_id"))

    class BadValidationPath(BaseModel):
        query: str
        flag: bool = Field(validation_alias=AliasPath("meta", "ciba_approved"))

    class BadNfkcAlias(BaseModel):
        query: str
        uid: str = Field(alias="\U0001d5ce\U0001d5cc\U0001d5be\U0001d5cb_principal_id")

    class NestedForbidden(BaseModel):
        subj: str = Field(alias="user_subject")

    class OuterWithNestedForbidden(BaseModel):
        query: str
        nested: NestedForbidden

    for bad_schema in (
        BadAlias,
        BadSerializationAlias,
        BadValidationChoices,
        BadValidationPath,
        BadNfkcAlias,
        OuterWithNestedForbidden,
    ):
        with pytest.raises(ValueError, match=r"E_AUTHORITY_CLAIM.*0x0058"):
            HawcxTool(
                name="x",
                description="x",
                hawcx_agent=agent,
                provider="nim",
                tool_id="x",
                endpoint="https://x",
                args_schema=bad_schema,
            )


def test_c2_run_screens_positional_and_keyword_tool_input_and_unpacks_valid_dicts() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="search",
        description="Search",
        hawcx_agent=agent,
        provider="nim",
        tool_id="nim-v1",
        endpoint="https://rs.example.com/search",
        args_schema=SearchArgs,
        default_user_principal_id="alice@example.com",
    )
    free_tool = HawcxTool(
        name="free_search",
        description="Free Search",
        hawcx_agent=agent,
        provider="nim",
        tool_id="nim-v1",
        endpoint="https://rs.example.com/search",
        default_user_principal_id="alice@example.com",
    )
    doc_tool = make_document_tool(
        agent,
        rs_base_url="https://rs.example.com",
        default_user_principal_id="alice@example.com",
    )

    # 1. Negative controls first: every positional/kwarg/JSON tool_input smuggle raises 0x0058.
    smuggle_calls = (
        lambda: tool.run({"query": "x", "user_principal_id": "bob@example.com"}),
        lambda: tool.run(tool_input={"query": "x", "user_principal_id": "bob@example.com"}),
        lambda: free_tool.run(tool_input={"query": "x", "user_principal_id": "bob@example.com"}),
        lambda: tool.run('{"query": "x", "user_principal_id": "bob@example.com"}'),
        lambda: tool.run(tool_input='{"query": "x", "ciba_approved": true}'),
        lambda: doc_tool.run("doc-42", user_principal_id="bob@example.com"),
        lambda: doc_tool.run({"document_id": "doc-42", "acting_for_user": "bob@example.com"}),
    )
    for call in smuggle_calls:
        with pytest.raises(HawcxError) as ei:
            call()
        err_text = str(ei.value)
        assert "E_AUTHORITY_CLAIM" in err_text
        assert "0x0058" in err_text
        assert "bob@example.com" not in err_text

    assert agent.invoke.call_count == 0
    assert agent.invoke_for.call_count == 0

    # 2. Positive controls: valid positional dict, tool_input dict, and JSON object unpack cleanly.
    assert tool.run({"query": "pos-dict"}) == '{"result": "ok"}'
    assert agent.invoke_for.call_args.kwargs["tool_arguments"] == {"query": "pos-dict"}

    assert tool.run(tool_input={"query": "kw-dict"}) == '{"result": "ok"}'
    assert agent.invoke_for.call_args.kwargs["tool_arguments"] == {"query": "kw-dict"}

    assert tool.run('{"query": "json-pos"}') == '{"result": "ok"}'
    assert agent.invoke_for.call_args.kwargs["tool_arguments"] == {"query": "json-pos"}

    assert free_tool.run(tool_input={"query": "free-kw"}) == '{"result": "ok"}'
    assert agent.invoke_for.call_args.kwargs["tool_arguments"] == {"query": "free-kw"}

    assert doc_tool.run({"document_id": "doc-42"}) == '{"result": "ok"}'
    assert doc_tool.run("doc-43") == '{"result": "ok"}'
    assert agent.invoke_for.call_count == 6


@pytest.mark.skipif(
    not hasattr(HawcxTool.__mro__[1], "to_structured_tool"),
    reason="CrewStructuredTool requires crewai installed",
)
def test_c2_crew_structured_tool_invoke_rejects_smuggled_authority_claims() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="search",
        description="Search",
        hawcx_agent=agent,
        provider="nim",
        tool_id="nim-v1",
        endpoint="https://rs.example.com/search",
        args_schema=SearchArgs,
        default_user_principal_id="alice@example.com",
    )
    st_tool = tool.to_structured_tool()
    with pytest.raises(HawcxError, match="0x0058"):
        st_tool.invoke({"query": "x", "user_principal_id": "bob@example.com"})
    with pytest.raises(HawcxError, match="0x0058"):
        st_tool.invoke('{"query": "x", "ciba_approved": true}')
    assert agent.invoke_for.call_count == 0
    assert st_tool.invoke({"query": "st-ok"}) == '{"result": "ok"}'
    assert agent.invoke_for.call_count == 1


def test_c2_nested_whitespace_zero_width_nfkc_and_depth_authority_bypasses_rejected() -> None:
    agent = _autospec_agent()
    tool = HawcxTool(
        name="t2",
        description="d",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    hostile_kwargs_list: list[dict[str, Any]] = [
        {"query": "x", "meta": {"user_principal_id": "bob@example.com", "ciba_approved": True}},
        {"query": "x", "items": [{"ok": 1}, {"user_subject": "bob@example.com"}]},
        {" user_principal_id ": "bob@example.com", "query": "x"},
        {"user\u200b_principal_id": "bob@example.com", "query": "x"},
        {"user\u202e_principal_id": "bob@example.com", "query": "x"},
        {"\U0001d5ce\U0001d5cc\U0001d5be\U0001d5cb_principal_id": "bob@example.com", "query": "x"},
        {"\uff55\uff53\uff45\uff52_principal_id": "bob@example.com", "query": "x"},
    ]
    for bad_kw in hostile_kwargs_list:
        with pytest.raises(HawcxError) as ei:
            tool.run(**bad_kw)
        msg = str(ei.value)
        assert "E_AUTHORITY_CLAIM" in msg
        assert "0x0058" in msg
        assert "bob@example.com" not in msg

    # Excessive nesting depth (>64) fails closed with 0x0058.
    deep: dict[str, Any] = {"leaf": "safe"}
    for _ in range(70):
        deep = {"wrap": deep}
    with pytest.raises(HawcxError, match="0x0058"):
        tool.run(payload=deep)

    # Cyclic container reference fails closed with 0x0058 instead of RecursionError.
    cyclic: dict[str, Any] = {}
    cyclic["self"] = cyclic
    with pytest.raises(HawcxError, match="0x0058"):
        tool.run(payload=cyclic)

    assert agent.invoke.call_count == 0
    assert agent.invoke_for.call_count == 0


def test_c2_construct_and_for_user_validate_headers_i2() -> None:
    agent = _autospec_agent()

    for bad_headers in (
        {"X-Bad": "val\r\nEvil: 1"},
        {"X-Bad\nName": "val"},
        {"X-Nul": "a\x00b"},
        {"": "val"},
        {"   ": "val"},
    ):
        with pytest.raises(ValueError):
            HawcxTool(
                name="x",
                description="x",
                hawcx_agent=agent,
                provider="nim",
                tool_id="x",
                endpoint="https://x",
                headers=bad_headers,
            )

    with pytest.raises((TypeError, ValueError)):
        HawcxTool(
            name="x",
            description="x",
            hawcx_agent=agent,
            provider="nim",
            tool_id="x",
            endpoint="https://x",
            headers={"X-Int": 123},  # type: ignore[dict-item]
        )

    with pytest.raises(HawcxError, match="0x0058"):
        HawcxTool(
            name="x",
            description="x",
            hawcx_agent=agent,
            provider="nim",
            tool_id="x",
            endpoint="https://x",
            headers={
                "X-Hawcx-Parent-Call-Record": "rec-1",
                "x-hawcx-parent-call-record": "rec-2",
            },
        )

    valid_tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        headers={"X-Custom": "clean"},
    )
    valid_tool.headers["X-Mutated"] = "bad\r\nheader"
    with pytest.raises(ValueError):
        valid_tool.for_user("alice@example.com")

