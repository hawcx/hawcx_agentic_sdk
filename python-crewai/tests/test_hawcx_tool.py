"""Unit tests for ``hawcx_crewai.HawcxTool``.

Strategy: mock the :class:`hawcx_haap.HawcxAgent` directly (the parent
``hawcx-haap`` package already covers IPC-level behaviour via its own
mock Assembler in ``python/tests/conftest.py``). These tests assert the
*HawcxTool → HawcxAgent* boundary contract: that the right wire fields
are routed onto the right ``invoke`` / ``invoke_for`` kwargs.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from hawcx_haap import HawcxAgent, ToolCallResponse
from hawcx_haap.errors import HawcxError, RequestRejected
from pydantic import BaseModel, Field

from hawcx_crewai import HawcxTool


def _mock_agent() -> MagicMock:
    agent = MagicMock(spec=HawcxAgent)
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


# ── Construction ─────────────────────────────────────────────────────────────


def test_construct_basic() -> None:
    agent = _mock_agent()
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


# ── _run forwards correctly ──────────────────────────────────────────────────


def test_run_invokes_agent_with_correct_wire_fields() -> None:
    agent = _mock_agent()
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
    assert kwargs["target_rs_url"] == "https://api.nim.nvidia.com/v1/search"
    assert kwargs["http_method"] == "POST"
    assert kwargs["tool"] == "nim-search-v1"
    assert kwargs["action"] == ["read"]
    assert kwargs["constraints"] == {"provider": "nim"}
    assert kwargs["headers"]["Content-Type"] == "application/json"

    # Body is JSON-encoded kwargs
    assert kwargs["body"] is not None
    body = json.loads(kwargs["body"].decode("utf-8"))
    assert body == {"query": "agent auth"}

    # invoke_for not called (no principal)
    agent.invoke_for.assert_not_called()


def test_run_with_default_user_principal_routes_to_invoke_for() -> None:
    agent = _mock_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        default_user_principal_id="alice@example.com",
    )

    tool._run(query="hi")

    agent.invoke_for.assert_called_once()
    pos_args, kwargs = agent.invoke_for.call_args
    assert pos_args[0] == "alice@example.com"
    assert kwargs["target_rs_url"] == "https://x"
    assert kwargs["constraints"] == {"provider": "nim"}
    agent.invoke.assert_not_called()


def test_run_per_call_principal_overrides_default() -> None:
    agent = _mock_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
        default_user_principal_id="alice@example.com",
    )

    tool._run(query="hi", user_principal_id="bob@example.com")

    agent.invoke_for.assert_called_once()
    pos_args, _ = agent.invoke_for.call_args
    assert pos_args[0] == "bob@example.com"


def test_run_empty_kwargs_no_body() -> None:
    agent = _mock_agent()
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
    # Content-Type should NOT be auto-added when there's no body
    assert "Content-Type" not in kwargs["headers"]


# ── Error mapping ────────────────────────────────────────────────────────────


def test_run_request_rejected_returns_string() -> None:
    agent = _mock_agent()
    agent.invoke.side_effect = RequestRejected(
        request_id="req-1", reason="ToolCredentialNotBound"
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
    assert "ToolCredentialNotBound" in out


def test_run_hawcx_error_returns_string() -> None:
    agent = _mock_agent()
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
    agent = _mock_agent()
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


# ── for_user sugar ───────────────────────────────────────────────────────────


def test_for_user_returns_sibling_tool_with_pinned_principal() -> None:
    agent = _mock_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    alice_tool = tool.for_user("alice@example.com")
    assert alice_tool.default_user_principal_id == "alice@example.com"
    assert tool.default_user_principal_id is None  # original unchanged

    alice_tool._run(query="hi")
    agent.invoke_for.assert_called_once()
    assert agent.invoke_for.call_args.args[0] == "alice@example.com"


# ── Backward-compat factories ────────────────────────────────────────────────


def test_make_search_tool_smoke() -> None:
    from hawcx_crewai import make_search_tool

    agent = _mock_agent()
    tool = make_search_tool(agent, rs_base_url="https://rs.example.com")
    assert tool.name == "hawcx_search"
    assert tool.endpoint == "https://rs.example.com/search"


def test_make_document_tool_smoke() -> None:
    from hawcx_crewai import make_document_tool

    agent = _mock_agent()
    tool = make_document_tool(agent, rs_base_url="https://rs.example.com")
    assert tool.name == "hawcx_get_document"

    # _run should compose the per-call URL from the document_id arg.
    tool._run(document_id="doc-42")
    kwargs = agent.invoke.call_args.kwargs
    assert kwargs["target_rs_url"] == "https://rs.example.com/documents/doc-42"


def test_make_document_tool_404_returns_friendly_string() -> None:
    from hawcx_crewai import make_document_tool

    agent = _mock_agent()
    agent.invoke.return_value = ToolCallResponse(
        request_id="req-1", http_status=404, headers={}, body=b""
    )
    tool = make_document_tool(agent)
    out = tool._run(document_id="missing")
    assert "not found" in out


# ── Args-schema integration with CrewAI (light) ──────────────────────────────


def test_args_schema_attached() -> None:
    """CrewAI uses args_schema for argument validation; ensure it round-trips."""
    agent = _mock_agent()
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


# ── Sanity: HawcxAgent.invoke isn't called twice on success ──────────────────


def test_run_single_invoke_per_call() -> None:
    agent = _mock_agent()
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


def test_run_kwargs_flow_to_tool_arguments(*_: Any) -> None:
    agent = _mock_agent()
    tool = HawcxTool(
        name="x",
        description="x",
        hawcx_agent=agent,
        provider="nim",
        tool_id="x",
        endpoint="https://x",
    )

    tool._run(query="hi", top_k=5)
    kwargs = agent.invoke.call_args.kwargs
    assert kwargs["tool_arguments"] == {"query": "hi", "top_k": 5}
