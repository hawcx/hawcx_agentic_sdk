"""Tests for HawcxAgent against a mock Assembler."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from hawcx_haap import HawcxAgent, TokenTransport
from hawcx_haap.agent import default_endpoint_for
from hawcx_haap.errors import RequestRejected


def test_default_endpoint_for_unix(monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        pytest.skip("Unix path convention test")
    endpoint = default_endpoint_for("research-u1", ipc_dir=Path("/var/run/haap"))
    assert endpoint == "/var/run/haap/research-u1/agent-assembler-0.sock"


def test_default_endpoint_for_unix_custom_index() -> None:
    if sys.platform == "win32":
        pytest.skip("Unix path convention test")
    endpoint = default_endpoint_for(
        "research-u1", index=3, ipc_dir=Path("/var/run/haap")
    )
    assert endpoint == "/var/run/haap/research-u1/agent-assembler-3.sock"


def test_default_endpoint_for_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    endpoint = default_endpoint_for("research-u1", index=2)
    assert endpoint == r"\\.\pipe\haap-research-u1-agent-assembler-2"


def test_agent_invoke_echo(mock_assembler, mock_assembler_endpoint: str) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        resp = agent.invoke(
            target_rs_url="https://api.example.com/echo",
            http_method="POST",
            headers={"Content-Type": "application/json"},
            tool="echo",
            action=["query"],
            body=b"ping",
            transport=TokenTransport.HTTP_HEADER,
        )
    assert resp.http_status == 200
    assert resp.body == b"ping"
    assert mock_assembler.received_request is not None
    assert mock_assembler.received_request["tool"] == "echo"
    assert mock_assembler.received_request["transport"] == "http_header"
    assert mock_assembler.received_request["headers"]["Content-Type"] == "application/json"


def test_agent_invoke_rejection(mock_assembler, mock_assembler_endpoint: str) -> None:
    mock_assembler.reject_with("intent verification failed")
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        with pytest.raises(RequestRejected) as ei:
            agent.invoke(
                target_rs_url="https://api.example.com/forbidden",
                tool="forbidden",
            )
    assert "intent verification" in ei.value.reason


def test_agent_invoke_with_request_id_override(
    mock_assembler, mock_assembler_endpoint: str
) -> None:
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        resp = agent.invoke(
            target_rs_url="https://api.example.com/",
            tool="x",
            request_id="custom-req-42",
        )
    assert resp.request_id == "custom-req-42"
    assert mock_assembler.received_request["request_id"] == "custom-req-42"


def test_agent_close_idempotent(mock_assembler_endpoint: str) -> None:
    agent = HawcxAgent.connect(mock_assembler_endpoint)
    agent.close()
    agent.close()  # second call must not raise


# ── Runtime principal switching (Q10 / Q13) ──────────────────────────────


def test_invoke_without_acting_for_user_omits_field(
    mock_assembler, mock_assembler_endpoint: str
) -> None:
    """Default invoke must produce wire output identical to pre-v6.9 callers.

    Backward-compat constraint: a caller that doesn't pass acting_for_user
    must observe the exact same wire payload as before the field existed,
    i.e. NO ``acting_for_user`` key in the JSON.
    """
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        agent.invoke(
            target_rs_url="https://api.example.com/echo",
            tool="echo",
            action=["query"],
            body=b"x",
        )
    assert mock_assembler.received_request is not None
    assert "acting_for_user" not in mock_assembler.received_request, (
        "acting_for_user must be omitted when not set (backward-compat: "
        "existing wire shape preserved)"
    )


def test_invoke_with_acting_for_user_sets_wire_field(
    mock_assembler, mock_assembler_endpoint: str
) -> None:
    """``acting_for_user="alice"`` must appear as a top-level wire field.

    Per CS v6.9.0 line 163, this is the input the Assembler projects into
    ``scope_json.user_principal_id``. The SDK's job is to put it on the
    wire under the agreed key; the Assembler's job is to put it in
    scope_json. We test only the SDK half here.
    """
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        agent.invoke(
            target_rs_url="https://api.example.com/echo",
            tool="read",
            acting_for_user="alice",
            body=b"hi",
        )
    assert mock_assembler.received_request is not None
    assert mock_assembler.received_request.get("acting_for_user") == "alice"
    # Wire shape sanity: acting_for_user is a top-level peer of `tool`
    # and `constraints`, NOT nested inside `constraints`. This is the
    # contract the Assembler reads against.
    assert "acting_for_user" not in (
        mock_assembler.received_request.get("constraints") or {}
    )


def test_invoke_for_is_equivalent_to_invoke_with_acting_for_user(
    mock_assembler, mock_assembler_endpoint: str
) -> None:
    """``invoke_for("bob", ...)`` == ``invoke(acting_for_user="bob", ...)``."""
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        agent.invoke_for(
            "bob",
            target_rs_url="https://api.example.com/echo",
            tool="read",
            body=b"hi",
        )
    assert mock_assembler.received_request is not None
    assert mock_assembler.received_request.get("acting_for_user") == "bob"


def test_invoke_for_rejects_empty_principal(mock_assembler_endpoint: str) -> None:
    """invoke_for must reject an empty user_principal_id at call time.

    A missing principal is most likely a caller bug — silently sending
    an empty acting_for_user="" would surface in scope_json as a
    perplexing empty-string principal that no Cedar policy expects.
    Raise loudly and direct the caller to plain invoke() for
    unprincipled calls.
    """
    with HawcxAgent.connect(mock_assembler_endpoint) as agent:
        with pytest.raises(ValueError) as ei:
            agent.invoke_for(
                "",
                target_rs_url="https://api.example.com/echo",
                tool="echo",
            )
    assert "user_principal_id" in str(ei.value)


def test_tool_call_request_to_wire_omits_acting_for_user_when_none() -> None:
    """Unit-level wire-encoding contract: None → no field."""
    from hawcx_haap.ipc import ToolCallRequest

    req = ToolCallRequest(
        request_id="r",
        target_rs_url="https://x",
        http_method="POST",
        tool="t",
    )
    wire = req.to_wire()
    assert "acting_for_user" not in wire


def test_tool_call_request_to_wire_includes_acting_for_user_when_set() -> None:
    """Unit-level wire-encoding contract: str → top-level field."""
    from hawcx_haap.ipc import ToolCallRequest

    req = ToolCallRequest(
        request_id="r",
        target_rs_url="https://x",
        http_method="POST",
        tool="t",
        acting_for_user="carol",
    )
    wire = req.to_wire()
    assert wire["acting_for_user"] == "carol"
