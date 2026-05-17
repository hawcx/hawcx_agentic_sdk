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
