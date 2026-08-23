"""Tests for hawcx_haap.mcp_caller — the allow/deny classification, mostly.

The interesting assertions are the ones about a DENY that does not look like
one: a rejection carried inside an HTTP 200, the same rejection wrapped in an
SSE frame, and a body nobody can read. Each of those had exactly one wrong
answer available (call it an allow) and this file forecloses it.
"""

from __future__ import annotations

import json

import pytest

from hawcx_haap import Caller, Decision, McpTool, TokenTransport
from hawcx_haap.errors import RequestRejected
from hawcx_haap.ipc import ToolCallRequest, ToolCallResponse
from hawcx_haap.mcp_caller import env_principal_allowlist

MAIL_READ = McpTool(
    tool_id="mail.read",
    url="https://mcp.example.invalid/servers/mail",
    name="list_messages",
    actions=("read",),
    resource="mailbox",
    arguments={"top": 5},
)
MAIL_SEND = McpTool(
    tool_id="mail.send",
    url="https://mcp.example.invalid/servers/mail",
    name="send_message",
    actions=("write",),
    resource="mailbox",
    arguments={"to": ["someone@example.invalid"]},
)

OK_BODY = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}'


class RecordingAgent:
    """Stands in for HawcxAgent. Records every invoke; answers as told."""

    def __init__(self, responder=None) -> None:
        self.calls: list[dict] = []
        self._responder = responder or (lambda kw: _response(OK_BODY))

    def invoke(self, *args, **kwargs):
        # Positional too: HawcxAgent forwards a ToolCallRequest that way, and
        # the allowlist test drives the real HawcxAgent with this as its client.
        self.calls.append(kwargs)
        return self._responder(kwargs)


def _response(body: bytes, status: int = 200) -> ToolCallResponse:
    return ToolCallResponse(request_id="r-1", http_status=status, headers={}, body=body)


def _caller(responder=None) -> tuple[Caller, RecordingAgent]:
    agent = RecordingAgent(responder)
    return Caller(agent=agent, provider="example"), agent


# ── Every call goes through invoke ───────────────────────────────────


def test_the_only_egress_path_is_invoke() -> None:
    caller, agent = _caller()
    caller.call(MAIL_READ, "alice@example.invalid")
    caller.call(MAIL_SEND, "alice@example.invalid")

    assert len(agent.calls) == 2
    first, second = agent.calls
    assert first["tool"] == "mail.read"
    assert first["action"] == ["read"]
    assert first["resource"] == "mailbox"
    assert first["target_rs_url"] == MAIL_READ.url
    assert first["acting_for_user"] == "alice@example.invalid"
    assert first["transport"] is TokenTransport.MCP_META_V7_2_5
    assert first["provider"] == "example"
    assert second["action"] == ["write"]


def test_the_body_is_an_mcp_tools_call_with_no_forged_hawcx_envelope() -> None:
    caller, agent = _caller()
    caller.call(MAIL_READ, "alice@example.invalid")

    body = json.loads(agent.calls[0]["body"])
    assert body["jsonrpc"] == "2.0"
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "list_messages"
    assert body["params"]["arguments"] == {"top": 5}
    # The Assembler injects the token at params._meta.hawcx. An agent that
    # wrote that field would be forging its own authorization.
    assert "_meta" not in body["params"]


def test_call_arguments_override_the_tool_defaults() -> None:
    caller, agent = _caller()
    caller.call(MAIL_READ, "alice@example.invalid", {"top": 99})
    assert json.loads(agent.calls[0]["body"])["params"]["arguments"] == {"top": 99}


def test_jsonrpc_ids_are_unique_per_caller() -> None:
    caller, agent = _caller()
    for _ in range(3):
        caller.call(MAIL_READ, "alice@example.invalid")
    ids = [json.loads(c["body"])["id"] for c in agent.calls]
    assert ids == [1, 2, 3]


def test_the_accept_header_admits_both_streamable_http_shapes() -> None:
    # Without text/event-stream the server may not send an SSE answer at all,
    # and the parsing below would never be exercised in production.
    caller, agent = _caller()
    caller.call(MAIL_READ, "alice@example.invalid")
    assert agent.calls[0]["headers"]["Accept"] == "application/json, text/event-stream"


def test_invoke_kwargs_needs_no_agent_and_serializes_through_the_sdk() -> None:
    kwargs = Caller(provider="example").invoke_kwargs(MAIL_SEND, "alice@example.invalid")
    body = kwargs.pop("body")
    wire = ToolCallRequest(
        request_id="capture-1", plaintext_request_body=body, **kwargs
    ).to_wire()

    assert wire["acting_for_user"] == "alice@example.invalid"
    assert wire["action"] == ["write"]
    assert wire["transport"] == "mcp_meta_v7_2_5"
    assert wire["provider"] == "example"
    assert "_meta" not in wire


# ── Classification ───────────────────────────────────────────────────


def test_a_success_is_an_allow() -> None:
    caller, _ = _caller()
    decision = caller.call(MAIL_READ, "alice@example.invalid")
    assert decision.allowed
    assert decision.reason is None
    assert decision.http_status == 200
    assert decision.request_id == "r-1"


def test_an_assembler_rejection_is_a_decision_not_an_exception() -> None:
    def reject(_kwargs):
        raise RequestRejected("req-7", "ScopeExceedsCeiling: write")

    caller, agent = _caller(reject)
    decision = caller.call(MAIL_SEND, "alice@example.invalid")

    assert decision.allowed is False
    assert "ScopeExceedsCeiling" in decision.reason
    assert decision.request_id == "req-7"
    assert decision.tool == "mail.send"
    # It was framed to the Assembler and stopped there: no destination request.
    assert len(agent.calls) == 1


def test_a_jsonrpc_rejection_inside_an_http_200_is_a_deny() -> None:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32005,
                "message": "DestinationResolutionFailed",
                "data": {"hawcx_reason_code": "0x002B"},
            },
        }
    ).encode()
    caller, _ = _caller(lambda kw: _response(body))
    decision = caller.call(MAIL_READ, "alice@example.invalid")

    assert decision.allowed is False
    assert decision.reason_code == "0x002B"
    assert decision.reason == "DestinationResolutionFailed"
    assert decision.http_status == 200


def test_an_sse_framed_denial_opening_with_event_message_is_a_deny() -> None:
    """The regression this module was extracted to stop shipping.

    A real SSE frame opens with ``event: message``, so an implementation that
    sniffs for a leading ``data:`` decides this body is not a stream, finds no
    JSON-RPC error in it, and returns ALLOW for a denial.
    """
    body = (
        b"event: message\n"
        b'data: {"jsonrpc":"2.0","id":1,"error":{"code":-32000,'
        b'"message":"HawcxRejection","data":{"hawcx_reason_code":"0x002B"}}}\n\n'
    )
    assert not body.startswith(b"data:"), "the frame this test exists for"

    caller, _ = _caller(lambda kw: _response(body))
    decision = caller.call(MAIL_SEND, "alice@example.invalid")

    assert decision.allowed is False
    assert decision.reason_code == "0x002B"


def test_an_sse_denial_after_other_events_and_comments_is_still_a_deny() -> None:
    # Servers are entitled to send keep-alive comments, ids and a prelude event
    # before the frame that matters. None of that may hide the denial.
    body = (
        b": keep-alive\n"
        b"event: endpoint\n"
        b'data: {"jsonrpc":"2.0","id":0,"result":{}}\n'
        b"\n"
        b"id: 42\n"
        b"event: message\n"
        b'data: {"jsonrpc":"2.0","id":1,"error":{"code":-32003,'
        b'"message":"PolicyDenied","data":{"hawcx_reason_code":"0x0031"}}}\n\n'
    )
    caller, _ = _caller(lambda kw: _response(body))
    decision = caller.call(MAIL_SEND, "alice@example.invalid")

    assert decision.allowed is False
    assert decision.reason_code == "0x0031"


def test_a_rejection_without_a_reason_code_still_denies() -> None:
    body = b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"HawcxRejection"}}'
    caller, _ = _caller(lambda kw: _response(body))
    decision = caller.call(MAIL_READ, "alice@example.invalid")

    assert decision.allowed is False
    assert decision.reason_code is None
    assert decision.reason == "HawcxRejection"


@pytest.mark.parametrize("code", [-32005, -32004, -32003, -32002, -32001, -32000])
def test_the_whole_haap_rejection_range_denies(code: int) -> None:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": code}}).encode()
    caller, _ = _caller(lambda kw: _response(body))
    assert caller.call(MAIL_READ, "alice@example.invalid").allowed is False


@pytest.mark.parametrize("code", [-32601, -32602, -32700, -31999, -32006])
def test_a_downstream_jsonrpc_fault_is_not_reported_as_a_policy_denial(code: int) -> None:
    # Outside -32005..-32000. Calling a "method not found" a policy denial
    # would manufacture evidence of a decision that was never made.
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": code}}).encode()
    caller, _ = _caller(lambda kw: _response(body))
    assert caller.call(MAIL_READ, "alice@example.invalid").allowed is True


@pytest.mark.parametrize("status", [401, 403])
def test_an_http_401_or_403_is_a_deny(status: int) -> None:
    caller, _ = _caller(lambda kw: _response(b'{"jsonrpc":"2.0","id":1}', status))
    decision = caller.call(MAIL_READ, "alice@example.invalid")
    assert decision.allowed is False
    assert f"HTTP {status}" in decision.reason


# ── Fail closed ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"   \n  ", id="whitespace"),
        pytest.param(b"<html><body>502 Bad Gateway</body></html>", id="html"),
        pytest.param(b'{"jsonrpc":"2.0","id":1,"result":{"tr', id="truncated-json"),
        pytest.param(b"event: message\ndata: {not json at all\n\n", id="broken-sse"),
        pytest.param(b'[{"jsonrpc":"2.0","id":1,"result":{}}]', id="jsonrpc-batch"),
        pytest.param(b'"just a string"', id="json-scalar"),
        pytest.param(b"\xff\xfe\x00garbage", id="not-utf8"),
    ],
)
def test_a_body_that_cannot_be_classified_denies(body: bytes) -> None:
    """Not being able to tell is not the same as being told yes.

    Every one of these bodies could be hiding a denial. Returning ALLOW for
    them would mean an agent proceeds on the strength of a response nobody
    read successfully.
    """
    caller, _ = _caller(lambda kw: _response(body))
    decision = caller.call(MAIL_READ, "alice@example.invalid")

    assert decision.allowed is False
    assert "unclassifiable" in decision.reason


def test_a_response_object_missing_its_fields_denies() -> None:
    # Whatever this is, it is not evidence that the call was permitted.
    caller, _ = _caller(lambda kw: object())
    assert caller.call(MAIL_READ, "alice@example.invalid").allowed is False


# ── Odds and ends ────────────────────────────────────────────────────


def test_summary_reads_as_a_verdict() -> None:
    allow = Decision(tool="mail.read", principal="alice", allowed=True, http_status=200)
    deny = Decision(
        tool="mail.send",
        principal="alice",
        allowed=False,
        reason="HawcxRejection",
        reason_code="0x002B",
    )
    assert allow.summary().startswith("ALLOW")
    assert "alice" in allow.summary()
    assert deny.summary().startswith("DENY")
    assert "0x002B" in deny.summary()
    assert "HawcxRejection" in deny.summary()


def test_an_unset_allowlist_env_var_is_not_an_empty_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Unset means "use your configured default"; set-but-empty means "forbid
    # runtime principal switching". Collapsing the two would silently widen or
    # silently narrow the gate depending on which way it collapsed.
    monkeypatch.delenv("HAWCX_PRINCIPAL_ALLOWLIST", raising=False)
    assert env_principal_allowlist() is None

    monkeypatch.setenv("HAWCX_PRINCIPAL_ALLOWLIST", "")
    assert env_principal_allowlist() == []

    monkeypatch.setenv("HAWCX_PRINCIPAL_ALLOWLIST", " alice@x.invalid , bob@x.invalid ")
    assert env_principal_allowlist() == ["alice@x.invalid", "bob@x.invalid"]


def test_the_principal_allowlist_gate_runs_before_any_ipc() -> None:
    """Drives the real HawcxAgent gate, not a stand-in for it."""
    from hawcx_haap import HawcxAgent
    from hawcx_haap.errors import HawcxError

    client = RecordingAgent()
    caller = Caller(agent=HawcxAgent(client, frozenset({"alice@example.invalid"})))

    with pytest.raises(HawcxError):
        caller.call(MAIL_READ, "attacker@example.invalid")
    assert client.calls == [], "IPC was attempted for a rejected principal"

    # And the permitted principal does get through the same gate.
    caller.call(MAIL_READ, "alice@example.invalid")
    assert len(client.calls) == 1
