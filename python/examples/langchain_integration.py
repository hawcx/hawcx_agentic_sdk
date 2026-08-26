"""LangChain × HAAP integration — an M365 directory agent.

Drives the SDK's MCP caller from a LangChain agent so every tool call is
authenticated through the Hawcx pipeline and attributed to one named end-user.

TWO IDENTIFIERS, ONE CALL — the thing to understand before editing this file
------------------------------------------------------------------------------
A tool call carries BOTH identifiers, in different fields, and nothing
translates between them:

* ``tool=<dotted id>`` (``o365.groups.members_write``) is the **TBAC scope**.
  The Assembler mints against it and the cascade enforces it at Step 13. Policy
  vocabulary.
* ``params.name=<kebab name>`` (``add-group-member``) is the **route**. The RSV
  derives ``(provider, action, resource)`` from it through the operator-managed
  routing config (CS v7.8.1 §45.7.5.3); unresolvable input is fail-closed per
  §45.7.5.5. Wire vocabulary.

They are deliberately never unified: §45.7.5.1 forbids the Assembler from
emitting any destination tuple, because agent-controllable destination input
would violate §45.7.2's wire-derivation invariant. The dotted id cannot route,
and the kebab name cannot be the scope.

``hawcx_haap.mcp_caller`` is the carrier for exactly this — ``McpTool`` holds
``tool_id`` AND ``name``, ``Caller.envelope()`` puts the name at
``params.name``, and ``Caller.invoke_kwargs()`` puts the id at ``tool=`` while
supplying the JSON-RPC ``body``, the ``content_type`` and the ``transport``.
Build on it. An earlier draft of this file called ``agent.invoke()`` directly
with no body at all, which meant no JSON-RPC document existed and
``params.name`` was never set — and passed the MCP name as a keyword, which
lands in ``params.arguments`` and reaches Graph as a bogus argument (a 400, not
a routing hint).

WHICH EGRESS PATH THIS DEMO IS PINNED TO, AND WHY
--------------------------------------------------
**The RSV ``/proxy`` path**, selected by setting ``provider`` on the ``Caller``.
That branch is taken when ``provider.is_some() && rs_proxy_url.is_some()`` and
sits *before* the transport match, so it wins regardless of ``transport``. The
body is forwarded to the target, so ``params.name`` arrives intact and the
gateway's kebab-keyed routing map resolves it.

The ``TokenTransport::McpMeta`` direct path is NOT used, deliberately: the
Assembler currently copies the dotted ``tool_id`` into ``params.name`` and
AEAD-encrypts the envelope where nothing reads it, so a kebab-keyed map cannot
resolve it and every call fail-closes as what looks like a policy denial. That
is a real Assembler defect, filed separately against
``hx_agent_client_auth_service``. Until it lands, keep ``provider`` set.

ATTRIBUTION IS BOUND, NOT SUGGESTED
------------------------------------
``build_m365_tools(caller, user)`` binds ``acting_for_user`` when the LangChain
tools are constructed, so there is no argument through which a model could name
a different user. ``crewai_integration.py`` takes the other approach — principal
in the task description, allowlist as the backstop. Prefer this shape when one
run serves exactly one human, which is what an employee's own assistant is. The
allowlist remains the second line of defence either way.

WHAT THIS GRANTS: NOTHING
--------------------------
Calling a tool here does not mean it succeeds. Real authority is the
intersection of the class manifest, the per-user scope ceiling and the routing
map, enforced at the RSV, out of this process's reach. A denial arriving back
through these tools is the system working — see ``Decision.allowed``.

Prerequisites
-------------
- The customer-side pipeline running (``haap-supervisor``) and an agent
  identity: ``HAAP_AGENT_ID`` or ``HAAP_ORG_TOKEN`` (runtime enrollment).
- ``HAAP_ALLOWED_PRINCIPALS`` — operator config; never model output.
- ``HAAP_M365_ENDPOINT`` — the MCP gateway endpoint fronting the M365 server.
- A chat model. See ``_chat_model_from_env``.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import Any

from hawcx_haap.mcp_caller import Caller, Decision, McpTool

# ── Operator config ──────────────────────────────────────────────────────────


def _require_env(var: str) -> str:
    val = os.environ.get(var)
    if not val:
        print(f"error: {var} is not set", file=sys.stderr)
        sys.exit(2)
    return val


#: The OAuth provider these tools resolve under. MUST equal the `provider` in
#: the armed PolicySet's `scope_mappings` or the §45.7.2 gate finds no mapping
#: and refuses every call — for a reason that looks nothing like the cause.
#: Deliberately not the `o365.*` tool_id prefix; those are a different
#: vocabulary. Setting it is also what pins this demo to the /proxy path.
PROVIDER = "microsoft-graph"

#: Vendored from `hx_m365_sync/tool_map.json`. Read the fixture's own `_comment`
#: for why it is vendored rather than cross-repo-imported.
_FIXTURE = pathlib.Path(__file__).with_name("m365_tool_map.fixture.json")


def _load_fixture() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


#: PROVISIONAL ARGUMENT SCHEMAS — the one thing here with no upstream source.
#:
#: `tool_map.json` carries ids, MCP names and routing, but no argument shapes;
#: the agent template carries only `{id, actions, risk}`. LangChain needs typed
#: arguments, so these are hand-authored from Microsoft Graph semantics.
#:
#: The AUTHORITATIVE source is the downstream MCP server's `tools/list` — what
#: `hawcx extract --tools` consumes. Reconcile in ITS favour when it exists. A
#: wrong name here surfaces as a downstream 400, not a HAAP denial, so it will
#: not look like a security failure.
#:
#: Keyed by MCP tool name so it lines up with `params.name`. A test asserts this
#: table covers exactly the callable tools in the fixture, so it cannot drift
#: out of step with the ids the way a free-standing table would.
ARGUMENT_SCHEMAS: dict[str, dict[str, tuple[type, bool, str]]] = {
    "list-groups": {
        "filter": (str, False, "Optional Graph $filter, e.g. startswith(displayName,'DEMO-')"),
        "top": (int, False, "Maximum number of groups to return."),
    },
    "get-group": {
        "group_id": (str, True, "The group's directory object id."),
    },
    "list-group-members": {
        "group_id": (str, True, "The group's directory object id."),
        "top": (int, False, "Maximum number of members to return."),
    },
    "add-group-member": {
        "group_id": (str, True, "The group's directory object id."),
        "user_id": (str, True, "The user's directory object id or userPrincipalName."),
    },
    "remove-group-member": {
        "group_id": (str, True, "The group's directory object id."),
        "user_id": (str, True, "The user's directory object id or userPrincipalName."),
    },
    "create-group": {
        "display_name": (str, True, "Human-readable group name."),
        "mail_nickname": (str, True, "Mail alias; letters, digits and dashes only."),
        "description": (str, False, "What the group is for."),
    },
    "delete-group": {
        "group_id": (str, True, "The group's directory object id."),
    },
    "list-users": {
        "filter": (str, False, "Optional Graph $filter, e.g. startswith(displayName,'Priya')"),
        "top": (int, False, "Maximum number of users to return."),
    },
}

#: One-line descriptions for the model. Kept beside the schemas rather than in
#: the fixture: the fixture is a vendored copy and must stay diffable against
#: upstream, and prompt wording is ours to tune.
DESCRIPTIONS: dict[str, str] = {
    "list-groups": "List directory groups. Use to find a group's id before acting on it.",
    "get-group": "Get one directory group by id.",
    "list-group-members": "List the members of one group.",
    "add-group-member": "Add one user to one group.",
    "remove-group-member": "Remove one user from one group.",
    "create-group": "Create a new directory group.",
    "delete-group": (
        "Delete a directory group. Destructive and not recoverable from here — the "
        "agent template declares this one `admin` risk while its siblings are "
        "`write_internal`, so a ceiling can grant create without delete."
    ),
    "list-users": "List directory users. Use to resolve a person to a user id.",
}


def unimplemented_tool_ids() -> frozenset[str]:
    """Tool ids the agent may request but no downstream MCP tool implements.

    Derived from the fixture (`mcp_tools: []`) rather than hand-maintained, so
    the day one is implemented upstream the list stops being wrong on its own.
    They stay in the agent template — an agent may legitimately request an
    entitlement before a server implements it, and the class manifest is written
    against the request — but they get no LangChain tool: handing a model an
    uncallable tool produces a retry loop that reads like a permission failure.
    """
    return frozenset(t["tool_id"] for t in _load_fixture()["tools"] if not t["mcp_tools"])


def m365_tools(endpoint: str | None = None) -> list[McpTool]:
    """The callable M365 surface, as `McpTool`s built from the vendored fixture.

    One `McpTool` per MCP tool name, not per tool_id: the vocabularies are not
    1:1 (`o365.groups.read` backs both `list-groups` and `get-group`), and the
    MCP name is the unit of work, the unit an argument schema fits, and what
    `params.name` carries.
    """
    endpoint = endpoint or _require_env("HAAP_M365_ENDPOINT")
    out: list[McpTool] = []
    for entry in _load_fixture()["tools"]:
        routing = entry.get("routing") or {}
        for name in entry["mcp_tools"]:
            out.append(
                McpTool(
                    tool_id=entry["tool_id"],
                    url=endpoint,
                    name=name,
                    actions=(routing.get("action", "read"),),
                    resource=routing.get("resource", "*"),
                )
            )
    return out


# ── LangChain adaptation ─────────────────────────────────────────────────────


def _args_model(tool: McpTool):
    """The pydantic model LangChain uses to type one tool's arguments."""
    from pydantic import BaseModel, Field, create_model

    schema = ARGUMENT_SCHEMAS.get(tool.name, {})
    fields: dict[str, Any] = {}
    for name, (py_type, required, desc) in schema.items():
        if required:
            fields[name] = (py_type, Field(..., description=desc))
        else:
            fields[name] = (py_type | None, Field(default=None, description=desc))
    model_name = "".join(p.capitalize() for p in tool.name.split("-")) + "Args"
    return create_model(model_name, __base__=BaseModel, **fields)


def build_m365_tools(
    caller: Caller,
    user_principal_id: str,
    *,
    endpoint: str | None = None,
) -> list[Any]:
    """Adapt the M365 `McpTool`s into LangChain `StructuredTool`s.

    ``user_principal_id`` is bound here, at construction — the model is never
    given a way to name a different one. It must already be in the
    ``principal_allowlist`` the ``HawcxAgent`` was built with; the SDK enforces
    that synchronously.

    Every call returns a :class:`~hawcx_haap.mcp_caller.Decision`. A denial is
    an outcome, not an exception, so the model sees the refusal text and can
    report it rather than retrying blindly.
    """
    from langchain_core.tools import StructuredTool

    tools: list[Any] = []
    for mcp_tool in m365_tools(endpoint):

        def _run(_tool: McpTool = mcp_tool, **kwargs: Any) -> str:
            # Drop unset optionals rather than forwarding explicit nulls: an
            # absent argument and one set to null are different asks, and the
            # §45.7.2 argument predicates treat "observed" as constraining.
            arguments = {k: v for k, v in kwargs.items() if v is not None}
            decision: Decision = caller.call(_tool, user_principal_id, arguments)
            # The model gets the verdict in words. `summary()` is one line and
            # already carries the reason code, which is what makes a denial
            # reportable rather than mysterious.
            return decision.summary() if not decision.allowed else decision.body or decision.summary()

        tools.append(
            StructuredTool.from_function(
                func=_run,
                name=mcp_tool.name.replace("-", "_"),
                description=DESCRIPTIONS.get(mcp_tool.name, mcp_tool.name),
                args_schema=_args_model(mcp_tool),
            )
        )
    return tools


def build_agent(chat_model: Any, caller: Caller, user_principal_id: str) -> Any:
    """A tool-calling agent scoped to one employee."""
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate

    tools = build_m365_tools(caller, user_principal_id)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                # The model is told who it acts for so its narration is honest;
                # the binding is already made in the tools, so this sentence is
                # instruction, not enforcement.
                f"You are a directory assistant acting for {user_principal_id}. "
                "Resolve people and groups to ids with the list/get tools before "
                "any change. Never invent an id. If a call is denied, report the "
                "denial verbatim and stop — do not try another route to the same "
                "outcome.",
            ),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ]
    )
    return AgentExecutor(
        agent=create_tool_calling_agent(chat_model, tools, prompt),
        tools=tools,
        verbose=True,
    )


# ── Runnable example ─────────────────────────────────────────────────────────


def main() -> int:
    from hawcx_haap import HawcxAgent

    agent_id = os.environ.get("HAAP_AGENT_ID")
    org_token = os.environ.get("HAAP_ORG_TOKEN")
    if not agent_id and not org_token:
        print(
            "error: set HAAP_AGENT_ID (pre-provisioned) or HAAP_ORG_TOKEN "
            "(runtime enrollment, preferred)",
            file=sys.stderr,
        )
        return 2

    allowed = [p.strip() for p in _require_env("HAAP_ALLOWED_PRINCIPALS").split(",") if p.strip()]
    user = os.environ.get("HAAP_ACTING_FOR_USER", allowed[0])
    if user not in allowed:
        # Fail before connecting: the SDK would refuse at invoke time anyway,
        # and refusing here names the config that is wrong.
        print(f"error: {user} is not in HAAP_ALLOWED_PRINCIPALS", file=sys.stderr)
        return 2

    task = " ".join(sys.argv[1:]) or "Which groups am I a member of?"
    chat = _chat_model_from_env()

    with HawcxAgent.connect_by_agent_id(agent_id, principal_allowlist=allowed) as haap_agent:
        # `provider` set => the RSV /proxy path, which is the one that forwards
        # the body so `params.name` reaches the gateway. See the module docstring.
        caller = Caller(agent=haap_agent, provider=PROVIDER)
        executor = build_agent(chat, caller, user)
        result = executor.invoke({"input": task})
        print(result.get("output", result))
    return 0


def _chat_model_from_env() -> Any:
    """Resolve a chat model from ``HAAP_LLM_PROVIDER``.

    No provider is pinned and no key is read here: the key belongs to the
    deployment, and hard-coding a provider in an example is how an example
    becomes a dependency. Anthropic is the PoC's demo-environment default.

    THE LLM HOP IS OUTSIDE HAAP ENTIRELY — no token, no cascade, no receipt.
    It is not a tool call and the gate never sees it. Conflating the two is the
    misreading this demo invites, so state it plainly when presenting.

    That does not make it ungoverned. ``hawcx_haap.egress`` (ADR-0048) routes
    agent HTTP through the per-agent SOCKS5-over-UDS broker, always sending
    ``ATYP=DOMAINNAME`` and never resolving DNS locally — which is precisely
    what makes the broker's hostname allowlist enforceable. So the answer to
    "what stops the agent calling anything it likes?" is "``api.anthropic.com``
    is on the broker allowlist and nothing else is", not a promise of restraint.
    To route this hop through the broker, hand the provider SDK the broker's
    client. `egress.client()` returns a configured `httpx.Client` that dials the
    UDS and performs the SOCKS5 CONNECT itself (no SOCKS *URL* can name a
    filesystem path, which is why the shim exists). TLS stays end-to-end — the
    broker never terminates it::

        import hawcx_haap.egress as egress
        from langchain_anthropic import ChatAnthropic

        with egress.client() as http:
            chat = ChatAnthropic(model=..., http_client=http)

    Whether a given provider SDK accepts a caller-supplied client is the
    provider's API, not something HAAP can impose — verify it for the one you
    pick rather than assuming.
    """
    provider = os.environ.get("HAAP_LLM_PROVIDER", "").lower()
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=os.environ.get("HAAP_LLM_MODEL", "claude-sonnet-4-5"))
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model=os.environ.get("HAAP_LLM_MODEL", "gpt-4o"))
    print(
        "error: set HAAP_LLM_PROVIDER to 'anthropic' (the PoC default) or "
        "'openai', plus that provider's own API key env var — or call "
        "build_agent() with your own chat model.",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    raise SystemExit(main())
