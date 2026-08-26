"""LangChain × HAAP integration — an M365 directory agent.

Shows how to drive the SDK's generated tool wrappers from a LangChain agent so
that every tool call is authenticated through the Hawcx pipeline and attributed
to one named end-user.

Why there is no framework-specific emitter
------------------------------------------
`hawcx wrap` deliberately generates plain callables rather than LangChain
subclasses (see ``hawcx_haap/wrap.py``): LangChain adapts any callable through
``StructuredTool.from_function``, so one neutral generator serves every
framework instead of one emitter (and one hard dependency) per framework. This
file is that adapter for LangChain.

Architecture
------------
- One ``HawcxAgent`` for the lifetime of the process (single Assembler
  connection, session keys held inside the Assembler binary).
- Tools are built **per end-user**: ``acting_for_user`` is bound at construction
  time, so every HAAP token minted by these tools carries that principal.
- The generated wrappers speak DOTTED HAAP tool ids (``o365.groups.read``) —
  what policy binds to. The LLM is given tools at MCP-call granularity
  (``list-groups``, ``get-group``) because that is the actual unit of work and
  the unit an argument schema fits. ``TOOL_SPECS`` below is the bridge, and
  mirrors ``hx_m365_sync/tool_map.json``.

Attribution is NOT model-controlled — a deliberate difference
-------------------------------------------------------------
``crewai_integration.py`` puts the user principal in the task description and
relies on the SDK's allowlist to reject a hallucinated one. This file does not
give the model the choice at all: ``build_m365_tools(agent, user)`` binds
``acting_for_user`` when the tool objects are constructed, so there is no
argument through which a model could name a different user. The allowlist stays
as the second line of defence. Prefer this shape when one agent run serves
exactly one human — which is the case for an employee's own assistant.

What this grants: nothing
-------------------------
Calling a tool here does not mean it will succeed. The agent's real authority is
the intersection of the class manifest, the per-user scope ceiling, and the
gateway's routing map — enforced at the RSV, out of this process's reach. A
DENY arriving back through these tools is the system working.

Prerequisites
-------------
- The customer-side pipeline running (``haap-supervisor``), and an agent
  identity: ``HAAP_AGENT_ID`` (pre-provisioned) or ``HAAP_ORG_TOKEN`` (runtime
  enrollment, preferred — v7.2.6 §4.2).
- ``HAAP_ALLOWED_PRINCIPALS`` — comma-separated end-user ids this agent may act
  for. Operator config; never derived from model output.
- ``HAAP_M365_ENDPOINT`` — the MCP gateway endpoint fronting the M365 server.
- An LLM provider key for whichever chat model you pass in (this file does not
  choose a provider or read a key; see ``build_agent``).

Generate the wrappers first::

    hawcx wrap m365_agent_template.yaml -o m365_tools.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

# ── Operator config ──────────────────────────────────────────────────────────
# Everything here comes from the operator environment, never from LLM output or
# a user-supplied request body. See README "Threat model - runtime principal".


def _require_env(var: str) -> str:
    val = os.environ.get(var)
    if not val:
        print(f"error: {var} is not set", file=sys.stderr)
        sys.exit(2)
    return val


# ── The tool surface the model sees ──────────────────────────────────────────


@dataclass(frozen=True)
class ToolSpec:
    """One tool as the LLM sees it, bound to the HAAP identity policy sees.

    ``mcp_name`` is the kebab-case name the downstream MCP server exposes;
    ``tool_id`` is the dotted HAAP id the generated wrapper and the scope
    ceiling both key on. They are DIFFERENT VOCABULARIES and not
    interchangeable — ``hx_m365_sync/tool_map.json`` is the mapping's home and
    says so explicitly. Note it is not 1:1: two ids below each back two MCP
    calls.
    """

    mcp_name: str
    tool_id: str
    description: str
    #: name -> (python type, required, human description). Kept as data rather
    #: than a pydantic model so this module can be imported — and tested —
    #: without LangChain or pydantic installed.
    args: dict[str, tuple[type, bool, str]] = field(default_factory=dict)


#: The OAuth provider these tools resolve under. MUST equal the `provider` in the
#: armed PolicySet's `scope_mappings` or the §45.7.2 gate finds no mapping — see
#: the note at the call site. Deliberately not tool_map.json's `o365`.
PROVIDER = "microsoft-graph"


#: PROVISIONAL ARGUMENT SCHEMAS.
#:
#: The agent template carries only ``{id, actions, risk}`` — ``tool_entries()``
#: projects exactly ``(id, actions)`` and the generated ``__call__`` takes
#: untyped ``**arguments``. LangChain wants typed arguments, so these are
#: hand-authored from Microsoft Graph semantics.
#:
#: The AUTHORITATIVE source is the downstream MCP server's ``tools/list``
#: response (that is what ``hawcx extract --tools`` consumes). Until that server
#: exists, reconcile any disagreement in ITS favour, not this file's. A wrong
#: argument name here surfaces as a downstream 400, not as a HAAP denial.
TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        mcp_name="list-groups",
        tool_id="o365.groups.read",
        description="List directory groups. Use to find a group's id before acting on it.",
        args={
            "filter": (str, False, "Optional Graph $filter, e.g. startswith(displayName,'DEMO-')"),
            "top": (int, False, "Maximum number of groups to return."),
        },
    ),
    ToolSpec(
        mcp_name="get-group",
        tool_id="o365.groups.read",
        description="Get one directory group by id.",
        args={"group_id": (str, True, "The group's directory object id.")},
    ),
    ToolSpec(
        mcp_name="list-group-members",
        tool_id="o365.groups.members_read",
        description="List the members of one group.",
        args={
            "group_id": (str, True, "The group's directory object id."),
            "top": (int, False, "Maximum number of members to return."),
        },
    ),
    ToolSpec(
        mcp_name="add-group-member",
        tool_id="o365.groups.members_write",
        description="Add one user to one group.",
        args={
            "group_id": (str, True, "The group's directory object id."),
            "user_id": (str, True, "The user's directory object id or userPrincipalName."),
        },
    ),
    ToolSpec(
        mcp_name="remove-group-member",
        tool_id="o365.groups.members_write",
        description="Remove one user from one group.",
        args={
            "group_id": (str, True, "The group's directory object id."),
            "user_id": (str, True, "The user's directory object id or userPrincipalName."),
        },
    ),
    ToolSpec(
        mcp_name="create-group",
        tool_id="o365.groups.create",
        description="Create a new directory group.",
        args={
            "display_name": (str, True, "Human-readable group name."),
            "mail_nickname": (str, True, "Mail alias; letters, digits and dashes only."),
            "description": (str, False, "What the group is for."),
        },
    ),
    ToolSpec(
        mcp_name="delete-group",
        tool_id="o365.groups.delete",
        description=(
            "Delete a directory group. Destructive and not recoverable from here — "
            "the template declares this one `admin` risk while its siblings are "
            "`write_internal`, so a ceiling can grant create without delete."
        ),
        args={"group_id": (str, True, "The group's directory object id.")},
    ),
    ToolSpec(
        mcp_name="list-users",
        tool_id="o365.users.read",
        description="List directory users. Use to resolve a person to a user id.",
        args={
            "filter": (str, False, "Optional Graph $filter, e.g. startswith(displayName,'Priya')"),
            "top": (int, False, "Maximum number of users to return."),
        },
    ),
)

#: Template tool ids with NO downstream MCP tool implementing them today
#: (``mcp_tools: []`` in tool_map.json). They stay in the agent template — an
#: agent may legitimately request an entitlement before a server implements it,
#: and the request is what the class manifest is written against — but they get
#: NO LangChain tool, because handing the model a tool that cannot be called
#: produces a retry loop that reads like a permission failure.
UNIMPLEMENTED_TOOL_IDS: frozenset[str] = frozenset(
    {"o365.users.write", "o365.applications.read"}
)


# ── LangChain adaptation ─────────────────────────────────────────────────────


def _args_model(spec: ToolSpec):
    """Build the pydantic model LangChain uses to type this tool's arguments."""
    from pydantic import BaseModel, Field, create_model

    fields: dict[str, Any] = {}
    for name, (py_type, required, desc) in spec.args.items():
        if required:
            fields[name] = (py_type, Field(..., description=desc))
        else:
            fields[name] = (py_type | None, Field(default=None, description=desc))
    model_name = "".join(part.capitalize() for part in spec.mcp_name.split("-")) + "Args"
    return create_model(model_name, __base__=BaseModel, **fields)


def build_m365_tools(
    haap_agent: Any,
    user_principal_id: str,
    *,
    endpoint: str | None = None,
    specs: tuple[ToolSpec, ...] = TOOL_SPECS,
) -> list[Any]:
    """Adapt the generated HAAP wrappers into LangChain ``StructuredTool``s.

    ``user_principal_id`` is bound into every tool here, at construction — the
    model is never given a way to name a different one. It must already be in
    the ``principal_allowlist`` the ``HawcxAgent`` was built with; the SDK
    enforces that synchronously.

    Requires ``m365_tools.py`` next to this file::

        hawcx wrap m365_agent_template.yaml -o m365_tools.py
    """
    from langchain_core.tools import StructuredTool

    from m365_tools import TOOLS  # generated; see the module docstring

    endpoint = endpoint or _require_env("HAAP_M365_ENDPOINT")

    tools: list[Any] = []
    for spec in specs:
        wrapper_cls = TOOLS.get(spec.tool_id)
        if wrapper_cls is None:
            # The generated module and this file disagree about the tool set.
            # Fail loudly: silently dropping the tool would look to an operator
            # like the model choosing not to use it.
            raise KeyError(
                f"{spec.mcp_name}: generated module has no wrapper for tool id "
                f"{spec.tool_id!r} — regenerate from m365_agent_template.yaml"
            )
        # One wrapper instance per LangChain tool. `acting_for_user` is the
        # attribution the console reads back (criterion 3) and the key the
        # per-user ceiling is stamped against (criterion 1).
        call_haap = wrapper_cls(
            haap_agent,
            endpoint,
            # `microsoft-graph`, NOT tool_map.json's `o365`. The provider string
            # is not free: the §45.7.2 scope-gate matches it against the armed
            # PolicySet's `scope_mappings`, and that value is `microsoft-graph`
            # — the same string the RSV's HAAP_RSV_MCP_PROVIDER was retargeted
            # to for the O365 run, and the provider the EIB stores the delegated
            # Graph grant under. Naming `o365` here finds no mapping, so every
            # call is refused for a reason that looks nothing like the real one.
            provider=PROVIDER,
            acting_for_user=user_principal_id,
        )

        def _run(_call: Callable[..., Any] = call_haap, _mcp: str = spec.mcp_name, **kwargs: Any):
            # Drop unset optionals rather than forwarding explicit nulls: an
            # absent argument and an argument set to null are different asks,
            # and the §45.7.2 argument predicates treat "observed" as
            # constraining. See haap-rsv's evaluate_argument_ceiling.
            arguments = {k: v for k, v in kwargs.items() if v is not None}
            # OPEN QUESTION (see the Ravi hand-off): how the MCP `params.name`
            # is carried. The wrapper sends the DOTTED tool id, while the
            # gateway's routing map is keyed by this KEBAB name. Passing it
            # explicitly keeps the intended call visible on the wire and in the
            # denial record until that carriage is settled.
            return _call(mcp_tool=_mcp, **arguments)

        tools.append(
            StructuredTool.from_function(
                func=_run,
                name=spec.mcp_name.replace("-", "_"),
                description=spec.description,
                args_schema=_args_model(spec),
            )
        )
    return tools


def build_agent(chat_model: Any, haap_agent: Any, user_principal_id: str) -> Any:
    """A tool-calling agent scoped to one employee.

    ``chat_model`` is supplied by the caller — this file deliberately chooses no
    provider and reads no API key, so the same example runs against whichever
    model the deployment has a key for.
    """
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate

    tools = build_m365_tools(haap_agent, user_principal_id)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                # The model is told WHO it acts for so its narration is honest,
                # but the binding is already made in the tools — this sentence
                # is instruction, not enforcement.
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

    # Supply your own chat model, e.g.:
    #   from langchain_anthropic import ChatAnthropic
    #   chat = ChatAnthropic(model="claude-sonnet-4-5")
    chat = _chat_model_from_env()

    with HawcxAgent.connect_by_agent_id(agent_id, principal_allowlist=allowed) as haap_agent:
        executor = build_agent(chat, haap_agent, user)
        result = executor.invoke({"input": task})
        print(result.get("output", result))
    return 0


def _chat_model_from_env() -> Any:
    """Resolve a chat model from ``HAAP_LLM_PROVIDER``, or explain what to set.

    No provider is hard-coded and no key is read here: the key belongs to the
    deployment, and pinning a provider in an example is how an example becomes a
    dependency.
    """
    provider = os.environ.get("HAAP_LLM_PROVIDER", "").lower()
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=os.environ.get("HAAP_LLM_MODEL", "claude-sonnet-4-5"))
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model=os.environ.get("HAAP_LLM_MODEL", "gpt-4o"))
    print(
        "error: set HAAP_LLM_PROVIDER to 'anthropic' or 'openai' (plus that "
        "provider's own API key env var), or call build_agent() with your own "
        "chat model.",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    raise SystemExit(main())
