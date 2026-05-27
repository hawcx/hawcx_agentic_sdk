# hawcx-crewai

CrewAI BaseTool adapter for the **Hawcx Agent Authentication Protocol** (HAAP
Canonical Specification v7.2.6, Pattern Z §45 + Pattern Y §47). Pure Python,
no native build.

> **Status:** alpha (0.1.0a1). Companion to `hawcx-haap`. Public API may
> change while the v7.2.6 sidecar surface stabilises.

## What it does

`HawcxTool` wraps a single HAAP-authenticated tool call as a drop-in
`crewai.tools.BaseTool`. Construct one per logical tool; hand the resulting
list to a CrewAI `Agent`'s `tools=[...]`.

The architectural property: **the LLM process never holds bearer
credentials or HAAP session keys.** `HawcxTool._run` forwards the call to a
connected `HawcxAgent`, which speaks local UDS only to the Assembler. The
Assembler fetches the HAAP token and the provider bearer credential
(NVIDIA NIM key, Anthropic key, etc.) from the Pattern Y sidecar (§47.8
`GetExternalCredential`) and attaches them to the outbound HTTPS request.
Neither the credential value nor the HAAP wire token ever crosses back into
the Python process.

## Install

```bash
pip install hawcx-crewai
```

Pulls in `hawcx-haap`, `crewai`, and `pydantic` as runtime dependencies.

## Quickstart

```python
from hawcx_haap import HawcxAgent
from hawcx_crewai import HawcxTool

with HawcxAgent.connect_by_agent_id(
    "research-u1",
    principal_allowlist=["alice@example.com", "bob@example.com"],
) as agent:
    nim_search = HawcxTool(
        name="nim_search",
        description="Search via NVIDIA NIM.",
        hawcx_agent=agent,
        provider="nim",                       # §47.2 provider class
        tool_id="nim-search-v1",              # §47.4 tool identity
        endpoint="https://api.nim.nvidia.com/v1/search",
        method="POST",
    )

    # Use `nim_search` as a regular CrewAI tool:
    # researcher = Agent(role="...", tools=[nim_search], ...)
```

## Multi-tenant (per-user principal)

When one agent process serves many end-users, declare the per-call
principal in your tool's `args_schema` so the LLM can supply it, and let
the SDK enforce the operator-controlled allowlist:

```python
from pydantic import BaseModel, Field

class SearchInput(BaseModel):
    query: str = Field(description="Search query.")
    user_principal_id: str = Field(
        description="End-user on whose behalf the search runs."
    )

tool = HawcxTool(
    name="hawcx_search",
    description="Search the protected knowledge base.",
    hawcx_agent=agent,
    provider="generic-bearer",
    tool_id="search",
    endpoint="https://api.example.com/search",
    args_schema=SearchInput,
)
```

`HawcxAgent.connect(..., principal_allowlist=[...])` is the enforcement
boundary: any `user_principal_id` not on the allowlist is rejected
synchronously before a single IPC byte is written. The error message
redacts the rejected principal to a 12-hex-char SHA-256 fingerprint, so
the exception text is not an enumeration oracle.

If your flow materializes one tool per user instead, use
`tool.for_user("alice@example.com")` to get a sibling instance bound to
that principal.

## Backward-compat factories

`make_search_tool` and `make_document_tool` are preserved for code
migrating from the pre-`hawcx-crewai` example. New code should construct
`HawcxTool` directly.

## License

Hawcx Proprietary License. See [LICENSE](LICENSE).
