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

## Multi-tenant (host-bound per-user principal)

Per HAAP Canonical Specification v7.21.4 §9.1, end-user identity must never cross
the untrusted LLM tool-call boundary (`args_schema` / tool `kwargs`). Instead,
bind the principal on the host via `default_user_principal_id` or materialize
one sibling tool per end-user via `tool.for_user(...)` (cheap — shares the
single `HawcxAgent` IPC connection):

```python
from pydantic import BaseModel, Field

class SearchInput(BaseModel):
    query: str = Field(description="Search query.")

base_tool = HawcxTool(
    name="hawcx_search",
    description="Search the protected knowledge base.",
    hawcx_agent=agent,
    provider="generic-bearer",
    tool_id="search",
    endpoint="https://api.example.com/search",
    args_schema=SearchInput,
)

alice_tool = base_tool.for_user("alice@example.com")
```

`HawcxAgent.connect(..., principal_allowlist=[...])` is the host enforcement
boundary: any `user_principal_id` not on the allowlist is rejected
synchronously before a single IPC byte is written. The error message
redacts the rejected principal to a 12-hex-char SHA-256 fingerprint, so
the exception text is not an enumeration oracle. Any attempt by an LLM or
custom `args_schema` to pass `user_principal_id` / `acting_for_user` in tool
arguments is rejected fail-closed (`E_AUTHORITY_CLAIM` / `0x0058`).

## Backward-compat factories

`make_search_tool` and `make_document_tool` are preserved for code
migrating from the pre-`hawcx-crewai` example. New code should construct
`HawcxTool` directly.

## License

Hawcx Proprietary License. See [LICENSE](LICENSE).
