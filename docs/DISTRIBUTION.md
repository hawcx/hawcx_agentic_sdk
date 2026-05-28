# HAAP SDK — Binary Distribution & CrewAI Integration Guide

> **SDK version:** `0.1.0-alpha.11`  
> **Protocol:** HAAP Canonical Specification v7.2.5  
> **Status:** Pre-product alpha. Customer evaluation only.

---

## Table of Contents

1. [What Is Distributed](#1-what-is-distributed)
2. [The Multi-Call Binary](#2-the-multi-call-binary)
3. [PyPI Distribution (`hawcx-haap`)](#3-pypi-distribution-hawcx-haap)
4. [npm Distribution (`@hawcx/hawcx-haap`)](#4-npm-distribution-hawcxhawcx-haap)
5. [CI Build Matrix](#5-ci-build-matrix)
6. [Getting Started with CrewAI](#6-getting-started-with-crewai)
7. [Annotated CrewAI Example](#7-annotated-crewai-example)
8. [Multi-Tenant Pattern](#8-multi-tenant-pattern)
9. [Security Model](#9-security-model)

---

## 1. What Is Distributed

The HAAP SDK ships **one real binary** — `hawcx-manager` — packaged into platform-specific wheels (PyPI) and scoped npm packages (npm). The binary implements the complete customer-side pipeline described in HAAP CS v7.2.5 §39:

| Role | Subcommand | Protocol Section |
|---|---|---|
| Supervisor | `hawcx-manager supervisor` | §39.1 — lifecycle orchestrator |
| Authenticator | `hawcx-manager authenticator` | §4.2.1 — holds `IK_i`, runs X3DH |
| TQS Precompute | `hawcx-manager tqs-precompute` | §40 — session-scoped `K_session_root` |
| TQS JIT | `hawcx-manager tqs-jit` | §40 — request-scoped, paired 1:1 with Assembler |
| Assembler | `hawcx-manager assembler` | §39, §47 — single-flight crypto-proxy |
| EIB | `hawcx-manager eib` | §45 — External Identity Broker, OAuth bearer |
| SDK CLI | `hawcx-manager sdk` | debug / operator CLI |

Seven legacy names (`haap-supervisor`, `haap-authenticator`, `haap-tqs-precompute`, `haap-tqs-jit`, `haap-assembler`, `haap-eib`, `haap-sdk`) are preserved as symlinks (Unix) or `.exe` copies (Windows) so that existing scripts continue to work unchanged.

**Not in this package:** `haap-rsv` (MCP-server-side verifier) ships from a separate image `ghcr.io/hawcx/haap-rsv` built from `hx_agent_authorizer`.

---

## 2. The Multi-Call Binary

`hawcx-manager` is a Rust binary built from `hx_agent_client_auth_service/crates/hawcx-manager/`. It dispatches to the correct role by inspecting `argv[0]`:

```
hawcx-manager supervisor      ← run as haap-supervisor or explicit subcommand
hawcx-manager authenticator   ← run as haap-authenticator or explicit subcommand
hawcx-manager assembler       ← run as haap-assembler (the IPC endpoint this SDK talks to)
hawcx-manager tqs-precompute  ← run as haap-tqs-precompute
hawcx-manager tqs-jit         ← run as haap-tqs-jit
hawcx-manager eib             ← run as haap-eib
hawcx-manager sdk             ← run as haap-sdk (operator CLI)
```

The supervisor (entry point for a normal deployment) spawns the remaining processes. You do not call the sub-roles directly.

---

## 3. PyPI Distribution (`hawcx-haap`)

### Install

```bash
pip install hawcx-haap
```

On `pip install`, the matching platform wheel is selected automatically. `hawcx-manager` lands in `venv/bin/hawcx-manager` (Unix) or `venv\Scripts\hawcx-manager.exe` (Windows).

### How it works

The build backend is [maturin](https://www.maturin.rs/) with `bindings = "bin"`. This packages a Rust binary — not a Python extension — into a platform-specific wheel. The same approach is used by `ruff`, `uv`, and `black`.

```toml
# python/pyproject.toml (relevant section)
[build-system]
requires = ["maturin>=1.5,<2.0"]
build-backend = "maturin"

[tool.maturin]
bindings = "bin"
# Rust source lives in sibling hx_agent_client_auth_service repo.
# CI passes --manifest-path at build time.
python-source = "src"
```

### Supported platforms

| Wheel tag | Platform | Architecture |
|---|---|---|
| `*-linux_x86_64` | Linux | x86-64 |
| `*-manylinux_*_aarch64` | Linux | ARM64 |
| `*-macosx_*_arm64` | macOS (Apple Silicon) | ARM64 |
| `*-win_amd64` | Windows | x86-64 |
| `*-win_arm64` | Windows | ARM64 |

### Locating the binary at runtime

```python
from hawcx_haap import get_binary_path

binary = get_binary_path()
# → "/path/to/venv/bin/hawcx-manager" (Unix)
# → "C:\...\venv\Scripts\hawcx-manager.exe" (Windows)
```

`get_binary_path()` raises `RuntimeError` if the binary is absent (e.g., installed from source without running maturin). The error message explains the local development workflow.

### Packages on PyPI

| Package | Purpose |
|---|---|
| `hawcx-haap` | Core IPC client + bundled `hawcx-manager` binary |
| `hawcx-crewai` | CrewAI `BaseTool` adapter (depends on `hawcx-haap`) |

---

## 4. npm Distribution (`@hawcx/hawcx-haap`)

### Install

```bash
npm install @hawcx/hawcx-haap
```

npm installs only the platform package matching the current OS and CPU. The main package resolves the binary path at runtime via `require.resolve`.

### How it works

The main package declares `optionalDependencies` pointing at five scoped packages, each tagged with `os` and `cpu` fields so npm skips non-matching ones:

```json
// node/package.json (relevant section)
"optionalDependencies": {
  "@hawcx/hawcx-haap-linux-x64":    "0.1.0-alpha.11",
  "@hawcx/hawcx-haap-linux-arm64":  "0.1.0-alpha.11",
  "@hawcx/hawcx-haap-darwin-arm64": "0.1.0-alpha.11",
  "@hawcx/hawcx-haap-win32-x64":    "0.1.0-alpha.11",
  "@hawcx/hawcx-haap-win32-arm64":  "0.1.0-alpha.11"
}
```

Each platform package ships `hawcx-manager` (or `hawcx-manager.exe`) as its sole file. The pattern is identical to `@biomejs/biome` and `esbuild`.

### Supported platforms

| npm package | OS | CPU |
|---|---|---|
| `@hawcx/hawcx-haap-linux-x64` | linux | x64 |
| `@hawcx/hawcx-haap-linux-arm64` | linux | arm64 |
| `@hawcx/hawcx-haap-darwin-arm64` | darwin | arm64 |
| `@hawcx/hawcx-haap-win32-x64` | win32 | x64 |
| `@hawcx/hawcx-haap-win32-arm64` | win32 | arm64 |

### Locating the binary at runtime

```typescript
import { getBinaryPath } from "@hawcx/hawcx-haap";

const binary = getBinaryPath();
// → "/path/to/node_modules/@hawcx/hawcx-haap-linux-x64/hawcx-manager"
```

`getBinaryPath()` throws if the current platform is unsupported or the platform package is not installed.

---

## 5. CI Build Matrix

Both release workflows (`release-python.yml`, `release-node.yml`) run the same 5-target Rust build matrix, checked out from `hx_agent_client_auth_service`, against the private Kellnr registry at `cargo.hawcx.com`.

| Rust target | CI runner | PyPI wheel | npm package |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` | `linux_x86_64` | `linux-x64` |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` | `manylinux_*_aarch64` | `linux-arm64` |
| `aarch64-apple-darwin` | `macos-14` | `macosx_*_arm64` | `darwin-arm64` |
| `x86_64-pc-windows-msvc` | `windows-latest` | `win_amd64` | `win32-x64` |
| `aarch64-pc-windows-msvc` | `windows-latest` | `win_arm64` | `win32-arm64` |

**Trigger tags:**

```bash
git tag python-v0.1.0-alpha.11 && git push origin python-v0.1.0-alpha.11
git tag node-v0.1.0-alpha.11   && git push origin node-v0.1.0-alpha.11
```

---

## 6. Getting Started with CrewAI

### Prerequisites

1. The `hawcx-manager` supervisor pipeline must be running on the agent host. The Assembler's socket path follows the convention `{XDG_RUNTIME_DIR}/hawcx/{agent_id}/agent-assembler-0.sock` (Linux) or `\\.\pipe\haap-{agent_id}-agent-assembler-0` (Windows).

2. The agent identity must be pre-provisioned in the Hawcx Admin Console (CAA → Authenticator flow per CS §4.6.3).

### Install

```bash
pip install hawcx-haap hawcx-crewai crewai
```

The `hawcx-haap` wheel bundles `hawcx-manager`. After install, `hawcx_haap.get_binary_path()` resolves the binary for supervisor start-up scripts.

### Packages involved

| Package | Role |
|---|---|
| `hawcx-haap` | IPC client + bundled binary. Core library. |
| `hawcx-crewai` | `HawcxTool` — a `crewai.tools.BaseTool` subclass. |
| `crewai` | Multi-agent orchestration framework. |

---

## 7. Annotated CrewAI Example

The `python-crewai/` directory in this repo contains the full `hawcx-crewai` adapter package. Below is an end-to-end example showing the idiomatic pattern for a HAAP-authenticated CrewAI crew.

```python
"""
hawcx_crewai_example.py
-----------------------
End-to-end example: a two-agent CrewAI crew where every tool call is
authenticated and policy-gated by HAAP (HAAP CS v7.2.5, Profile E).

Dependencies:
    pip install hawcx-haap hawcx-crewai crewai

Prerequisites:
    - hawcx-manager supervisor pipeline running on this host.
      Start it: $(hawcx_haap.get_binary_path()) supervisor start
    - Agent "research-u1" pre-provisioned in the Hawcx Admin Console.
    - Tools "nim-search-v1" and "docs-reader-v1" bound to credentials
      in the credential store for this agent.
"""

import os

from crewai import Agent, Crew, Process, Task
from pydantic import BaseModel, Field

from hawcx_haap import HawcxAgent
from hawcx_crewai import HawcxTool


# ─────────────────────────────────────────────────────────────────────
# Step 1: Define typed argument schemas for each tool.
#
# CrewAI surfaces these to the LLM for argument validation and
# tool-selection prompting. The `user_principal_id` field is the
# per-call identity axis: the LLM supplies it, and the SDK enforces
# that it is on the operator-controlled allowlist before writing any
# IPC bytes (HAAP CS v7.2.5 H-3 hardening).
# ─────────────────────────────────────────────────────────────────────

class SearchInput(BaseModel):
    query: str = Field(description="Search query to run against the NIM knowledge base.")
    user_principal_id: str = Field(
        description=(
            "ID of the end-user on whose behalf this search is performed. "
            "Must be one of the principals registered for this research agent."
        )
    )


class DocsInput(BaseModel):
    document_id: str = Field(description="Opaque identifier of the document to retrieve.")
    user_principal_id: str = Field(
        description="ID of the end-user on whose behalf this document is fetched."
    )


# ─────────────────────────────────────────────────────────────────────
# Step 2: Connect to the running Assembler process.
#
# HawcxAgent.connect_by_agent_id() resolves the conventional UDS path:
#   {XDG_RUNTIME_DIR}/hawcx/research-u1/agent-assembler-0.sock
# and performs the §7 capability handshake synchronously.
#
# principal_allowlist is a required, operator-controlled closed set.
# Any user_principal_id not in this list is rejected synchronously
# before a single byte is written to the IPC socket. Never derive this
# list from LLM output or request bodies.
# ─────────────────────────────────────────────────────────────────────

ALLOWED_USERS = ["alice@example.com", "bob@example.com"]

with HawcxAgent.connect_by_agent_id(
    "research-u1",
    principal_allowlist=ALLOWED_USERS,
) as agent:

    # ─────────────────────────────────────────────────────────────────
    # Step 3: Construct HawcxTool instances.
    #
    # One HawcxTool per logical tool. All instances share the same
    # agent (one Assembler connection per process). Construction is
    # cheap — no IPC at this point.
    #
    # Key fields:
    #   provider  — §47.2 provider class. Routes the §47.8
    #               GetExternalCredential IPC to the correct sidecar
    #               (haap-nim-provider, haap-anthropic-provider, etc.).
    #   tool_id   — §47.4 tool identity binding. The sidecar refuses
    #               to disclose a credential unless the requesting
    #               tool_id matches the bound tool_id in the credential
    #               store. Two tools with different tool_ids cannot
    #               share credentials even within the same pipeline.
    #   endpoint  — Destination URL. The Assembler constructs the
    #               outbound HTTPS request; the Python process never
    #               sees the bearer token.
    #   action    — TBAC action list (Cedar policy evaluation context).
    # ─────────────────────────────────────────────────────────────────

    nim_search_tool = HawcxTool(
        name="nim_search",
        description=(
            "Search the organisation's private knowledge base via NVIDIA NIM. "
            "Use this when you need to find facts, recent documents, or technical "
            "references. Always supply the user_principal_id you were given."
        ),
        hawcx_agent=agent,
        provider="nim",                            # §47.2 — routes to haap-nim-provider sidecar
        tool_id="nim-search-v1",                   # §47.4 — credential binding key
        endpoint="https://api.nim.nvidia.com/v1/search",
        method="POST",
        action=["read"],                           # Cedar policy action
        args_schema=SearchInput,
    )

    docs_tool = HawcxTool(
        name="docs_reader",
        description=(
            "Retrieve a specific document from the internal document store by ID. "
            "Use this to pull the full text of a document whose ID you have found "
            "via nim_search. Always supply the user_principal_id you were given."
        ),
        hawcx_agent=agent,
        provider="generic-bearer",                 # §47.2 — generic bearer sidecar
        tool_id="docs-reader-v1",                  # §47.4 — separate credential from nim_search
        endpoint="https://docs.internal.example.com/v1/documents",
        method="GET",
        action=["read"],
        args_schema=DocsInput,
    )

    # ─────────────────────────────────────────────────────────────────
    # Step 4: Define CrewAI Agents.
    #
    # Each CrewAI Agent receives the relevant HawcxTool(s) in its
    # tools list. The LLM backing the agent sees only the tool's
    # name, description, and args_schema — never the provider keys,
    # HAAP session tokens, or IPC internals.
    # ─────────────────────────────────────────────────────────────────

    researcher = Agent(
        role="Research Analyst",
        goal=(
            "Find and retrieve the most relevant technical documents "
            "answering the user's question, using the NIM search tool "
            "and document retrieval tool."
        ),
        backstory=(
            "You are a meticulous research analyst with access to a private "
            "knowledge base. You always cite your sources by document ID."
        ),
        tools=[nim_search_tool, docs_tool],
        verbose=True,
        # The LLM powering this agent. Must be set per your CrewAI config.
        # e.g., llm="gpt-4o" or set OPENAI_API_KEY in environment.
    )

    summarizer = Agent(
        role="Technical Writer",
        goal="Synthesize research findings into a clear, concise summary.",
        backstory=(
            "You turn raw research into polished technical summaries. "
            "You do not call external tools; you work only from the "
            "documents provided to you by the Research Analyst."
        ),
        tools=[],    # no HAAP tools needed for summarization
        verbose=True,
    )

    # ─────────────────────────────────────────────────────────────────
    # Step 5: Define Tasks.
    #
    # The user_principal_id is injected into the task description so
    # the LLM learns to pass it through in every tool call. This is
    # the recommended multi-tenant pattern: the principal flows through
    # the agent context rather than being hardcoded in the tool.
    # ─────────────────────────────────────────────────────────────────

    user_id = "alice@example.com"   # from authenticated session — never from LLM output
    question = "What are the performance characteristics of the HAAP TQS pipeline?"

    research_task = Task(
        description=(
            f"Answer the following question using the nim_search and docs_reader tools.\n"
            f"Question: {question}\n\n"
            f"IMPORTANT: For every tool call, pass user_principal_id='{user_id}'. "
            f"Do not call any tool without this field."
        ),
        expected_output=(
            "A list of relevant document IDs and their key findings, "
            "with direct quotes where available."
        ),
        agent=researcher,
    )

    summarize_task = Task(
        description=(
            "Using the research findings above, write a 3-paragraph technical "
            "summary suitable for a developer audience. Include the document IDs "
            "as citations."
        ),
        expected_output="A concise 3-paragraph technical summary with citations.",
        agent=summarizer,
        context=[research_task],   # receives researcher's output as context
    )

    # ─────────────────────────────────────────────────────────────────
    # Step 6: Assemble and run the Crew.
    #
    # Process.sequential: tasks run in order; each task's output
    # becomes context for the next. Use Process.hierarchical for a
    # manager-agent architecture (CrewAI Enterprise).
    # ─────────────────────────────────────────────────────────────────

    crew = Crew(
        agents=[researcher, summarizer],
        tasks=[research_task, summarize_task],
        process=Process.sequential,
        verbose=True,
    )

    result = crew.kickoff()
    print(result)

# ── context manager __exit__ closes the Assembler IPC socket ─────────
# After the `with` block the connection is closed. Instantiate the
# agent at application startup and keep it open for the lifetime of
# the process; reconnecting per-request adds ~5 ms handshake latency.
```

---

## 8. Multi-Tenant Pattern

When one agent process serves many end-users, there are two patterns:

### A. Per-call principal via `args_schema` (recommended)

Declare `user_principal_id` in the tool's `args_schema`. The LLM supplies it on each call; the SDK enforces it against `principal_allowlist` before any IPC.

```python
# Shown in the example above — see SearchInput / DocsInput schemas.
```

### B. Per-user tool instance via `for_user`

For flows that materialize a dedicated tool per user (e.g., one `Crew` per user request):

```python
# Cheap — shares the underlying HawcxAgent (one IPC connection).
alice_search = nim_search_tool.for_user("alice@example.com")
bob_search   = nim_search_tool.for_user("bob@example.com")

# alice_search always calls invoke_for("alice@example.com", ...)
# bob_search always calls invoke_for("bob@example.com", ...)
```

---

## 9. Security Model

| Property | How it is achieved |
|---|---|
| **Credentials never reach the LLM process** | `HawcxTool._run` calls `HawcxAgent.invoke` over local UDS. The Assembler fetches provider credentials internally (§47.8 `GetExternalCredential`) and attaches them to the outbound HTTPS request. The credential value is never returned to Python. |
| **HAAP session keys never reach the LLM process** | All cryptography (`K_session_root`, `K_req`, `K_resp`) lives inside the Assembler process. The SDK exchanges only plaintext request bodies and decrypted response bodies over the IPC socket. |
| **LLM-supplied principals are sandboxed** | `principal_allowlist` is a closed, operator-controlled set validated synchronously at `HawcxAgent.connect()`. A compromised or hallucinating LLM cannot escalate to an out-of-list principal. |
| **Per-tool credential binding** | `tool_id` (§47.4) prevents one tool from borrowing another tool's credentials even within the same pipeline. |
| **IPC socket isolation** | Sockets are placed under `$XDG_RUNTIME_DIR/hawcx/` (Linux) — created 0o700 per UID by systemd. The SDK refuses to fall back to `/tmp/hawcx/` without an explicit `HAAP_SDK_ALLOW_TMP_IPC=1` opt-in. |

---

*Generated 2026-05-26. Source: `hawcx_agentic_sdk` `0.1.0-alpha.11`, HAAP CS v7.2.5.*
