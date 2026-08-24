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

The build backend is [hatchling](https://hatch.pypa.io/latest/). The package itself is **pure Python** — there is no Rust source in this repo and no Python extension module. The platform-specific `hawcx-manager` binary is *staged as package data*, not compiled: the release workflow drops it into `src/hawcx_haap/_bin/` before each wheel build, and the custom hatchling hook in `python/hatch_build.py` force-includes that directory **only when it exists**.

```toml
# python/pyproject.toml (relevant section)
[build-system]
requires = ["hatchling>=1.21"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/hawcx_haap"]

# hatch_build.py force-includes src/hawcx_haap/_bin/ when the release workflow
# has staged a binary there. Absent it, the wheel is simply pure-Python.
[tool.hatch.build.targets.wheel.hooks.custom]
path = "hatch_build.py"
```

Consequences worth knowing:

- A dev / editable install needs **no Rust toolchain and no cargo registry access** — the hook no-ops and `get_binary_path()` raises at call time instead.
- The hook emits a `py3-none-any` wheel; the release workflow retags it to the real platform tag with `python -m wheel tags` afterwards.
- Build platform wheels with `python -m build --wheel`, **not** via sdist: the sdist deliberately excludes `src/hawcx_haap/_bin`.

> This section previously described [maturin](https://www.maturin.rs/) with `bindings = "bin"`. That was accurate before the alpha.13 packaging change and is not what the repo does today (verified 2026-08-22).

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

`get_binary_path()` raises `RuntimeError` if the binary is absent (e.g., installed from an sdist or an editable checkout, where nothing was staged into `_bin/`). The error message explains the local development workflow.

### Packages on PyPI

| Package | Purpose |
|---|---|
| `hawcx-haap` | Core IPC client + bundled `hawcx-manager` binary |
| `hawcx-crewai` | CrewAI `BaseTool` adapter (depends on `hawcx-haap`) |

### The `hawcx` CLI

`hawcx-haap` installs one console script, `hawcx` (`[project.scripts]` → `hawcx_haap.cli:main`):

| Subcommand | Purpose |
|---|---|
| `hawcx validate <template>` | Check a `hawcx/agent-template/v1` document; prints every error code at once |
| `hawcx extract --tools <mcp.json> \| --names ...` | Draft a template from an existing agent's tool list (output is a DRAFT) |
| `hawcx wrap <template> -o <out.py>` | Generate HAAP tool wrappers from a template |
| `hawcx init <template> -d <dir>` | Scaffold a whole agent: the generated tool module **plus** a `config.py` you own |
| `hawcx submit <template> --org <org>` | Push a validated template to the Admin Console as a draft |
| `hawcx bundle <project-dir>` | Pack a Python agent into one executable `.pyz` and print its `sha256` |

**Python only.** Node bundling is not yet available: `node/package.json` has no `bin` field and this SDK ships no Node CLI at all. A single-file `.mjs` entry (and later a Node SEA) is a separate increment; nothing half-built is shipped in its place.

#### `hawcx init` — the generated module and the config you own

`hawcx wrap` emits the tool module. Since 0.1.5 the Lane A core (`Caller`,
`Decision`, allow/deny classification) lives in the SDK too, which leaves
exactly one file per customer still hand-written: the deployment config — where
each MCP server is, what the downstream tool is called, which resource, which
provider, and which principals the agent may act for. `hawcx init` scaffolds it.

```bash
hawcx init agent-template.yaml -d ./myagent
# ./myagent/hawcx_tools.py: wrote 2 tool wrapper(s) from agent-template.yaml
# ./myagent/config.py: wrote config skeleton
```

| File | Owner | On re-run |
|---|---|---|
| `hawcx_tools.py` | `@generated` — do not edit | rewritten with `--force` |
| `config.py` | **the customer's** — edit and keep | **kept**, always; `--force` does not reach it |

The two files have opposite ownership, and one `--force` cannot serve both —
which is why this is a separate subcommand rather than a `wrap --config` flag.
A flag passed to regenerate the module would eventually overwrite a config
someone spent a day filling in. There is no flag to overwrite `config.py`;
delete it yourself if you want a fresh one.

**An unfilled value fails loudly rather than looking configured.** Every
deployment-specific value is emitted as `FILL_ME` and the file ends in
`require_filled(...)`, so an untouched config raises on **import** and names
every gap in one message:

```
ValueError: 8 unfilled config value(s): PROVIDER, PRINCIPAL_ALLOWLIST,
TOOLS['o365.mail.read'].url, TOOLS['o365.mail.read'].name, ...
```

Every path at once, not one per traceback. A commented placeholder
(`# TODO: your RS URL`) reads as considered, survives review, and arrives at
the Assembler as a real target; this cannot get past the import.

**`PRINCIPAL_ALLOWLIST` has no default**, and a test pins it that way. It is the
fail-closed gate on `acting_for_user`, so a default would be a default answer to
which users the agent may act for. `[]` is a real answer — "forbid runtime
principal switching entirely" — and has to be a human's choice.

Not scaffolded, deliberately: the HTTP method (MCP `tools/call` over Streamable
HTTP is POST and `Caller.invoke_kwargs` sets it) and per-tool providers (a
`Caller` carries one `provider`; an agent spanning two builds two `Caller`s).
The generated config imports only `hawcx_haap` and stays pure-Python, so an
agent carrying it still bundles with `hawcx bundle` below — a zipapp cannot
carry native extensions.

#### `hawcx bundle` — the measurable exec target

HAAP's code-identity gate measures the bytes of the exact file the supervisor `exec`s and requires that digest to be listed in the org-signed class manifest's `allowed_workload_selectors`. The supervisor's agent config has **no args field**, so it cannot hand a script path to an interpreter — which means an `agent_bin` pointing at `/usr/local/bin/python` measures CPython and proves nothing about the agent. The exec target has to *be* the agent program. `hawcx bundle` produces that file.

```bash
hawcx bundle ./my_agent -o my-agent.pyz
# sha256:9f2c...e41b          <- stdout: the digest, and nothing else
#   my-agent.pyz (48213 bytes)   <- stderr: what to do with it
```

The mechanism is the standard library's [`zipapp`](https://docs.python.org/3/library/zipapp.html) — no new dependency, no vendored packer. Dependencies are staged with `pip install --target` (from `<project>/requirements.txt` by default, or `-r`), the project is copied in alongside them, and the archive is written with a `#!/usr/bin/env python3` shebang and the executable bit.

| Flag | Meaning |
|---|---|
| `-o, --output` | Output path (default: `<dirname>.pyz` in the cwd) |
| `-m, --main` | Entry point as `package.module:function`; omit when the project has a `__main__.py` |
| `-r, --requirement` | Requirements file to vendor (default: `<project>/requirements.txt` if present) |
| `--force` | Overwrite an existing output file — refused without it, same as `hawcx wrap` |

**Native extension modules are refused.** If any `.so`, `.pyd`, or `.dylib` lands in the staged tree, the build fails and names the offending package(s). This is not a missing feature: CPython cannot import an extension module out of a zip, so a runtime that appears to support it does so by unpacking to a temp directory — at which point the bytes HAAP measured are no longer the bytes that execute. The documented escape hatch is **PyInstaller**: a one-file PyInstaller binary is also a single measurable exec target. `hawcx bundle` does not drive PyInstaller; run it yourself and hash the result.

In practice this rules out a large slice of the agent ecosystem today — anything pulling in `pydantic` (and therefore `pydantic-core`), for instance, which includes CrewAI-based agents. Treat the refusal as the honest signal it is.

**Digest stability.** Two builds of unchanged input on one machine produce byte-identical output: staged mtimes are normalised, byte-compilation is disabled (`--no-compile`), and `zipapp` walks the tree in sorted order. Full **cross-machine** reproducibility is **not** claimed — `pip` resolves wheels for the running interpreter and platform, and zip stores timestamps in local time. Build on the platform you deploy to. Cross-machine reproducibility is roadmap.

**Named residual.** The interpreter the shebang points at is *not* measured; it is the same trust class as the system libraries the agent links. What is measured is the whole agent program plus its vendored dependencies.

Windows Lane A bundles are out of scope for v0 — the shebang mechanism is Unix, and the attach path is Unix-only today.

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
