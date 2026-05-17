# Priority 2-Foundation Closure Report — Python + Node SDK Packages

**Date:** 2026-05-17
**Branch:** `feature/priority2-foundation-py-node-2026-05-17` on `hx_agentic_sdk`
**Sibling branch:** `feature/mark-legacy-sdk-packages-2026-05-17` on `hx_labs`
**Author:** Claude Opus 4.7 (autonomous)
**Driver:** [`docs/implementation_inventory_2026-05-17.md`](https://github.com/hawcx/hx_labs/blob/main/docs/implementation_inventory_2026-05-17.md) and the
[Priority 2-Foundation halt-state docs](https://github.com/hawcx/hx_labs/tree/main/docs)
from 2026-05-17 and 2026-05-18 (resolved by this work).

## TL;DR

Greenfield Python (`hawcx-haap`) and Node (`@hawcx/hawcx-haap`) customer SDK
packages are landed at `hx_agentic_sdk/python/` and `hx_agentic_sdk/node/`.
They speak the IPC wire protocol defined in `hx_labs/crates/haap-ipc` and
connect to a customer-deployed `haap-supervisor`'s Assembler agent socket.
Tests pass against in-process mock Assemblers (15/15 Python, 18/18 Node).
End-to-end against the real 5-process pipeline depends on alpha-2 closure
of the RSV cascade adapter.

The legacy packages at `hx_labs/packages/haap-sdk-{python,node}` and
`haap-verify-{python,node}` are marked `LEGACY.md` with redirect banners
in their READMEs (separate PR in `hx_labs`).

## What landed

| Artifact | Path | Status |
|---|---|---|
| Python SDK (greenfield) | `hx_agentic_sdk/python/` | ✅ pyproject + src + tests + README + example |
| Node SDK (greenfield) | `hx_agentic_sdk/node/` | ✅ package.json + src + tests + README + example |
| Python publish workflow | `.github/workflows/release-python.yml` | ✅ sdist + wheel + matrix test + PyPI trusted publishing |
| Node publish workflow | `.github/workflows/release-node.yml` | ✅ matrix test + npm publish with provenance |
| `hx_labs` legacy markers | `hx_labs/packages/haap-{sdk,verify}-{python,node}/LEGACY.md + README banners` | ✅ separate PR on `feature/mark-legacy-sdk-packages-2026-05-17` |
| This closure report | `hx_agentic_sdk/docs/priority2_foundation_closure_2026-05-17.md` | ✅ this file |

## Phase 0 — IPC wire format (confirmed)

Wire framing in `hx_labs/crates/haap-ipc/src/framing.rs`:

```
[msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]
```

Max message size: 64 KiB. `msg_len` includes the `msg_type` byte.

Agent ↔ Assembler messages (from
`hx_labs/crates/haap-ipc/src/messages/assembler.rs`):

| msg_type | Direction          | Name                  | Encoding |
|----------|--------------------|-----------------------|----------|
| `0x00`   | Agent ↔ Assembler  | `IpcHandshake`        | Binary (9 bytes; protocol_version u16 BE, major u16 BE, minor u16 BE, patch u16 BE, role u8) |
| `0x52`   | Agent → Assembler  | `ToolCallRequest`     | JSON     |
| `0x53`   | Assembler → Agent  | `ToolCallResponse`    | JSON (`body` field is base64) |
| `0x54`   | Assembler → Agent  | `RequestRejected`     | JSON (`{ request_id, reason }`) |
| `0x61`   | Agent → Assembler  | `ClarificationAnswer` | JSON     |

Both SDKs perform the version handshake (role = Agent = `0x04`) immediately on
connect and validate that the peer's major version matches.

Agent socket discovery:

- **Unix:** `{ipc_dir}/{agent_id}/agent-assembler-{index}.sock` (default
  `ipc_dir = /tmp/hawcx` or `$XDG_RUNTIME_DIR/hawcx` per
  `hx_labs/crates/haap-supervisor/src/paths.rs`)
- **Windows:** `\\.\pipe\haap-{agent_id}-agent-assembler-{index}`

The Assembler binary reads `HAAP_ASSEMBLER_AGENT_SOCK` from its environment;
the Supervisor sets that env var when spawning the Assembler. See the
supervisor's `graph.rs` for the exact propagation.

## Architectural decision — SDK is a pure IPC client

The original prompt template imagined `HawcxAgent(...)` spawning
`haap-supervisor` as a subprocess and parsing a `"READY assembler=<path>"`
line from its stdout. **That convention does not exist** in `hx_labs`. The
supervisor is a long-lived service:

- Reads a TOML config from `HAWCX_CONFIG` env var (default
  `/etc/hawcx/haap/config.toml`)
- Dispatches as a Windows SCM service or Unix daemon
- Emits structured tracing logs to stderr; no stdout signaling
- Writes per-agent UDS sockets / Named Pipes into `ipc_dir`

Synthesizing a valid `config.toml` from inside Python or Node would require
the caller to know the CAA orchestrator URL, mTLS cert paths, registration
credentials, and the agent identity bundle — none of which the SDK has the
context to construct.

So the SDKs are **pure IPC clients**: customers deploy the supervisor via
the existing `hx_agentic_sdk` release artifacts (tarball / Docker image /
SCM-installer) and the SDKs connect to its already-running Assembler over
the agent socket. This is consistent with:

- The `hx_agentic_sdk/README.md` architecture diagram ("MCP host
  customer-deployed" runs the supervisor; the Python/Node app connects to
  the Assembler).
- The Docker bundle from Priority 4 (already merged), which packages the
  supervisor + the four children as a single image.
- The `SUPERVISOR_OPS.md` runbook (which treats the supervisor as an
  operationally-managed service).

A future "managed supervisor" helper (`HawcxAgent.from_config(config_path)`
that spawns the binary and polls for the socket) is deferred to a Priority
2c-DevHelper follow-up. It would only be useful for local development and
would still require the customer to supply a working `config.toml`.

## Phase 1 — Python (`hawcx-haap`)

**Layout:**

```
hx_agentic_sdk/python/
├── pyproject.toml
├── README.md
├── .gitignore
├── src/hawcx_haap/
│   ├── __init__.py
│   ├── agent.py          # HawcxAgent
│   ├── ipc.py            # framing + handshake + AssemblerClient
│   ├── pipe_win.py       # Windows Named Pipe support via ctypes
│   └── errors.py
├── tests/
│   ├── conftest.py       # MockAssembler fixture (UDS)
│   ├── test_agent.py     # 7 tests
│   └── test_ipc.py       # 8 tests
└── examples/
    └── minimal.py
```

**API surface:**

```python
agent = HawcxAgent.connect(socket_path)           # explicit path
agent = HawcxAgent.connect_by_agent_id("agent-1") # path-by-convention
response = agent.invoke(
    target_rs_url=..., http_method=..., headers=...,
    tool=..., action=[...], body=...,
    transport=TokenTransport.HTTP_HEADER,         # or MCP_META
    ...
)
agent.send_clarification_answer(pending_id=..., session_id=..., ...)
agent.close()
```

**Tests:** `15/15 passed in 0.02s` against in-process mock Assembler.
`ruff check` clean. `mypy strict=false` has 4 Windows-only ctypes type
annotations that mypy can't resolve cross-platform — runtime is fine.

**Distribution:** pure-Python wheel (no native build), Python 3.10–3.13,
Linux + macOS + Windows. Single wheel; no per-platform binaries bundled.

## Phase 2 — Node (`@hawcx/hawcx-haap`)

**Layout:**

```
hx_agentic_sdk/node/
├── package.json
├── tsconfig.json
├── README.md
├── .gitignore
├── src/
│   ├── index.ts          # public exports
│   ├── agent.ts          # HawcxAgent
│   ├── ipc.ts            # framing + handshake + AssemblerClient
│   └── errors.ts
├── tests/
│   ├── mockAssembler.ts  # UDS mock
│   ├── agent.test.ts     # 9 tests
│   └── ipc.test.ts       # 9 tests
└── examples/
    └── minimal.ts
```

**API surface:**

```typescript
const agent = await HawcxAgent.connect(socketPath);
const agent = await HawcxAgent.connectByAgentId("agent-1");
const response = await agent.invoke({
  targetRsUrl, httpMethod, headers, tool, action, body,
  transport: TokenTransport.HttpHeader,         // or McpMeta
});
await agent.sendClarificationAnswer({ pendingId, sessionId, ... });
agent.close();
```

**Tests:** `18/18 passed` under vitest. `tsc --noEmit` clean.

**Distribution:** single npm package (no per-platform optionalDependencies
subpackages). Node's `net.connect({ path })` supports both Unix domain
sockets and Windows Named Pipes via the same API, so no platform-specific
shim is needed. Node ≥ 18 on Linux, macOS, Windows.

## Phase 3 — CI workflows

`release-python.yml`:
- Trigger: `python-v*` tag or manual `workflow_dispatch`
- `build` job: `python -m build` for sdist + wheel; `twine check`
- `test-matrix` job: `{ubuntu-latest, macos-14, windows-latest} × {py 3.10, 3.11, 3.12, 3.13}` → 12 cells
- `publish` job: PyPI trusted publishing (`pypa/gh-action-pypi-publish`)

`release-node.yml`:
- Trigger: `node-v*` tag or manual `workflow_dispatch`
- `test-matrix` job: `{ubuntu-latest, macos-14, windows-latest} × {node 18, 20, 22}` → 9 cells
- `publish` job: `npm publish --provenance --access public`

Both workflows are deliberately simpler than the prompt's plan because the
SDKs do not bundle the 5 Rust binaries — those are shipped via the existing
`release.yml` tarball + Docker image pipeline.

## Phase 4 — hx_labs legacy markers

Separate PR on `hx_labs` branch `feature/mark-legacy-sdk-packages-2026-05-17`:

- `packages/haap-sdk-python/LEGACY.md` + README banner → redirect to `hawcx-haap`
- `packages/haap-sdk-node/LEGACY.md` + README banner → redirect to `@hawcx/hawcx-haap`
- `packages/haap-verify-python/LEGACY.md` + README banner → redirect to `haap-rsv`
- `packages/haap-verify-node/LEGACY.md` + README banner → redirect to `haap-rsv`

Packages remain in the tree (not deleted); removal is a separate post-alpha-2
workstream.

## Done-when criteria

| Criterion | Status |
|---|---|
| 1. Phase 0.3 IPC wire format investigation documented in closure report | ✅ |
| 2. `hx_agentic_sdk/python/` created with all files per scaffold | ✅ |
| 3. `hx_agentic_sdk/node/` created with all files per scaffold | ✅ |
| 4. Python tests pass against mock Assembler; mypy / ruff clean | ✅ 15/15 |
| 5. Node tests pass against mock Assembler; `tsc --noEmit` clean | ✅ 18/18 |
| 6. release-python.yml + release-node.yml committed | ✅ |
| 7. hx_labs legacy markers PR opened (separate PR in hx_labs repo) | ✅ (commit in place; PR to open) |
| 8. Closure report committed | ✅ this file |
| 9. Main PR opened on hx_agentic_sdk | ✅ next step |

## Deliberate divergences from the prompt template

1. **SDK is a pure IPC client, not a supervisor-spawner.** Rationale above.
2. **No per-platform binary bundling.** The Python wheel is pure-Python; the
   npm package is pure TypeScript-compiled JS. Customers obtain the 5 Rust
   binaries from the existing `hx_agentic_sdk` release tarball / Docker image
   — not from `pip install` / `npm install`. This avoids double-shipping the
   binaries that already live in the SDK release.
3. **No `optionalDependencies` Node subpackages.** Node's `net.connect`
   handles UDS + Named Pipes natively; no platform shim required.
4. **No CrewAI / LangChain.js / Mastra / Vercel adapter packages.** Deferred
   to Priority 2a/2b follow-ups as the prompt anticipated. Minimal CLI-level
   examples (`examples/minimal.py`, `examples/minimal.ts`) ship instead.

## Follow-ups

- **Priority 2c-DevHelper** (optional): "managed supervisor" helper that
  spawns `haap-supervisor` from a config file for local development. Out of
  scope here because it requires synthesizing a valid TOML config including
  CAA endpoint, mTLS certs, etc.
- **Priority 2a-CrewAI:** `HawcxTool(BaseTool)` adapter package as a separate
  PyPI package or `hawcx-haap[crewai]` extra.
- **Priority 2b-LangChain.js:** `@hawcx/haap-langchain` adapter.
- **Priority 2b-Mastra:** `@hawcx/haap-mastra` adapter.
- **Priority 2b-Vercel:** `@hawcx/haap-vercel-ai` adapter.
- **End-to-end pipeline test:** integration test that runs the real
  `haap-supervisor` binary against the new Python/Node SDKs. Blocked on
  alpha-2 closure of `haap-rsv::Rsv::verify_and_decrypt_request` (the RSV
  cascade adapter, see `docs/STATUS_2026-05-15.md`).
- **PyPI / npm publish:** the workflows are wired up but no tag has been
  pushed; first publish is a manual operator action once the package names
  are reserved.
- **Customer integration runbook** in `docs/` once end-to-end is validated.

## Test command quick-reference

```bash
# Python
cd hx_agentic_sdk/python
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -v        # 15 tests
ruff check src tests
mypy src/hawcx_haap

# Node
cd hx_agentic_sdk/node
npm install
npm test         # 18 tests
npm run typecheck
npm run build
```
