# hawcx_agentic_sdk — Claude Code Context

This is the **Hawcx Agentic Authentication SDK**. The repo is a Cargo
workspace plus a sibling Node package. Read this before reasoning about
how the SDK fits into the broader Hawcx HAAP stack.

## What this repo ships

| Layer | Path | What it is |
|---|---|---|
| Rust workspace | `crates/` | The 5-binary `haap-supervisor` pipeline (Authenticator / TQS-precompute / TQS-jit / Assembler / Supervisor) that runs **customer-side**, co-located with the agent process. |
| Node SDK | `node/` (npm package `@hawcx/hawcx-haap`) | Thin **local Unix-domain-socket IPC client** that agent code (typically Node.js) imports to talk to the local Assembler binary. **Not** a network client. |

## Critical architectural facts (often misunderstood)

1. **The Node SDK does NOT make network calls.** It connects to a local
   Unix socket and speaks a framed binary protocol
   (`[u32 BE len][u8 type][JSON payload]`, 64 KiB cap) to the local
   Assembler binary. All "network" happens inside the supervisor
   pipeline, downstream of the SDK.

2. **The 5-binary supervisor pipeline is a separate deployment unit**
   from any agent. In K8s, it's a sidecar Pod sharing an `emptyDir` UDS
   with the agent container — analogous to how the CAA runs two
   containers in one Pod with a shared socket.

3. **The CAA is upstream of the SDK request path, NOT in it.** The
   Customer Admin Agent provisions agent identity via Admin Console and
   writes `SubstrateMaterial` to customer Redis. The supervisor reads
   that material on startup. After that, agent requests flow
   `agent code → SDK → Assembler UDS → TQS/Authenticator → RS`. The CAA
   is offline-path infrastructure, not a peer of the running agent.

## Node SDK API surface

```js
HawcxAgent.connect(endpoint) -> Promise<HawcxAgent>
HawcxAgent.connectByAgentId(agentId) -> Promise<HawcxAgent>
agent.invoke({ targetRsUrl, httpMethod, tool, action, body, ... }) -> Promise<ToolCallResponse>
agent.invokeFor(userPrincipalId, opts) -> Promise<ToolCallResponse>
agent.sendClarificationAnswer({...}) -> Promise<void>
agent.close()
defaultEndpointFor(agentId) -> string
```

Errors: `HawcxError` / `IpcError` / `HandshakeError` / `RequestRejected`.

## Publishing status (as of 2026-05-20)

`@hawcx/hawcx-haap` is **NOT yet published** to npm — registry returns
404. Consumers that need it today must:
- Clone this repo
- Build `node/`
- Reference it via `package.json` "file:" or vendor it

The demo at `/Users/vishwa/workspace/hawcx_agentic_sdk_demo/` uses the
vendor approach. When publishing happens, that demo should flip its
dependency.

## The full HAAP stack (where this repo fits)

| Repo | Path | Role |
|---|---|---|
| `hawcx_agentic_sdk` (this) | `/Users/vishwa/workspace/hawcx_agentic_sdk` | The SDK + supervisor pipeline (customer-side, in-Pod with agent) |
| `hawcx_agentic_sdk_demo` | `/Users/vishwa/workspace/hawcx_agentic_sdk_demo` | Reference demo (Node/Express, mock-mode by default) |
| `hx_agent_client_admin_service` (CAA) | `/Users/vishwa/workspace/hx_agent_client_admin_service` | Customer Admin Agent — provisions identity, writes substrate to Redis. Two-binary (Orchestrator + Authenticator) with mandatory trust boundary. |
| `hx_agent_auth_service` (AS) | `/Users/vishwa/workspace/hx_agent_auth_service` | Hawcx-SaaS-side auth server. Implements HAAP §4.2.1 X3DH cascade. Live at `stage-auth-server.hawcx.com`. |
| `hx_labs` | `/Users/vishwa/workspace/hx_labs` | Protocol library crates (`haap-core`, `haap-crypto`, `haap-as-client`, etc.) consumed by everyone. |
| `hx_iac` | `/Users/vishwa/workspace/hx_iac` | All GCP infrastructure as Terraform. |
| `hx_agent_admin_console` | `/Users/vishwa/workspace/hx_agent_admin_console` | Admin console + Postgres migration owner. |

## Stage-client cluster (where this SDK would deploy)

Vishwa stood up a new GCP project `hawcx-stage-client` (project number
`612575354704`) on 2026-05-20 with a dedicated GKE Autopilot cluster
`hx-stage-client-gke` in `us-east1`. The CAA is deployed there in
namespace `hx-agent-client-admin-service`. A namespace called
`hx-agentic-sdk-demo` is reserved for SDK-using agent demos.

For a **full integration test** of an SDK-using agent in stage-client,
all of this needs to be true:

1. Package the 5-binary supervisor pipeline as a K8s sidecar Docker image
2. Provision agent identity via Admin Console (CAA's
   `POST /v1/admin/sdk/enroll` flow — uses OTRC + customer's `IK_c`)
3. Wire customer Redis (`HAAP_CUSTOMER_REDIS_URL` → the Memorystore
   in stage-client at `10.30.0.3:6379`)
4. Seal the identity bundle (`HAAP_PINNED_IK_SP`)
5. Have the AS's `/v3/register_agent` path accept the supervisor's
   identity assertion

This is a **week-plus separate workstream** from the SDK + demo work.
For now, the demo runs in **mock mode** — in-process MockAssembler
speaking the real wire protocol — proving SDK wiring without the
supervisor.

## HAAP spec

The Canonical Specification lives in `hx_labs/tools/spec/canonical/`
(currently at v7.2.0). Cross-references in this repo's source code use
section numbers from that spec.

## What NOT to assume

- Don't assume the SDK speaks gRPC, HTTP, or any network protocol. It's
  local UDS only.
- Don't assume the SDK talks to the CAA. They never speak directly.
- Don't assume `@hawcx/hawcx-haap` is on npm. It isn't yet.
- Don't conflate the SDK (this repo) with the CAA. Different repos,
  different binaries, different deployment shapes.
