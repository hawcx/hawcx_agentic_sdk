# @hawcx/hawcx-haap

Node.js customer SDK for the [Hawcx Agent Authentication Protocol (HAAP)][cs],
per [Canonical Specification v7.2.0][cs] §39 (Profile E).

> **Status**: alpha (0.1.0-alpha.1). Public API may change before 1.0.

## What this SDK does

`@hawcx/hawcx-haap` is the **agent-side IPC client** for the HAAP Profile E
pipeline. You construct a `HawcxAgent` against the local Assembler socket,
then call `invoke(...)` to issue authenticated tool calls. The Assembler
attaches the TBAC token, encrypts the body, dispatches the outbound HTTPS
request to the Resource Server, decrypts the response, and returns it.

Per CS §39, the Node process **never** holds session keys (`response_key`,
`K_req`, `K_resp`) — all cryptographic operations happen inside the
Assembler process. The SDK and Assembler communicate over a Unix domain
socket (Linux/macOS) or Named Pipe (Windows) with `SO_PEERCRED` / kernel
DACL enforcement at connect time.

## What this SDK does NOT do

This SDK does **not** spawn or manage the `haap-supervisor` process. The
supervisor runs as a long-lived service (Docker / systemd / Windows SCM)
that you deploy separately using the
[hx_agentic_sdk release artifacts](../README.md). The 6-process pipeline
(Authenticator, TQS-precompute, TQS-jit, Assembler, External Identity
Broker, Supervisor — per HAAP CS v7.2.0 §45.2) needs to be already
running before you construct `HawcxAgent`.

## Prerequisites

1. **Supervisor running.** Install the `hx_agentic_sdk` release tarball or
   Docker image; run `haap-supervisor` with a valid `config.toml` (see
   [`docs/SUPERVISOR_OPS.md`](../docs/SUPERVISOR_OPS.md)).

2. **Agent identity provisioned.** The Authenticator's per-agent `IK_i` must
   be pre-provisioned through the Hawcx Admin Console → CAA → Authenticator
   flow (CS §4.6.3). This SDK does not enroll agents.

3. **Agent socket reachable.** The Assembler binds an agent socket at:
   - **Unix:** `{ipc_dir}/{agent_id}/agent-assembler-{index}.sock`
   - **Windows:** `\\.\pipe\haap-{agent_id}-agent-assembler-{index}`

## Install

```bash
npm install @hawcx/hawcx-haap
# or: pnpm add @hawcx/hawcx-haap
# or: yarn add @hawcx/hawcx-haap
```

Single TypeScript-compiled CommonJS package. Supports Node ≥ 18 on Linux,
macOS, and Windows. No native build required.

## Usage

```typescript
import { Buffer } from "node:buffer";
import { HawcxAgent } from "@hawcx/hawcx-haap";

const agent = await HawcxAgent.connect(
  "/var/run/haap/research-u1/agent-assembler-0.sock",
);
try {
  const response = await agent.invoke({
    targetRsUrl: "https://api.example.com/search",
    httpMethod: "POST",
    headers: { "Content-Type": "application/json" },
    tool: "search",
    action: ["read"],
    body: Buffer.from('{"query": "agent authentication"}'),
  });
  console.log(response.httpStatus);     // 200
  console.log(response.headers);        // { "Content-Type": "...", ... }
  console.log(response.body.toString()); // decrypted response
} finally {
  agent.close();
}
```

Resolve the socket path from an agent id:

```typescript
const agent = await HawcxAgent.connectByAgentId("research-u1");
```

### Error handling

```typescript
import {
  HawcxAgent,
  HandshakeError,
  IpcError,
  RequestRejected,
} from "@hawcx/hawcx-haap";

try {
  const agent = await HawcxAgent.connect(socketPath);
  try {
    const response = await agent.invoke(...);
  } finally {
    agent.close();
  }
} catch (err) {
  if (err instanceof HandshakeError) {
    // Assembler's IPC SDK major version doesn't match ours.
  } else if (err instanceof RequestRejected) {
    // Assembler rejected (policy / quota / allowlist).
    console.log(`rejected: ${err.reason}`);
  } else if (err instanceof IpcError) {
    // Connection refused, EOF, framing error, etc.
  } else {
    throw err;
  }
}
```

### Token transport (HTTP header vs. MCP meta)

Per CS §34:

- `TokenTransport.HttpHeader` (Assembler default): `Authorization: HAAP <token>`
- `TokenTransport.McpMeta`: MCP `params._meta["haap/tbac"].token`

```typescript
import { TokenTransport } from "@hawcx/hawcx-haap";

await agent.invoke({
  targetRsUrl: "https://mcp-gateway.example.com/rpc",
  httpMethod: "POST",
  tool: "search",
  body: mcpJsonrpcRequestBody,
  transport: TokenTransport.McpMeta,
});
```

## Wire protocol

`@hawcx/hawcx-haap` speaks the IPC wire protocol defined in
[`hx_labs/crates/haap-ipc`](../README.md). Each frame is:

```
[msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]
```

Max frame size: 64 KiB. Agent-side messages:

| msg_type | Direction         | Name                  | Payload encoding |
| -------- | ----------------- | --------------------- | ---------------- |
| `0x00`   | Agent ↔ Assembler | `IpcHandshake`        | Binary (9 bytes) |
| `0x52`   | Agent → Assembler | `ToolCallRequest`     | JSON             |
| `0x53`   | Assembler → Agent | `ToolCallResponse`    | JSON             |
| `0x54`   | Assembler → Agent | `RequestRejected`     | JSON             |
| `0x61`   | Agent → Assembler | `ClarificationAnswer` | JSON             |

Connecting performs the version handshake (`0x00`); subsequent calls use the
JSON-payload framing. Windows Named Pipes are supported transparently via
Node's `net.connect({ path })`.

## Development

```bash
cd hx_agentic_sdk/node
npm install
npm test                     # vitest against mock Assembler
npm run typecheck            # tsc --noEmit
npm run build                # emit dist/
```

Tests run against an in-process mock Assembler — no real binaries needed.
End-to-end validation against the real 6-process pipeline depends on
alpha-2 closure of the RSV cascade adapter; see the closure report at
[`docs/priority2_foundation_closure_2026-05-17.md`](../docs/priority2_foundation_closure_2026-05-17.md).

## License

Apache-2.0. See the top-level [LICENSE](../LICENSE).

[cs]: https://github.com/hawcx/hx_agentic_sdk
