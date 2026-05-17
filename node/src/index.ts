/**
 * `@hawcx/hawcx-haap` — customer SDK for the Hawcx Agent Authentication
 * Protocol (HAAP).
 *
 * Per CS v6.7.4 §39, Profile E uses a five-process customer-side pipeline
 * (Authenticator, TQS-precompute, TQS-jit, Assembler, Supervisor). This SDK
 * is the Node entry point: it connects to a customer-deployed
 * `haap-supervisor` via the Assembler's agent IPC socket and proxies tool
 * calls through it.
 *
 * The SDK does **not** spawn the supervisor — that's a separate operational
 * concern (Docker / systemd / SCM). Customers install the supervisor via the
 * `hx_agentic_sdk` release tarball or Docker image; this SDK connects to its
 * already-running Assembler over the agent socket.
 *
 * Prerequisites:
 *
 * - The 5-process pipeline must be running and the Assembler's agent socket
 *   reachable. Default path on Unix:
 *   `{ipc_dir}/{agent_id}/agent-assembler-{index}.sock`. On Windows:
 *   `\\\\.\\pipe\\haap-{agent_id}-agent-assembler-{index}`.
 * - The agent identity must be pre-provisioned via the Hawcx Admin Console
 *   (Console → CAA → Authenticator flow per CS §4.6.3) before the
 *   Authenticator can establish a session with the AS.
 *
 * Quick start:
 *
 *     import { HawcxAgent } from "@hawcx/hawcx-haap";
 *
 *     const agent = await HawcxAgent.connect(
 *       "/var/run/haap/research-u1/agent-assembler-0.sock",
 *     );
 *     try {
 *       const response = await agent.invoke({
 *         targetRsUrl: "https://api.example.com/search",
 *         httpMethod: "POST",
 *         headers: { "Content-Type": "application/json" },
 *         tool: "search",
 *         action: ["read"],
 *         body: Buffer.from('{"query": "agents"}'),
 *       });
 *     } finally {
 *       agent.close();
 *     }
 *
 * Per CS §39, the Node process never holds session keys (`response_key`,
 * `K_req`, `K_resp`). All cryptographic operations happen inside the
 * Assembler process; the SDK exchanges only plaintext request bodies and
 * decrypted response bodies over the local IPC socket.
 */

export { HawcxAgent, defaultEndpointFor } from "./agent";
export type { HawcxAgentInvokeOptions } from "./agent";
export {
  AssemblerClient,
  TokenTransport,
  encodeFrame,
  MSG_TOOL_CALL_REQUEST,
  MSG_TOOL_CALL_RESPONSE,
  MSG_REQUEST_REJECTED,
  MSG_CLARIFICATION_ANSWER,
  MSG_TYPE_HANDSHAKE,
  MAX_MESSAGE_SIZE,
} from "./ipc";
export type { ToolCallRequest, ToolCallResponse } from "./ipc";
export { HawcxError, IpcError, HandshakeError, RequestRejected } from "./errors";
