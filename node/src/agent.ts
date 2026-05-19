/**
 * `HawcxAgent` — the customer-facing entry point.
 *
 * Thin ergonomic wrapper around `AssemblerClient`. Takes a socket path to an
 * already-running Assembler agent endpoint, performs the IPC handshake, and
 * exposes `invoke` for sending tool calls.
 *
 * Per CS v6.7.4 §39, the SDK process never sees session keys — the Assembler
 * handles all crypto. The SDK only carries plaintext request bodies inbound
 * and decrypted response bodies outbound, both over the local IPC channel.
 *
 * See the package-level README for the prerequisites (supervisor running,
 * agent identity provisioned via CAA).
 */

import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import * as process from "node:process";

import {
  AssemblerClient,
  TokenTransport,
  type ToolCallResponse,
} from "./ipc";

export interface HawcxAgentInvokeOptions {
  targetRsUrl: string;
  httpMethod?: string;
  headers?: Record<string, string>;
  tool?: string;
  action?: readonly string[];
  resource?: string;
  constraints?: Record<string, unknown>;
  body?: Buffer | null;
  claimedIntentHash?: string;
  toolArguments?: unknown;
  contentType?: string;
  transport?: TokenTransport;
  requestId?: string;
  /**
   * Optional runtime principal — the human user on whose behalf this
   * single tool call is made (CS v6.9.0 line 163). When set, the
   * Assembler projects this into `scope_json.user_principal_id` on
   * the minted token; the gateway's Cedar policy can then enforce
   * `context.user_principal_id == resource.owner_user_id`. The
   * agent's pinned `subject_user_id` (set at enrollment) is not
   * modified — only per-call scope_json metadata.
   *
   * Use {@link HawcxAgent.invokeFor} for the sugar form.
   */
  actingForUser?: string;
}

function defaultIpcDir(): string {
  if (process.platform === "win32") {
    // Windows pipes are in the kernel namespace; ipc_dir is unused.
    return "";
  }
  const xdgRuntime = process.env.XDG_RUNTIME_DIR;
  if (xdgRuntime) return path.join(xdgRuntime, "hawcx");
  return path.join(os.tmpdir(), "hawcx");
}

/**
 * Compute the conventional Assembler agent-socket path for an agent id.
 *
 * - **Unix:** `{ipc_dir}/{agentId}/agent-assembler-{index}.sock`
 * - **Windows:** `\\\\.\\pipe\\haap-{agentId}-agent-assembler-{index}`
 */
export function defaultEndpointFor(
  agentId: string,
  options: { index?: number; ipcDir?: string } = {},
): string {
  const index = options.index ?? 0;
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\haap-${agentId}-agent-assembler-${index}`;
  }
  const dir = options.ipcDir ?? defaultIpcDir();
  return path.join(dir, agentId, `agent-assembler-${index}.sock`);
}

/**
 * High-level HAAP agent client. Connect once, invoke many times, close.
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
 * Not thread-safe; for concurrent use, wrap in a queue or open multiple
 * agents.
 */
export class HawcxAgent {
  private constructor(private client: AssemblerClient | null) {}

  /**
   * Open the agent IPC socket at `endpoint` and complete the version handshake.
   *
   * On Unix, `endpoint` is a filesystem path. On Windows, it's a Named Pipe
   * path (`\\\\.\\pipe\\haap-<agent_id>-agent-assembler-<index>`).
   */
  static async connect(
    endpoint: string,
    options: { timeoutMs?: number } = {},
  ): Promise<HawcxAgent> {
    const client = await AssemblerClient.connect(endpoint, options);
    return new HawcxAgent(client);
  }

  /**
   * Resolve the conventional Assembler-agent endpoint for an agent id, then
   * `connect`.
   */
  static connectByAgentId(
    agentId: string,
    options: { index?: number; ipcDir?: string; timeoutMs?: number } = {},
  ): Promise<HawcxAgent> {
    return HawcxAgent.connect(
      defaultEndpointFor(agentId, options),
      options,
    );
  }

  /**
   * Profile E tool call.
   *
   * Forwards a `ToolCallRequest` to the Assembler and returns the decrypted
   * `ToolCallResponse`. Throws `RequestRejected` if the Assembler rejects.
   *
   * Parameters mirror the fields of `haap_ipc::messages::assembler::
   * ToolCallRequest`. `body` maps to the wire field `plaintext_request_body`.
   */
  async invoke(opts: HawcxAgentInvokeOptions): Promise<ToolCallResponse> {
    if (!this.client) throw new Error("agent already closed");
    const requestId = opts.requestId ?? `req-${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    return this.client.invoke({
      requestId,
      targetRsUrl: opts.targetRsUrl,
      httpMethod: (opts.httpMethod ?? "POST").toUpperCase(),
      headers: opts.headers,
      tool: opts.tool ?? "",
      action: opts.action,
      resource: opts.resource,
      constraints: opts.constraints,
      body: opts.body,
      claimedIntentHash: opts.claimedIntentHash,
      toolArguments: opts.toolArguments,
      contentType: opts.contentType,
      transport: opts.transport,
      actingForUser: opts.actingForUser,
    });
  }

  /**
   * Sugar for {@link invoke} with a required `actingForUser`.
   *
   * `agent.invokeFor("alice", { targetRsUrl: ... })` is equivalent to
   * `agent.invoke({ actingForUser: "alice", targetRsUrl: ... })`. The
   * positional principal makes the per-call identity axis visually
   * load-bearing at call sites that fan out to many users.
   *
   * Throws if `userPrincipalId` is the empty string (a missing
   * principal is most likely a caller bug; use plain `invoke()` if
   * "no principal" is the intended semantic).
   */
  async invokeFor(
    userPrincipalId: string,
    opts: HawcxAgentInvokeOptions,
  ): Promise<ToolCallResponse> {
    if (!userPrincipalId) {
      throw new Error(
        "invokeFor requires a non-empty userPrincipalId; " +
          "use invoke() without actingForUser for unprincipled calls",
      );
    }
    return this.invoke({ ...opts, actingForUser: userPrincipalId });
  }

  /**
   * Profile E first hop: forward a clarification answer to the Assembler.
   */
  async sendClarificationAnswer(args: {
    pendingId: string;
    sessionId: number | bigint;
    answerIndex?: number;
    answerText?: string;
  }): Promise<void> {
    if (!this.client) throw new Error("agent already closed");
    await this.client.sendClarificationAnswer(args);
  }

  /** Close the IPC connection. Idempotent. */
  close(): void {
    if (this.client) {
      this.client.close();
      this.client = null;
    }
  }
}
