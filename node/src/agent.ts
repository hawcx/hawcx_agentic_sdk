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
import { createHash, randomUUID } from "node:crypto";
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
 * Construction options shared by every `HawcxAgent.connect*` factory.
 *
 * `principalAllowlist` (H-3 hardening 2026-05-20) gates which
 * `actingForUser` values this agent instance is permitted to emit. The
 * SDK validates `invoke({ actingForUser })` against this allowlist
 * before forwarding to the Assembler — out-of-list values throw
 * synchronously, so LLM-derived principal strings cannot silently
 * impersonate other users.
 *
 * Pass an empty array (`[]`) to disable runtime principal switching
 * entirely; any non-empty `actingForUser` will throw. Pass `["*"]` only
 * if the caller has independently verified the principal source is
 * trusted (signed claim, headers from an authenticated upstream, etc.)
 * — the SDK does not validate `"*"` semantics; it's an explicit
 * escape hatch with a load-bearing string so a future reader spots it
 * in code review.
 */
export interface HawcxAgentOptions {
  timeoutMs?: number;
  /**
   * Closed set of user principal IDs this agent may emit via
   * `actingForUser`. Validated synchronously inside `invoke` /
   * `invokeFor`; out-of-list values throw before any IPC bytes are
   * written.
   *
   * MUST be a static set sourced from operator config — never derive
   * from LLM output, request bodies, or any input that a model can
   * influence. See README "Threat model — runtime principal" for the
   * full guidance.
   */
  principalAllowlist: readonly string[];
}

/**
 * Construction options for the agent-id factory. Same as
 * {@link HawcxAgentOptions} plus the index/ipcDir resolution fields.
 */
export interface HawcxAgentConnectByAgentIdOptions extends HawcxAgentOptions {
  index?: number;
  ipcDir?: string;
}

/**
 * Construction options for `HawcxAgent.enroll` — runtime identity
 * acquisition per HAAP CS v7.2.6 §4.2 (Tier-2 Agent Enrollment) and
 * §5.2 (X3DH Mode B).
 *
 * **Skeleton — wire implementation lands in a follow-up.** The Python
 * SDK currently ships the canonical client; this interface is here so
 * Node consumers can type-check their integration code against the
 * eventual API shape.
 */
export interface HawcxAgentEnrollOptions extends HawcxAgentOptions {
  /** Authenticator slot identifier — e.g. `"researcher"`. */
  name: string;
  /**
   * Single-use org-issued enrollment token from the Hawcx Admin
   * Console. Treat as a credential — never log or persist on disk.
   */
  orgToken: string;
  /** Optional agent_class (default `"default"`). */
  agentClass?: string;
  /**
   * Override for the Authenticator's UDS/pipe path. Defaults to the
   * canonical convention `{ipcDir}/{name}/auth-control.sock` (Unix) or
   * `\\\\.\\pipe\\haap-{name}-auth-control` (Windows). Honors
   * `HAAP_AUTH_CONTROL_SOCK` env var as well.
   */
  authenticatorSocket?: string;
  index?: number;
  ipcDir?: string;
  /** Connect timeout for the post-enroll Assembler socket. */
  timeoutMs?: number;
  /** Timeout for the enrollment ceremony (X3DH round-trip to the AS). */
  enrollTimeoutMs?: number;
}

/**
 * Result of a successful `HawcxAgent.enroll` — mirrors the Python
 * `EnrollmentResult` dataclass and the Rust
 * `RegisterAgentResult::Enrolled` variant.
 */
export interface EnrollmentResult {
  agentInstanceId: string;
  clientId: string;
  ikFingerprint: string;
  sessionId: string;
  alreadyEnrolled: boolean;
  trustLevel?: string;
}

/**
 * High-level HAAP agent client. Connect once, invoke many times, close.
 *
 *     const agent = await HawcxAgent.connect(
 *       "/var/run/haap/research-u1/agent-assembler-0.sock",
 *       { principalAllowlist: ["alice", "bob"] },
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
  private constructor(
    private client: AssemblerClient | null,
    private readonly principalAllowlist: ReadonlySet<string>,
  ) {}

  /**
   * Open the agent IPC socket at `endpoint` and complete the version handshake.
   *
   * On Unix, `endpoint` is a filesystem path. On Windows, it's a Named Pipe
   * path (`\\\\.\\pipe\\haap-<agent_id>-agent-assembler-<index>`).
   *
   * `options.principalAllowlist` is required (H-3 2026-05-20). Pass `[]`
   * to forbid runtime principal switching entirely.
   */
  static async connect(
    endpoint: string,
    options: HawcxAgentOptions,
  ): Promise<HawcxAgent> {
    const allowlist = validatePrincipalAllowlist(options.principalAllowlist);
    const client = await AssemblerClient.connect(endpoint, options);
    return new HawcxAgent(client, allowlist);
  }

  /**
   * Resolve the conventional Assembler-agent endpoint for an agent id, then
   * `connect`.
   */
  static connectByAgentId(
    agentId: string,
    options: HawcxAgentConnectByAgentIdOptions,
  ): Promise<HawcxAgent> {
    return HawcxAgent.connect(
      defaultEndpointFor(agentId, options),
      options,
    );
  }

  /**
   * Acquire an agent identity at runtime (HAAP CS v7.2.6 §4.2) and connect
   * to its Assembler.
   *
   * Drives the per-agent Authenticator over its control socket to perform
   * X3DH Mode B (§5.2) against the configured AS using the supplied
   * `orgToken`, then opens the Assembler agent socket for the resulting
   * `agent_instance_id`.
   *
   * **Status — 2026-05-22 (v7.2.6 task #11):** the Python SDK ships the
   * canonical implementation of this surface. The Node SDK exposes the
   * type contract here so customers using `@hawcx/hawcx-haap` can compile
   * against the same API; the wire client lands in a follow-up. Until
   * then this method throws `Error("HawcxAgent.enroll not yet implemented
   * in Node SDK — use the Python SDK or HawcxAgent.connectByAgentId")`.
   *
   * `orgToken` is a single-use bearer credential — do not persist or log.
   */
  static async enroll(
    _options: HawcxAgentEnrollOptions,
  ): Promise<HawcxAgent> {
    throw new Error(
      "HawcxAgent.enroll not yet implemented in Node SDK — " +
        "use the Python SDK for runtime enrollment, or " +
        "HawcxAgent.connectByAgentId with a pre-provisioned agent_id. " +
        "Tracking: v7.2.6 task #11 follow-up.",
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
   *
   * If `opts.actingForUser` is set, it MUST be a member of the
   * `principalAllowlist` passed at construction time. Out-of-list
   * values throw synchronously before any IPC bytes are written —
   * an LLM-derived principal string can never silently switch the
   * effective user.
   */
  async invoke(opts: HawcxAgentInvokeOptions): Promise<ToolCallResponse> {
    if (!this.client) throw new Error("agent already closed");
    if (opts.actingForUser !== undefined) {
      this.assertPrincipalAllowed(opts.actingForUser);
    }
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
   * "no principal" is the intended semantic) or if the principal is
   * not a member of the `principalAllowlist` passed at construction.
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
    // assertPrincipalAllowed runs again inside invoke(), but throwing
    // here gives the caller a clearer stack trace pointing at the
    // invokeFor site rather than the inner forwarding call.
    this.assertPrincipalAllowed(userPrincipalId);
    return this.invoke({ ...opts, actingForUser: userPrincipalId });
  }

  private assertPrincipalAllowed(principal: string): void {
    // Empty-string principal is treated identically to "unset" by the
    // Assembler (no `acting_for_user` projected onto scope_json), but
    // we still reject it here as a caller-side correctness check —
    // letting `""` through is almost always a bug.
    if (principal === "") {
      throw new Error(
        "actingForUser must be a non-empty string; omit the field to opt out of runtime principal switching",
      );
    }
    if (!this.principalAllowlist.has(principal)) {
      // Do NOT echo the rejected principal back into the error
      // message unredacted — an attacker fuzzing principal IDs could
      // use the exception text to confirm or deny enumeration. We
      // log a SHA-1-style short fingerprint instead.
      const fp = principalFingerprint(principal);
      throw new Error(
        `actingForUser principal not in principalAllowlist (fingerprint=${fp}); ` +
          "add the principal to the allowlist at HawcxAgent.connect() time " +
          "or omit actingForUser. See README 'Threat model — runtime principal'.",
      );
    }
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

/**
 * Validate `principalAllowlist` shape at construction time. Required so
 * a caller can't accidentally pass `undefined` (TypeScript would catch
 * this at compile time inside the monorepo, but the SDK is consumed
 * from JS too).
 */
function validatePrincipalAllowlist(
  list: readonly string[] | undefined,
): ReadonlySet<string> {
  if (!Array.isArray(list)) {
    throw new TypeError(
      "HawcxAgent options.principalAllowlist is required: pass an array of " +
        "permitted user principal IDs, or [] to forbid runtime principal switching. " +
        "See README 'Threat model — runtime principal'.",
    );
  }
  for (const p of list) {
    if (typeof p !== "string") {
      throw new TypeError(
        `principalAllowlist entries must be strings; got ${typeof p}`,
      );
    }
    if (p === "") {
      throw new TypeError(
        "principalAllowlist entries must be non-empty strings",
      );
    }
  }
  return new Set(list);
}

/**
 * 12-hex-char SHA-256 prefix of the principal string, used in error
 * messages so the SDK does not echo rejected principal IDs verbatim.
 * Truncated SHA-256 — never SHA-1 / MD5 (Hawcx posture).
 */
function principalFingerprint(principal: string): string {
  return createHash("sha256").update(principal, "utf8").digest("hex").slice(0, 12);
}
