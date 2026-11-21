/**
 * Authenticator control-socket IPC client — runtime agent-identity acquisition
 * (HAAP CS v7.2.6 §4.2 / §5.2 X3DH Mode B).
 *
 * Mirrors `python/src/hawcx_haap/auth_ipc.py` and the Rust control socket
 * protocol in `crates/haap-auth-bin/src/control_socket.rs`:
 *
 * Wire format: `[msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]`
 * - `MSG_REGISTER_REQ = 0x07`  — Agent runtime -> Authenticator, JSON
 * - `MSG_REGISTER_RESP = 0x08` — Authenticator -> Agent runtime, JSON
 *
 * Unlike the Assembler agent socket, the Authenticator control socket does NOT
 * exchange an IPC version handshake — it accepts framed requests directly.
 */

import { Buffer } from "node:buffer";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import * as process from "node:process";

import { EnrollmentRejected, HawcxError, IpcError } from "./errors";
import {
  FrameReader,
  MAX_MESSAGE_SIZE,
  connectAssembler,
  encodeFrame,
  writeFrameBytes,
} from "./ipc";

export const MSG_REGISTER_REQ = 0x07;
export const MSG_REGISTER_RESP = 0x08;

/**
 * Result of a successful `HawcxAgent.enroll` / `AuthenticatorClient.registerAgent`
 * — mirrors Python `EnrollmentResult` and Rust `RegisterAgentResult::Enrolled` /
 * `AlreadyEnrolled`.
 */
export interface EnrollmentResult {
  agentInstanceId: string;
  clientId: string;
  ikFingerprint: string;
  sessionId: string;
  alreadyEnrolled: boolean;
  trustLevel?: string;
}

function defaultIpcDir(): string {
  if (process.platform === "win32") {
    return "";
  }
  const xdgRuntime = process.env.XDG_RUNTIME_DIR;
  if (xdgRuntime) return path.join(xdgRuntime, "hawcx");
  return path.join(os.tmpdir(), "hawcx");
}

/**
 * Compute the canonical Authenticator control-socket path.
 *
 * - Honors `HAAP_AUTH_CONTROL_SOCK` override (matches Python SDK & Rust supervisor).
 * - Windows: `\\\\.\\pipe\\haap-{agentId}-auth-control`
 * - Unix:    `{ipcDir}/{agentId}/auth-control.sock`
 */
export function defaultAuthControlSocketFor(
  agentId: string,
  options: { ipcDir?: string } = {},
): string {
  const override = process.env.HAAP_AUTH_CONTROL_SOCK;
  if (override) {
    return override;
  }
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\haap-${agentId}-auth-control`;
  }
  const base = options.ipcDir ?? defaultIpcDir();
  return path.join(base, agentId, "auth-control.sock");
}

/**
 * Client for the per-agent Authenticator control socket.
 *
 * Reuses `connectAssembler` for transport setup so every Authenticator
 * connection enforces the exact same socket-path, parent-dir, and kernel
 * peer-credential (`SO_PEERCRED` / `LOCAL_PEERCRED` / Windows Named Pipe SID)
 * checks as Assembler connections.
 */
export class AuthenticatorClient {
  private closed = false;

  private constructor(
    private readonly sock: net.Socket,
    private readonly reader: FrameReader,
  ) {}

  static async connect(
    endpoint: string,
    options: { timeoutMs?: number } = {},
  ): Promise<AuthenticatorClient> {
    const timeoutMs = options.timeoutMs ?? 30_000;
    const sock = await connectAssembler(endpoint, timeoutMs);
    const reader = new FrameReader(sock);
    return new AuthenticatorClient(sock, reader);
  }

  async registerAgent(args: {
    agentClass: string;
    subjectUserId: string;
    orgToken: string;
    preparedAgentId?: string;
  }): Promise<EnrollmentResult> {
    if (this.closed) {
      throw new HawcxError("authenticator client already closed");
    }

    const payloadObj: Record<string, unknown> = {
      agent_class: args.agentClass,
      subject_user_id: args.subjectUserId,
      org_token: args.orgToken,
    };
    if (args.preparedAgentId !== undefined) {
      payloadObj.prepared_agent_id = args.preparedAgentId;
    }

    const body = Buffer.from(JSON.stringify(payloadObj), "utf-8");
    if (body.length + 1 > MAX_MESSAGE_SIZE) {
      throw new IpcError(
        `register payload too large: ${body.length} bytes (max ${MAX_MESSAGE_SIZE - 1})`,
      );
    }

    await writeFrameBytes(this.sock, encodeFrame(MSG_REGISTER_REQ, body));
    const [msgType, respBody] = await this.reader.read();
    if (msgType !== MSG_REGISTER_RESP) {
      throw new IpcError(
        `unexpected response msg_type 0x${msgType.toString(16).padStart(2, "0")}; ` +
          `expected 0x${MSG_REGISTER_RESP.toString(16).padStart(2, "0")} (MSG_REGISTER_RESP)`,
      );
    }
    return parseRegisterResponse(respBody);
  }

  close(): void {
    if (!this.closed) {
      this.closed = true;
      this.sock.destroy();
    }
  }
}

function parseRegisterResponse(body: Buffer): EnrollmentResult {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(body.toString("utf-8")) as Record<string, unknown>;
  } catch (err) {
    throw new IpcError(
      `malformed register response: ${(err as Error).message}`,
    );
  }

  if ("error" in obj && !("type" in obj)) {
    throw new EnrollmentRejected(String(obj.error));
  }

  const variant = obj.type;
  if (variant === "Enrolled") {
    return {
      agentInstanceId: String(obj.agent_instance_id ?? ""),
      clientId: String(obj.client_id ?? ""),
      ikFingerprint: String(obj.ik_fingerprint ?? ""),
      sessionId: String(obj.session_id ?? ""),
      alreadyEnrolled: false,
    };
  }
  if (variant === "AlreadyEnrolled") {
    const result: EnrollmentResult = {
      agentInstanceId: String(obj.agent_instance_id ?? ""),
      clientId: String(obj.client_id ?? ""),
      ikFingerprint: String(obj.ik_fingerprint ?? ""),
      sessionId: String(obj.session_id ?? ""),
      alreadyEnrolled: true,
    };
    if (obj.trust_level !== undefined && obj.trust_level !== null) {
      result.trustLevel = String(obj.trust_level);
    }
    return result;
  }
  if (variant === "Degraded") {
    const aid = obj.agent_instance_id ? String(obj.agent_instance_id) : null;
    throw new EnrollmentRejected(
      String(obj.reason ?? "policy push failed"),
      aid,
    );
  }
  throw new IpcError(
    `unknown RegisterAgentResult variant: ${String(variant)} (expected Enrolled / AlreadyEnrolled / Degraded)`,
  );
}
