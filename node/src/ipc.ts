/**
 * Assembler IPC client — speaks the wire protocol from `hx_labs/crates/haap-ipc`.
 *
 * Wire format (verified against `crates/haap-ipc/src/framing.rs`):
 *
 *     [msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]
 *
 * `msg_len` includes the `msg_type` byte. `MAX_MESSAGE_SIZE` is 64 KiB.
 *
 * On connect both sides exchange an `IpcHandshake` (msg_type `0x00`) with
 * payload `[protocol_version: u16 BE][major: u16 BE][minor: u16 BE]
 * [patch: u16 BE][role: u8]`. Per `crates/haap-ipc/src/handshake.rs`, major
 * version MUST match; minor mismatches are logged warnings on the Rust side.
 *
 * Agent ↔ Assembler messages (CS v6.0.0 §39.7 channel allowlists):
 * - `MSG_TOOL_CALL_REQUEST = 0x52`    Agent → Assembler, JSON
 * - `MSG_TOOL_CALL_RESPONSE = 0x53`   Assembler → Agent, JSON
 * - `MSG_REQUEST_REJECTED = 0x54`     Assembler → Agent, JSON
 * - `MSG_CLARIFICATION_ANSWER = 0x61` Agent → Assembler, JSON (Profile E)
 */

import { Buffer } from "node:buffer";
import * as net from "node:net";

import { HandshakeError, IpcError, RequestRejected } from "./errors";

// ── Protocol constants (mirror crates/haap-ipc/src/handshake.rs) ────

export const PROTOCOL_VERSION = 1;
export const SDK_VERSION_MAJOR = 0;
export const SDK_VERSION_MINOR = 5;
export const SDK_VERSION_PATCH = 0;

export const ROLE_AGENT = 0x04;
export const ROLE_ASSEMBLER = 0x05;

export const MSG_TYPE_HANDSHAKE = 0x00;
export const MSG_TOOL_CALL_REQUEST = 0x52;
export const MSG_TOOL_CALL_RESPONSE = 0x53;
export const MSG_REQUEST_REJECTED = 0x54;
export const MSG_CLARIFICATION_ANSWER = 0x61;

export const MAX_MESSAGE_SIZE = 64 * 1024;

// ── Public wire types ───────────────────────────────────────────────

/**
 * Per-call outbound transport selector (CS v6.7.4 §34).
 *
 * `http_header` (default): token in `Authorization: HAAP <b64>` HTTP header.
 * `mcp_meta`: token in MCP `params._meta["haap/tbac"].token`.
 *
 * Values match serde `#[rename_all = "snake_case"]` on the Rust side.
 */
export enum TokenTransport {
  HttpHeader = "http_header",
  McpMeta = "mcp_meta",
}

/**
 * Agent → Assembler request (msg_type `0x52`).
 *
 * Mirrors `haap_ipc::messages::assembler::ToolCallRequest`. The Assembler
 * constructs the requested scope from `tool` / `action` / `resource` /
 * `constraints` per CS §39.7; the SDK process does not see token material
 * or session keys.
 */
export interface ToolCallRequest {
  requestId: string;
  targetRsUrl: string;
  httpMethod: string;
  headers?: Record<string, string>;
  tool: string;
  action?: readonly string[];
  resource?: string;
  constraints?: Record<string, unknown>;
  body?: Buffer | null;
  claimedIntentHash?: string;
  toolArguments?: unknown;
  contentType?: string;
  transport?: TokenTransport;
  /**
   * Optional runtime principal (CS v6.9.0 line 163). When set, the
   * Assembler projects this string into `scope_json.user_principal_id`
   * on the minted token so the gateway's Cedar policy can enforce
   * `context.user_principal_id == resource.owner_user_id`. The
   * agent's pinned `subject_user_id` is NOT modified — only per-call
   * scope_json metadata. See `HawcxAgent.invokeFor`.
   */
  actingForUser?: string;
}

/**
 * Assembler → Agent response (msg_type `0x53`).
 *
 * Mirrors `haap_ipc::messages::assembler::ToolCallResponse`. `body` is the
 * decrypted RS response (`Buffer`).
 */
export interface ToolCallResponse {
  requestId: string;
  httpStatus: number;
  headers: Record<string, string>;
  body: Buffer;
}

function toolCallRequestToWire(req: ToolCallRequest): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    request_id: req.requestId,
    target_rs_url: req.targetRsUrl,
    http_method: req.httpMethod,
    headers: req.headers ?? {},
    tool: req.tool,
    action: req.action ?? [],
    resource: req.resource ?? "*",
    constraints: req.constraints ?? {},
  };
  if (req.body !== undefined && req.body !== null) {
    wire.plaintext_request_body = req.body.toString("base64");
  }
  if (req.claimedIntentHash !== undefined) {
    wire.claimed_intent_hash = req.claimedIntentHash;
  }
  if (req.toolArguments !== undefined) {
    wire.tool_arguments = req.toolArguments;
  }
  if (req.contentType !== undefined) {
    wire.content_type = req.contentType;
  }
  if (req.transport !== undefined) {
    wire.transport = req.transport;
  }
  if (req.actingForUser !== undefined) {
    // Top-level wire field, NOT nested in `constraints`. The Assembler
    // projects this into `scope_json.user_principal_id` per
    // CS v6.9.0 line 163.
    wire.acting_for_user = req.actingForUser;
  }
  return wire;
}

function toolCallResponseFromWire(obj: Record<string, unknown>): ToolCallResponse {
  const requestId = String(obj.request_id ?? "");
  const httpStatus = Number(obj.http_status ?? 0);
  const headers = (obj.headers as Record<string, string>) ?? {};
  const bodyB64 = (obj.body as string) ?? "";
  return {
    requestId,
    httpStatus,
    headers,
    body: bodyB64 ? Buffer.from(bodyB64, "base64") : Buffer.alloc(0),
  };
}

// ── Framing helpers ─────────────────────────────────────────────────

export function encodeFrame(msgType: number, payload: Buffer): Buffer {
  const msgLen = 1 + payload.length;
  if (msgLen > MAX_MESSAGE_SIZE) {
    throw new IpcError(
      `frame too large: ${msgLen} bytes (max ${MAX_MESSAGE_SIZE})`,
    );
  }
  const frame = Buffer.allocUnsafe(4 + msgLen);
  frame.writeUInt32BE(msgLen, 0);
  frame.writeUInt8(msgType & 0xff, 4);
  payload.copy(frame, 5);
  return frame;
}

/**
 * Async reader that hands out [msgType, payload] tuples from a Node `net.Socket`.
 *
 * Internal state: a single resolver queue. The socket's `data` events accumulate
 * into a buffer; whenever a complete frame is present, the head waiter is
 * resolved with it. `error`, `end`, and `close` events propagate to all pending
 * waiters.
 */
class FrameReader {
  private buffer = Buffer.alloc(0);
  private waiters: Array<{
    resolve: (frame: [number, Buffer]) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private closeError: Error | null = null;

  constructor(private readonly sock: net.Socket) {
    sock.on("data", (chunk: Buffer) => this.onData(chunk));
    sock.on("error", (err) => this.onError(err));
    sock.on("end", () => this.onClose(null));
    sock.on("close", () => this.onClose(null));
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.drain();
  }

  private onError(err: Error): void {
    this.onClose(err);
  }

  private onClose(err: Error | null): void {
    if (this.closed) return;
    this.closed = true;
    this.closeError =
      err ?? new IpcError("IPC peer closed connection mid-message");
    for (const w of this.waiters) {
      w.reject(this.closeError);
    }
    this.waiters = [];
  }

  private drain(): void {
    while (this.waiters.length > 0 && this.tryReadOne()) {
      // tryReadOne resolves head waiter
    }
  }

  private tryReadOne(): boolean {
    if (this.buffer.length < 4) return false;
    const msgLen = this.buffer.readUInt32BE(0);
    if (msgLen === 0) {
      const head = this.waiters.shift();
      head?.reject(new IpcError("frame length 0 (illegal)"));
      return true;
    }
    if (msgLen > MAX_MESSAGE_SIZE) {
      const head = this.waiters.shift();
      head?.reject(
        new IpcError(
          `frame too large: ${msgLen} bytes (max ${MAX_MESSAGE_SIZE})`,
        ),
      );
      return true;
    }
    if (this.buffer.length < 4 + msgLen) return false;
    const frame = this.buffer.subarray(4, 4 + msgLen);
    const msgType = frame.readUInt8(0);
    const payload = Buffer.from(frame.subarray(1));
    this.buffer = Buffer.from(this.buffer.subarray(4 + msgLen));
    const head = this.waiters.shift();
    head?.resolve([msgType, payload]);
    return true;
  }

  read(): Promise<[number, Buffer]> {
    if (this.closed) {
      return Promise.reject(
        this.closeError ?? new IpcError("connection closed"),
      );
    }
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.drain();
    });
  }
}

// ── Handshake ───────────────────────────────────────────────────────

function encodeHandshake(role: number): Buffer {
  const buf = Buffer.allocUnsafe(9);
  buf.writeUInt16BE(PROTOCOL_VERSION, 0);
  buf.writeUInt16BE(SDK_VERSION_MAJOR, 2);
  buf.writeUInt16BE(SDK_VERSION_MINOR, 4);
  buf.writeUInt16BE(SDK_VERSION_PATCH, 6);
  buf.writeUInt8(role & 0xff, 8);
  return buf;
}

interface DecodedHandshake {
  protocol: number;
  major: number;
  minor: number;
  patch: number;
  role: number;
}

function decodeHandshake(payload: Buffer): DecodedHandshake {
  if (payload.length < 9) {
    throw new IpcError(
      `handshake payload too short: ${payload.length} (want >=9)`,
    );
  }
  return {
    protocol: payload.readUInt16BE(0),
    major: payload.readUInt16BE(2),
    minor: payload.readUInt16BE(4),
    patch: payload.readUInt16BE(6),
    role: payload.readUInt8(8),
  };
}

// ── Connect + AssemblerClient ───────────────────────────────────────

/**
 * Connect to the Assembler at `endpoint` and return a Node `net.Socket`.
 *
 * On Unix, `endpoint` is a filesystem path to a Unix domain socket.
 * On Windows, `endpoint` is a Named Pipe path
 * (`\\\\.\\pipe\\haap-<agent_id>-agent-assembler-<index>`). Node's `net.connect`
 * supports both via the `path` option.
 */
export function connectAssembler(
  endpoint: string,
  timeoutMs: number,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ path: endpoint });
    const timer =
      timeoutMs > 0
        ? setTimeout(() => {
            sock.destroy();
            reject(new IpcError(`timed out connecting to ${endpoint}`));
          }, timeoutMs)
        : null;
    const onError = (err: Error) => {
      if (timer) clearTimeout(timer);
      reject(new IpcError(`connect ${endpoint} failed: ${err.message}`));
    };
    sock.once("error", onError);
    sock.once("connect", () => {
      if (timer) clearTimeout(timer);
      sock.removeListener("error", onError);
      resolve(sock);
    });
  });
}

/**
 * Synchronous-feeling, async client for the Assembler IPC channel.
 *
 * On `connect`, performs the version handshake (role = `Agent`). After that,
 * the connection is ready for ToolCallRequest / ToolCallResponse round-trips.
 *
 * Not safe to invoke concurrently. Wrap in a queue for parallel calls.
 */
export class AssemblerClient {
  private constructor(
    private readonly sock: net.Socket,
    private readonly reader: FrameReader,
  ) {}

  static async connect(
    endpoint: string,
    options: { timeoutMs?: number } = {},
  ): Promise<AssemblerClient> {
    const timeoutMs = options.timeoutMs ?? 5000;
    const sock = await connectAssembler(endpoint, timeoutMs);
    const reader = new FrameReader(sock);
    try {
      await write(sock, encodeFrame(MSG_TYPE_HANDSHAKE, encodeHandshake(ROLE_AGENT)));
      const [type, payload] = await reader.read();
      if (type !== MSG_TYPE_HANDSHAKE) {
        throw new IpcError(
          `expected handshake (0x00), got 0x${type.toString(16).padStart(2, "0")}`,
        );
      }
      const hs = decodeHandshake(payload);
      if (hs.major !== SDK_VERSION_MAJOR) {
        throw new HandshakeError(SDK_VERSION_MAJOR, hs.major);
      }
      if (hs.role !== ROLE_ASSEMBLER) {
        throw new IpcError(
          `expected peer role Assembler (0x05), got 0x${hs.role.toString(16).padStart(2, "0")}`,
        );
      }
    } catch (err) {
      sock.destroy();
      throw err;
    }
    return new AssemblerClient(sock, reader);
  }

  async invoke(req: ToolCallRequest): Promise<ToolCallResponse> {
    const wire = toolCallRequestToWire(req);
    const payload = Buffer.from(JSON.stringify(wire), "utf-8");
    await write(this.sock, encodeFrame(MSG_TOOL_CALL_REQUEST, payload));

    const [type, body] = await this.reader.read();
    if (type === MSG_TOOL_CALL_RESPONSE) {
      const obj = JSON.parse(body.toString("utf-8")) as Record<string, unknown>;
      return toolCallResponseFromWire(obj);
    }
    if (type === MSG_REQUEST_REJECTED) {
      const obj = JSON.parse(body.toString("utf-8")) as Record<string, unknown>;
      throw new RequestRejected(
        String(obj.request_id ?? req.requestId),
        String(obj.reason ?? ""),
      );
    }
    throw new IpcError(
      `unexpected response msg_type 0x${type.toString(16).padStart(2, "0")}; expected 0x53 or 0x54`,
    );
  }

  async sendClarificationAnswer(args: {
    pendingId: string;
    sessionId: number | bigint;
    answerIndex?: number;
    answerText?: string;
  }): Promise<void> {
    // `session_id` is a `u64` on the Rust side
    // (`haap_ipc::messages::assembler::ClarificationAnswer`). The
    // previous code unconditionally narrowed `bigint` to `Number`
    // via `Number(args.sessionId)`, which silently truncates session
    // IDs above 2^53 (`Number.MAX_SAFE_INTEGER`). The Rust side then
    // looked up the *wrong* session and returned a "session not
    // found" rejection — a confusing failure mode rooted in JS-side
    // narrowing (M-5 hardening 2026-05-20).
    //
    // Fix: bigint inputs are emitted as a decimal string so no
    // precision is lost. Number inputs are passed through unchanged
    // (the common path — caller already chose `number`).
    //
    // BREAKING WIRE CHANGE (bigint path only): a follow-up bug filed
    // against `hx_labs/crates/haap-ipc/src/messages/assembler.rs`
    // tracks adding a serde `deserialize_with` helper so `u64` will
    // accept both a JSON number and a string-encoded decimal. Until
    // that lands, callers passing `bigint` values above 2^53 will
    // hit a deserialiser error on the Assembler side rather than
    // silent truncation — which is the correct failure mode.
    const obj: Record<string, unknown> = {
      pending_id: args.pendingId,
      session_id: encodeSessionIdForWire(args.sessionId),
    };
    if (args.answerIndex !== undefined) obj.answer_index = args.answerIndex;
    if (args.answerText !== undefined) obj.answer_text = args.answerText;
    const payload = Buffer.from(JSON.stringify(obj), "utf-8");
    await write(this.sock, encodeFrame(MSG_CLARIFICATION_ANSWER, payload));
  }

  close(): void {
    this.sock.destroy();
  }
}

/**
 * Encode a `session_id` for the JSON wire payload.
 *
 * `bigint` inputs are emitted as a decimal string (so 64-bit values
 * above `Number.MAX_SAFE_INTEGER` round-trip without precision loss
 * once the Rust deserialiser learns to accept the string form).
 * `number` inputs are passed through unchanged (emitted as a JSON
 * number by `JSON.stringify`).
 *
 * Exported so unit tests can pin the exact wire shape.
 */
export function encodeSessionIdForWire(
  sessionId: number | bigint,
): number | string {
  return typeof sessionId === "bigint" ? sessionId.toString(10) : sessionId;
}

function write(sock: net.Socket, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    sock.write(data, (err) => {
      if (err) reject(new IpcError(`write failed: ${err.message}`));
      else resolve();
    });
  });
}
