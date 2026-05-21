/**
 * In-process mock Assembler used by vitest tests.
 *
 * Speaks the wire protocol from `hx_labs/crates/haap-ipc`:
 *
 *   [msg_len: u32 BE][msg_type: u8][payload]
 *
 * Performs the version handshake (role = Assembler / 0x05) on connect, then
 * accepts ToolCallRequest (0x52) frames and replies with ToolCallResponse
 * (0x53) or RequestRejected (0x54) per the configuration.
 *
 * Unix-only (uses a UDS path under `os.tmpdir()`). The Node `net` module
 * does support Named Pipes on Windows so the production client works there;
 * we just don't run a mock server on Windows in tests.
 */

import { Buffer } from "node:buffer";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

const PROTOCOL_VERSION = 1;
const SDK_VERSION_MAJOR = 0;
const SDK_VERSION_MINOR = 5;
const SDK_VERSION_PATCH = 0;
const ROLE_ASSEMBLER = 0x05;

const MSG_TYPE_HANDSHAKE = 0x00;
const MSG_TOOL_CALL_REQUEST = 0x52;
const MSG_TOOL_CALL_RESPONSE = 0x53;
const MSG_REQUEST_REJECTED = 0x54;

interface ToolCallRequestWire {
  request_id: string;
  target_rs_url: string;
  http_method: string;
  headers: Record<string, string>;
  tool: string;
  action?: string[];
  resource?: string;
  plaintext_request_body?: string;
  transport?: string;
  [k: string]: unknown;
}

export interface MockResponseOverride {
  body: Buffer;
  status?: number;
  headers?: Record<string, string>;
}

export class MockAssembler {
  readonly socketPath: string;
  receivedRequest: ToolCallRequestWire | null = null;

  private readonly parentDir: string;
  private server: net.Server | null = null;
  private rejectReason: string | null = null;
  private responseOverride: MockResponseOverride | null = null;
  private closed = false;

  constructor() {
    // Sockets must live inside a 0o700 dir owned by the current UID
    // for the H-4 client-side parent-dir check to accept them. Use
    // mkdtempSync inside os.tmpdir() (which gives us a fresh
    // exclusive dir) and chmod it 0o700.
    this.parentDir = fs.mkdtempSync(path.join(os.tmpdir(), "hawcx-mock-"));
    fs.chmodSync(this.parentDir, 0o700);
    this.socketPath = path.join(
      this.parentDir,
      `assembler-${crypto.randomBytes(8).toString("hex")}.sock`,
    );
  }

  rejectWith(reason: string): void {
    this.rejectReason = reason;
  }

  respondWith(override: MockResponseOverride): void {
    this.responseOverride = override;
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((sock) => this.handleConnection(sock));
      this.server.on("error", reject);
      this.server.listen(this.socketPath, () => {
        this.server!.off("error", reject);
        resolve();
      });
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await new Promise<void>((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
    try {
      fs.unlinkSync(this.socketPath);
    } catch {
      // ignore
    }
    try {
      fs.rmdirSync(this.parentDir);
    } catch {
      // ignore
    }
  }

  private handleConnection(sock: net.Socket): void {
    let buf = Buffer.alloc(0);
    let handshakeDone = false;
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      while (true) {
        if (buf.length < 4) return;
        const msgLen = buf.readUInt32BE(0);
        if (buf.length < 4 + msgLen) return;
        const frame = buf.subarray(4, 4 + msgLen);
        buf = Buffer.from(buf.subarray(4 + msgLen));
        const msgType = frame.readUInt8(0);
        const payload = frame.subarray(1);

        if (!handshakeDone) {
          if (msgType !== MSG_TYPE_HANDSHAKE) {
            sock.destroy();
            return;
          }
          const reply = Buffer.allocUnsafe(9);
          reply.writeUInt16BE(PROTOCOL_VERSION, 0);
          reply.writeUInt16BE(SDK_VERSION_MAJOR, 2);
          reply.writeUInt16BE(SDK_VERSION_MINOR, 4);
          reply.writeUInt16BE(SDK_VERSION_PATCH, 6);
          reply.writeUInt8(ROLE_ASSEMBLER, 8);
          writeFrame(sock, MSG_TYPE_HANDSHAKE, reply);
          handshakeDone = true;
          continue;
        }

        if (msgType !== MSG_TOOL_CALL_REQUEST) {
          // Ignore non-request frames in the mock.
          continue;
        }
        const req = JSON.parse(payload.toString("utf-8")) as ToolCallRequestWire;
        this.receivedRequest = req;

        if (this.rejectReason !== null) {
          const payloadBytes = Buffer.from(
            JSON.stringify({
              request_id: req.request_id,
              reason: this.rejectReason,
            }),
            "utf-8",
          );
          writeFrame(sock, MSG_REQUEST_REJECTED, payloadBytes);
          continue;
        }

        let body: Buffer;
        let status: number;
        let headers: Record<string, string>;
        if (this.responseOverride) {
          body = this.responseOverride.body;
          status = this.responseOverride.status ?? 200;
          headers = this.responseOverride.headers ?? {};
        } else {
          // Default echo: return the plaintext_request_body unchanged.
          body = req.plaintext_request_body
            ? Buffer.from(req.plaintext_request_body, "base64")
            : Buffer.alloc(0);
          status = 200;
          headers = { "X-Mock": "1" };
        }
        const payloadBytes = Buffer.from(
          JSON.stringify({
            request_id: req.request_id,
            http_status: status,
            headers,
            body: body.toString("base64"),
          }),
          "utf-8",
        );
        writeFrame(sock, MSG_TOOL_CALL_RESPONSE, payloadBytes);
      }
    });
    sock.on("error", () => sock.destroy());
  }
}

function writeFrame(sock: net.Socket, msgType: number, payload: Buffer): void {
  const msgLen = 1 + payload.length;
  const frame = Buffer.allocUnsafe(4 + msgLen);
  frame.writeUInt32BE(msgLen, 0);
  frame.writeUInt8(msgType, 4);
  payload.copy(frame, 5);
  sock.write(frame);
}
