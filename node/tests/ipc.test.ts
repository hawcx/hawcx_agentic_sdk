/**
 * Low-level IPC tests — framing, type encoding, AssemblerClient round-trip.
 */

import { Buffer } from "node:buffer";
import * as net from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AssemblerClient,
  HandshakeError,
  IpcError,
  MAX_MESSAGE_SIZE,
  MSG_TYPE_HANDSHAKE,
  RequestRejected,
  TokenTransport,
  encodeFrame,
} from "../src";

import { MockAssembler } from "./mockAssembler";

describe("framing", () => {
  it("encodeFrame layout matches [u32 BE len][u8 type][payload]", () => {
    const frame = encodeFrame(0x52, Buffer.from("hello"));
    expect(frame.readUInt32BE(0)).toBe(1 + "hello".length);
    expect(frame.readUInt8(4)).toBe(0x52);
    expect(frame.subarray(5).toString()).toBe("hello");
  });

  it("encodeFrame allows empty payload", () => {
    const frame = encodeFrame(0x21, Buffer.alloc(0));
    expect(frame.length).toBe(5);
    expect(frame.readUInt32BE(0)).toBe(1);
    expect(frame.readUInt8(4)).toBe(0x21);
  });

  it("encodeFrame rejects oversized payload", () => {
    expect(() =>
      encodeFrame(0x52, Buffer.alloc(MAX_MESSAGE_SIZE)),
    ).toThrowError(IpcError);
  });
});

// Skips on Windows: the AssemblerClient transport currently binds Unix
// domain sockets, which Node on the Windows GHA runner image rejects
// with EACCES. Named-pipe parity for the Node binding mirrors the Rust
// SDK's CS v7.2.5 §39.12.2 implementation (hx_labs::haap_ipc::win_dacl)
// and is tracked as a follow-up.
describe.skipIf(process.platform === "win32")("AssemblerClient (UDS)", () => {
  let mock: MockAssembler;

  beforeEach(async () => {
    mock = new MockAssembler();
    await mock.start();
  });

  afterEach(async () => {
    await mock.close();
  });

  it("performs handshake and echoes ToolCallRequest body", async () => {
    const client = await AssemblerClient.connect(mock.socketPath);
    try {
      const resp = await client.invoke({
        requestId: "req-1",
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        tool: "echo",
        body: Buffer.from("hello"),
      });
      expect(resp.requestId).toBe("req-1");
      expect(resp.httpStatus).toBe(200);
      expect(resp.body.toString()).toBe("hello");
    } finally {
      client.close();
    }
    expect(mock.receivedRequest?.tool).toBe("echo");
  });

  it("transport enum serializes as snake_case", async () => {
    const client = await AssemblerClient.connect(mock.socketPath);
    try {
      await client.invoke({
        requestId: "req-2",
        targetRsUrl: "https://mcp.example.com",
        httpMethod: "POST",
        tool: "search",
        transport: TokenTransport.McpMeta,
      });
    } finally {
      client.close();
    }
    expect(mock.receivedRequest?.transport).toBe("mcp_meta");
  });

  it("raises RequestRejected when Assembler sends 0x54", async () => {
    mock.rejectWith("destination not in allowlist");
    const client = await AssemblerClient.connect(mock.socketPath);
    try {
      await expect(
        client.invoke({
          requestId: "req-r",
          targetRsUrl: "https://forbidden.example.com",
          httpMethod: "GET",
          tool: "oops",
        }),
      ).rejects.toBeInstanceOf(RequestRejected);
    } finally {
      client.close();
    }
  });

  it("optional fields are omitted from the wire when undefined", async () => {
    const client = await AssemblerClient.connect(mock.socketPath);
    try {
      await client.invoke({
        requestId: "req-3",
        targetRsUrl: "https://api.example.com",
        httpMethod: "GET",
        tool: "fetch",
      });
    } finally {
      client.close();
    }
    expect(mock.receivedRequest).not.toHaveProperty("plaintext_request_body");
    expect(mock.receivedRequest).not.toHaveProperty("transport");
    expect(mock.receivedRequest).not.toHaveProperty("claimed_intent_hash");
  });
});

// Windows: same UDS portability gap as the (UDS) block above.
// Linux: these tests bind sockets under their own per-test dir (created
// via mkdtempSync with mode 0o700) rather than dropping straight into
// /tmp, because the AssemblerClient enforces the H-3/M-3 parent-dir
// hardening from PR #14 (refuses /tmp because it's owned by uid 0 and
// world-writable). MockAssembler uses the same per-user-dir pattern.
describe.skipIf(process.platform === "win32")("AssemblerClient handshake validation", () => {
  const fs = require("node:fs") as typeof import("node:fs");
  const os = require("node:os") as typeof import("node:os");
  const path = require("node:path") as typeof import("node:path");

  let parentDir: string;
  beforeEach(() => {
    parentDir = fs.mkdtempSync(path.join(os.tmpdir(), "hawcx-hs-"));
    fs.chmodSync(parentDir, 0o700);
  });
  afterEach(() => {
    try {
      fs.rmSync(parentDir, { recursive: true, force: true });
    } catch {
      /* best-effort cleanup */
    }
  });

  it("throws HandshakeError when peer major version is wrong", async () => {
    const socketPath = path.join(parentDir, `wrong-version-${Date.now()}.sock`);
    const server = net.createServer((sock) => {
      sock.once("data", () => {
        const reply = Buffer.allocUnsafe(9);
        reply.writeUInt16BE(1, 0);
        reply.writeUInt16BE(99, 2); // wrong major
        reply.writeUInt16BE(0, 4);
        reply.writeUInt16BE(0, 6);
        reply.writeUInt8(0x05, 8);
        const frame = Buffer.allocUnsafe(4 + 1 + reply.length);
        frame.writeUInt32BE(1 + reply.length, 0);
        frame.writeUInt8(MSG_TYPE_HANDSHAKE, 4);
        reply.copy(frame, 5);
        sock.write(frame);
      });
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    try {
      await expect(AssemblerClient.connect(socketPath)).rejects.toBeInstanceOf(
        HandshakeError,
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("throws IpcError when peer claims a non-Assembler role", async () => {
    const socketPath = path.join(parentDir, `wrong-role-${Date.now()}.sock`);
    const server = net.createServer((sock) => {
      sock.once("data", () => {
        const reply = Buffer.allocUnsafe(9);
        reply.writeUInt16BE(1, 0);
        reply.writeUInt16BE(0, 2);
        reply.writeUInt16BE(5, 4);
        reply.writeUInt16BE(0, 6);
        reply.writeUInt8(0x01, 8); // claims Supervisor
        const frame = Buffer.allocUnsafe(4 + 1 + reply.length);
        frame.writeUInt32BE(1 + reply.length, 0);
        frame.writeUInt8(MSG_TYPE_HANDSHAKE, 4);
        reply.copy(frame, 5);
        sock.write(frame);
      });
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    try {
      await expect(AssemblerClient.connect(socketPath)).rejects.toThrowError(
        /Assembler/,
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
