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
  validateWindowsNamedPipePath,
  verifyWindowsNamedPipeServer,
} from "../src";
import { _setPeerVerifiersForTesting } from "../src/ipc";

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
// SDK's CS v7.2.5 §39.12.2 implementation (haap_ipc::win_dacl)
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
    expect(mock.receivedRequest).not.toHaveProperty("mcp_tool_name");
  });

  it("serializes mcpToolName as mcp_tool_name distinct from tool", async () => {
    const client = await AssemblerClient.connect(mock.socketPath);
    try {
      await client.invoke({
        requestId: "req-mcp-1",
        targetRsUrl: "https://mcp.example.com",
        httpMethod: "POST",
        tool: "docs.write",
        mcpToolName: "write-doc",
        transport: TokenTransport.McpMeta,
      });
    } finally {
      client.close();
    }
    expect(mock.receivedRequest?.tool).toBe("docs.write");
    expect(mock.receivedRequest?.mcp_tool_name).toBe("write-doc");
    expect(mock.receivedRequest?.transport).toBe("mcp_meta");
  });

  it("TokenTransport.McpMetaV725 aliases to mcp_meta (never emits unsupported mcp_meta_v7_2_5)", async () => {
    expect(TokenTransport.McpMeta).toBe("mcp_meta");
    expect(TokenTransport.McpMetaV725).toBe("mcp_meta");
    const client = await AssemblerClient.connect(mock.socketPath);
    try {
      await client.invoke({
        requestId: "req-mcp-alias",
        targetRsUrl: "https://mcp.example.com",
        httpMethod: "POST",
        tool: "search",
        transport: TokenTransport.McpMetaV725,
      });
    } finally {
      client.close();
    }
    expect(mock.receivedRequest?.transport).toBe("mcp_meta");
  });
});

describe.skipIf(process.platform === "win32")(
  "Unix peer-UID verification (SO_PEERCRED / LOCAL_PEERCRED)",
  () => {
    let mock: MockAssembler;
    const savedExpectedUid = process.env.HAAP_SDK_EXPECTED_PEER_UID;

    beforeEach(async () => {
      delete process.env.HAAP_SDK_EXPECTED_PEER_UID;
      _setPeerVerifiersForTesting({ unix: null });
      mock = new MockAssembler();
      await mock.start();
    });

    afterEach(async () => {
      _setPeerVerifiersForTesting({ unix: null });
      if (savedExpectedUid === undefined) {
        delete process.env.HAAP_SDK_EXPECTED_PEER_UID;
      } else {
        process.env.HAAP_SDK_EXPECTED_PEER_UID = savedExpectedUid;
      }
      await mock.close();
    });

    it("rejects mismatched HAAP_SDK_EXPECTED_PEER_UID via real kernel peercred before handshake", async () => {
      const wrongUid = process.getuid!() + 1;
      process.env.HAAP_SDK_EXPECTED_PEER_UID = String(wrongUid);
      const expectedMechanism =
        process.platform === "darwin" ? "LOCAL_PEERCRED" : "SO_PEERCRED";

      await expect(AssemblerClient.connect(mock.socketPath)).rejects.toSatisfy(
        (err: unknown) =>
          err instanceof IpcError &&
          err.message.includes(expectedMechanism) &&
          err.message.includes(`expected ${wrongUid}`),
      );
      expect(mock.receivedRequest).toBeNull();
    });

    it("succeeds when explicit HAAP_SDK_EXPECTED_PEER_UID matches our UID", async () => {
      process.env.HAAP_SDK_EXPECTED_PEER_UID = String(process.getuid!());
      const client = await AssemblerClient.connect(mock.socketPath);
      try {
        const resp = await client.invoke({
          requestId: "req-peer-ok",
          targetRsUrl: "https://api.example.com/echo",
          httpMethod: "POST",
          tool: "echo",
          body: Buffer.from("peer-ok"),
        });
        expect(resp.body.toString()).toBe("peer-ok");
      } finally {
        client.close();
      }
    });

    it.each(["", "-1", "abc", "123abc", "4294967296"])(
      "rejects malformed HAAP_SDK_EXPECTED_PEER_UID=%j before connect",
      async (badUid) => {
        process.env.HAAP_SDK_EXPECTED_PEER_UID = badUid;
        await expect(AssemblerClient.connect(mock.socketPath)).rejects.toThrow(
          /not a valid uid/,
        );
      },
    );

    it("fails closed if the peer-credential lookup throws", async () => {
      _setPeerVerifiersForTesting({
        unix: () => {
          throw new IpcError("simulated SO_PEERCRED syscall failure");
        },
      });
      await expect(AssemblerClient.connect(mock.socketPath)).rejects.toThrow(
        /simulated SO_PEERCRED syscall failure/,
      );
    });
  },
);

describe("Windows Named Pipe server verification", () => {
  const savedExpectedSid = process.env.HAAP_SDK_EXPECTED_PEER_SID;

  beforeEach(() => {
    delete process.env.HAAP_SDK_EXPECTED_PEER_SID;
    _setPeerVerifiersForTesting({ windows: null });
  });

  afterEach(() => {
    _setPeerVerifiersForTesting({ windows: null });
    if (savedExpectedSid === undefined) {
      delete process.env.HAAP_SDK_EXPECTED_PEER_SID;
    } else {
      process.env.HAAP_SDK_EXPECTED_PEER_SID = savedExpectedSid;
    }
  });

  it("rejects remote UNC pipes and traversal paths", () => {
    expect(() =>
      validateWindowsNamedPipePath("\\\\attacker\\pipe\\haap-agent-0"),
    ).toThrow(IpcError);
    expect(() =>
      validateWindowsNamedPipePath("\\\\.\\pipe\\nested\\haap-agent-0"),
    ).toThrow(IpcError);
    expect(() => validateWindowsNamedPipePath("/tmp/haap.sock")).toThrow(
      IpcError,
    );
  });

  it("rejects malformed HAAP_SDK_EXPECTED_PEER_SID", () => {
    process.env.HAAP_SDK_EXPECTED_PEER_SID = "not-a-sid";
    expect(() =>
      validateWindowsNamedPipePath("\\\\.\\pipe\\haap-a1-agent-assembler-0"),
    ).toThrow(/not a valid Windows SID/);
  });

  it("rejects untrusted pipe owner SID (negative control)", () => {
    const pipe = "\\\\.\\pipe\\haap-a1-agent-assembler-0";
    _setPeerVerifiersForTesting({
      windows: () => ({
        serverPid: 4242,
        ownerSid: "S-1-5-21-100-200-300-9999",
        currentUserSid: "S-1-5-21-100-200-300-1001",
      }),
    });
    expect(() => verifyWindowsNamedPipeServer(pipe, null)).toThrow(
      /untrusted SID/,
    );
  });

  it("rejects mismatched explicit HAAP_SDK_EXPECTED_PEER_SID", () => {
    const pipe = "\\\\.\\pipe\\haap-a1-agent-assembler-0";
    process.env.HAAP_SDK_EXPECTED_PEER_SID = "S-1-5-21-100-200-300-1001";
    const expected = validateWindowsNamedPipePath(pipe);
    _setPeerVerifiersForTesting({
      windows: () => ({
        serverPid: 4242,
        ownerSid: "S-1-5-21-100-200-300-1002",
        currentUserSid: "S-1-5-21-100-200-300-1001",
      }),
    });
    expect(() => verifyWindowsNamedPipeServer(pipe, expected)).toThrow(
      /expected S-1-5-21-100-200-300-1001/,
    );
  });

  it("accepts current user SID, LocalSystem (S-1-5-18), LocalService (S-1-5-19), and matching explicit SID", () => {
    const pipe = "\\\\.\\pipe\\haap-a1-agent-assembler-0";
    for (const ownerSid of [
      "S-1-5-21-100-200-300-1001",
      "S-1-5-18",
      "S-1-5-19",
    ]) {
      _setPeerVerifiersForTesting({
        windows: () => ({
          serverPid: 4242,
          ownerSid,
          currentUserSid: "S-1-5-21-100-200-300-1001",
        }),
      });
      expect(() => verifyWindowsNamedPipeServer(pipe, null)).not.toThrow();
    }

    process.env.HAAP_SDK_EXPECTED_PEER_SID = "s-1-5-21-100-200-300-1001";
    const expected = validateWindowsNamedPipePath(pipe);
    _setPeerVerifiersForTesting({
      windows: () => ({
        serverPid: 4242,
        ownerSid: "S-1-5-21-100-200-300-1001",
        currentUserSid: "S-1-5-21-100-200-300-9999",
      }),
    });
    expect(() => verifyWindowsNamedPipeServer(pipe, expected)).not.toThrow();
  });

  it("rejects invalid server PID 0", () => {
    const pipe = "\\\\.\\pipe\\haap-a1-agent-assembler-0";
    _setPeerVerifiersForTesting({
      windows: () => ({
        serverPid: 0,
        ownerSid: "S-1-5-18",
        currentUserSid: "S-1-5-18",
      }),
    });
    expect(() => verifyWindowsNamedPipeServer(pipe, null)).toThrow(
      /invalid server PID/,
    );
  });
});

describe.runIf(process.platform === "win32")(
  "Windows Named Pipe live server verification",
  () => {
    const savedExpectedSid = process.env.HAAP_SDK_EXPECTED_PEER_SID;

    afterEach(() => {
      if (savedExpectedSid === undefined) {
        delete process.env.HAAP_SDK_EXPECTED_PEER_SID;
      } else {
        process.env.HAAP_SDK_EXPECTED_PEER_SID = savedExpectedSid;
      }
    });

    it("accepts our own local named pipe and rejects a mismatched expected SID", async () => {
      const pipe = `\\\\.\\pipe\\hawcx-sdk-test-${process.pid}-${Date.now()}`;
      const server = net.createServer((sock) => {
        sock.on("error", () => sock.destroy());
      });
      await new Promise<void>((resolve) => server.listen(pipe, resolve));
      try {
        expect(() => verifyWindowsNamedPipeServer(pipe, null)).not.toThrow();
        expect(() =>
          verifyWindowsNamedPipeServer(pipe, "S-1-5-21-0-0-0-999999"),
        ).toThrow(/expected S-1-5-21-0-0-0-999999/);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });
  },
);

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
