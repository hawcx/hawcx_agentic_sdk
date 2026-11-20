/**
 * HawcxAgent tests against the in-process MockAssembler.
 */

import { Buffer } from "node:buffer";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  EnrollmentRejected,
  HawcxAgent,
  HawcxError,
  IpcError,
  MSG_REGISTER_REQ,
  MSG_REGISTER_RESP,
  RequestRejected,
  TokenTransport,
  defaultAuthControlSocketFor,
  defaultEndpointFor,
  encodeFrame,
} from "../src";

import { MockAssembler } from "./mockAssembler";

// Skips on Windows: MockAssembler binds a Unix domain socket which the
// Windows GHA runner rejects with EACCES. Named-pipe parity for the
// Node binding is tracked as a follow-up (see ipc.test.ts comment).
describe.skipIf(process.platform === "win32")("HawcxAgent", () => {
  let mock: MockAssembler;

  beforeEach(async () => {
    mock = new MockAssembler();
    await mock.start();
  });

  afterEach(async () => {
    await mock.close();
  });

  it("invoke round-trip echoes the body", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      const resp = await agent.invoke({
        actingForUser: null,
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        headers: { "Content-Type": "application/json" },
        tool: "echo",
        action: ["read"],
        body: Buffer.from('{"query": "hello"}'),
      });
      expect(resp.httpStatus).toBe(200);
      expect(resp.body.toString()).toBe('{"query": "hello"}');
    } finally {
      agent.close();
    }
    const req = mock.receivedRequest!;
    expect(req.target_rs_url).toBe("https://api.example.com/echo");
    expect(req.tool).toBe("echo");
    expect(req.action).toEqual(["read"]);
    expect(req.headers["Content-Type"]).toBe("application/json");
  });

  it("auto-generates request_id when caller does not supply one", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        actingForUser: null,
        targetRsUrl: "https://example.com",
        httpMethod: "GET",
        tool: "fetch",
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.request_id).toMatch(/^req-/);
  });

  it("preserves caller-supplied request_id", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        actingForUser: null,
        targetRsUrl: "https://example.com",
        httpMethod: "GET",
        tool: "fetch",
        requestId: "my-id-007",
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.request_id).toBe("my-id-007");
  });

  it("throws RequestRejected when Assembler rejects", async () => {
    mock.rejectWith("intent verification failed");
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await expect(
        agent.invoke({
        actingForUser: null,
          targetRsUrl: "https://forbidden.example.com",
          httpMethod: "GET",
          tool: "x",
        }),
      ).rejects.toBeInstanceOf(RequestRejected);
    } finally {
      agent.close();
    }
  });

  it("close is idempotent", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    agent.close();
    expect(() => agent.close()).not.toThrow();
  });

  it("uppercases the http method", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        actingForUser: null,
        targetRsUrl: "https://example.com",
        httpMethod: "post",
        tool: "x",
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.http_method).toBe("POST");
  });
});

describe("defaultEndpointFor", () => {
  it("computes the Unix socket path", () => {
    if (process.platform === "win32") return; // skip on Windows
    const endpoint = defaultEndpointFor("research-u1", {
      ipcDir: "/var/run/haap",
    });
    expect(endpoint).toBe("/var/run/haap/research-u1/agent-assembler-0.sock");
  });

  it("supports custom index", () => {
    if (process.platform === "win32") return;
    const endpoint = defaultEndpointFor("research-u1", {
      index: 3,
      ipcDir: "/var/run/haap",
    });
    expect(endpoint).toBe("/var/run/haap/research-u1/agent-assembler-3.sock");
  });
});

describe.skipIf(process.platform === "win32")("runtime principal switching (acting_for_user)", () => {
  let mock: MockAssembler;

  beforeEach(async () => {
    mock = new MockAssembler();
    await mock.start();
  });

  afterEach(async () => {
    await mock.close();
  });

  it("throws when the actingForUser key is omitted (no silent unprincipled default)", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await expect(
        // @ts-expect-error actingForUser is now a required key (Ask 2)
        agent.invoke({
          targetRsUrl: "https://api.example.com/echo",
          httpMethod: "POST",
          tool: "echo",
          body: Buffer.from("x"),
        }),
      ).rejects.toThrow(/actingForUser is required/);
    } finally {
      agent.close();
    }
    // The `rejects.toThrow` above proves the throw fires before any IPC write.
  });

  it("explicit null omits acting_for_user from the wire (unprincipled, pre-field bytes)", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        tool: "echo",
        body: Buffer.from("x"),
        actingForUser: null,
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest).toBeDefined();
    expect("acting_for_user" in (mock.receivedRequest ?? {})).toBe(false);
  });

  it("places acting_for_user at the top level (not in constraints) when set", async () => {
    // Per CS v6.9.0 line 163 the Assembler projects this into
    // scope_json.user_principal_id. Nesting it inside `constraints`
    // would silently land it under scope_json.constraints.* and miss
    // any Cedar policy that reads context.user_principal_id.
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        tool: "read",
        actingForUser: "alice",
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.acting_for_user).toBe("alice");
    expect(mock.receivedRequest?.constraints?.acting_for_user).toBeUndefined();
  });

  it("invokeFor(...) is equivalent to invoke({ actingForUser })", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invokeFor("bob", {
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        tool: "read",
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.acting_for_user).toBe("bob");
  });

  it("invoke({ actingForUser: <out-of-allowlist> }) throws before IPC", async () => {
    // H-3 hardening: an LLM-derived principal MUST NOT silently
    // switch the effective user. The SDK validates against the
    // construction-time allowlist before any IPC bytes are written.
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice"],
    });
    try {
      await expect(
        agent.invoke({
          targetRsUrl: "https://api.example.com/echo",
          httpMethod: "POST",
          tool: "read",
          actingForUser: "eve", // not in allowlist
        }),
      ).rejects.toThrow(/principalAllowlist/);
      // No request was forwarded to the mock — the throw fires before
      // the IPC write. (MockAssembler initialises receivedRequest to
      // `null`, not `undefined`, so a falsy check is the right shape.)
      expect(mock.receivedRequest).toBeFalsy();
    } finally {
      agent.close();
    }
  });

  it("invokeFor on an out-of-allowlist principal throws", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice"],
    });
    try {
      await expect(
        agent.invokeFor("eve", {
          targetRsUrl: "https://api.example.com/echo",
          httpMethod: "POST",
          tool: "read",
        }),
      ).rejects.toThrow(/principalAllowlist/);
    } finally {
      agent.close();
    }
  });

  it("connect() with no principalAllowlist throws synchronously", async () => {
    // Required parameter — TypeScript catches this at compile time,
    // but JS callers (or `as any` escapes) must hit a runtime guard.
    await expect(
      // @ts-expect-error - intentionally omitting required field
      HawcxAgent.connect(mock.socketPath, {}),
    ).rejects.toThrow(/principalAllowlist/);
  });

  it("empty principalAllowlist forbids any actingForUser", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: [],
    });
    try {
      await expect(
        agent.invoke({
          targetRsUrl: "https://api.example.com/echo",
          httpMethod: "POST",
          tool: "read",
          actingForUser: "alice",
        }),
      ).rejects.toThrow(/principalAllowlist/);
      // But an unprincipled call still works.
      await agent.invoke({
        actingForUser: null,
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        tool: "read",
      });
      expect(mock.receivedRequest).toBeDefined();
      expect("acting_for_user" in (mock.receivedRequest ?? {})).toBe(false);
    } finally {
      agent.close();
    }
  });

  it("invokeFor rejects an empty principal", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await expect(
        agent.invokeFor("", {
          targetRsUrl: "https://api.example.com/echo",
          httpMethod: "POST",
          tool: "x",
        }),
      ).rejects.toThrow(/userPrincipalId/);
    } finally {
      agent.close();
    }
  });
});

describe.skipIf(process.platform === "win32")("invoke transports", () => {
  let mock: MockAssembler;

  beforeEach(async () => {
    mock = new MockAssembler();
    await mock.start();
  });

  afterEach(async () => {
    await mock.close();
  });

  it("snake_cases TokenTransport.McpMeta on the wire", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        actingForUser: null,
        targetRsUrl: "https://mcp.example.com",
        httpMethod: "POST",
        tool: "search",
        transport: TokenTransport.McpMeta,
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.transport).toBe("mcp_meta");
  });

  it("forwards mcpToolName via invoke and invokeFor", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice"],
    });
    try {
      await agent.invokeFor("alice", {
        targetRsUrl: "https://mcp.example.com",
        httpMethod: "POST",
        tool: "docs.read",
        mcpToolName: "read-doc",
        transport: TokenTransport.McpMeta,
      });
    } finally {
      agent.close();
    }
    expect(mock.receivedRequest?.tool).toBe("docs.read");
    expect(mock.receivedRequest?.mcp_tool_name).toBe("read-doc");
    expect(mock.receivedRequest?.acting_for_user).toBe("alice");
  });
});

class MockAuthenticator {
  receivedPayload: Record<string, unknown> | null = null;
  private server: net.Server | null = null;
  private response: Record<string, unknown> = {
    type: "Enrolled",
    agent_instance_id: "aid-001",
    client_id: "client-001",
    ik_fingerprint: "ab".repeat(32),
    session_id: "sess-001",
  };

  constructor(readonly socketPath: string) {}

  respondWith(response: Record<string, unknown>): void {
    this.response = response;
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((sock) => {
        let buf = Buffer.alloc(0);
        sock.on("data", (chunk: Buffer) => {
          buf = Buffer.concat([buf, chunk]);
          if (buf.length < 4) return;
          const msgLen = buf.readUInt32BE(0);
          if (buf.length < 4 + msgLen) return;
          const msgType = buf.readUInt8(4);
          const payload = buf.subarray(5, 4 + msgLen);
          if (msgType !== MSG_REGISTER_REQ) {
            sock.destroy();
            return;
          }
          this.receivedPayload = JSON.parse(
            payload.toString("utf-8"),
          ) as Record<string, unknown>;
          const body = Buffer.from(JSON.stringify(this.response), "utf-8");
          sock.write(encodeFrame(MSG_REGISTER_RESP, body));
        });
        sock.on("error", () => sock.destroy());
      });
      this.server.on("error", reject);
      this.server.listen(this.socketPath, () => {
        this.server!.off("error", reject);
        resolve();
      });
    });
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }
}

describe("defaultAuthControlSocketFor", () => {
  const savedOverride = process.env.HAAP_AUTH_CONTROL_SOCK;

  afterEach(() => {
    if (savedOverride === undefined) {
      delete process.env.HAAP_AUTH_CONTROL_SOCK;
    } else {
      process.env.HAAP_AUTH_CONTROL_SOCK = savedOverride;
    }
  });

  it("computes the canonical Unix control socket path", () => {
    if (process.platform === "win32") return;
    delete process.env.HAAP_AUTH_CONTROL_SOCK;
    expect(
      defaultAuthControlSocketFor("researcher", { ipcDir: "/var/run/haap" }),
    ).toBe("/var/run/haap/researcher/auth-control.sock");
  });

  it("honors HAAP_AUTH_CONTROL_SOCK override", () => {
    process.env.HAAP_AUTH_CONTROL_SOCK = "/custom/path/auth.sock";
    expect(defaultAuthControlSocketFor("ignored")).toBe(
      "/custom/path/auth.sock",
    );
  });
});

describe.skipIf(process.platform === "win32")("HawcxAgent.enroll", () => {
  let baseDir: string;
  let auth: MockAuthenticator;
  let asmServer: net.Server;
  const savedExpectedUid = process.env.HAAP_SDK_EXPECTED_PEER_UID;
  const savedAuthOverride = process.env.HAAP_AUTH_CONTROL_SOCK;

  beforeEach(async () => {
    delete process.env.HAAP_SDK_EXPECTED_PEER_UID;
    delete process.env.HAAP_AUTH_CONTROL_SOCK;
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "hx-enroll-"));
    fs.chmodSync(baseDir, 0o700);

    const authDir = path.join(baseDir, "researcher");
    fs.mkdirSync(authDir, { mode: 0o700 });
    auth = new MockAuthenticator(path.join(authDir, "auth-control.sock"));
    await auth.start();

    const asmDir = path.join(baseDir, "aid-001");
    fs.mkdirSync(asmDir, { mode: 0o700 });
    const asmPath = path.join(asmDir, "agent-assembler-0.sock");
    asmServer = net.createServer((sock) => {
      let handshakeDone = false;
      let buf = Buffer.alloc(0);
      sock.on("data", (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        while (buf.length >= 4) {
          const msgLen = buf.readUInt32BE(0);
          if (buf.length < 4 + msgLen) return;
          const msgType = buf.readUInt8(4);
          const payload = buf.subarray(5, 4 + msgLen);
          buf = Buffer.from(buf.subarray(4 + msgLen));
          if (!handshakeDone) {
            const reply = Buffer.allocUnsafe(9);
            reply.writeUInt16BE(1, 0);
            reply.writeUInt16BE(0, 2);
            reply.writeUInt16BE(5, 4);
            reply.writeUInt16BE(0, 6);
            reply.writeUInt8(0x05, 8);
            sock.write(encodeFrame(0x00, reply));
            handshakeDone = true;
          } else if (msgType === 0x52) {
            const req = JSON.parse(payload.toString("utf-8")) as {
              request_id: string;
            };
            const resp = Buffer.from(
              JSON.stringify({
                request_id: req.request_id,
                http_status: 200,
                headers: {},
                body: Buffer.from("enrolled-ok").toString("base64"),
              }),
              "utf-8",
            );
            sock.write(encodeFrame(0x53, resp));
          }
        }
      });
      sock.on("error", () => sock.destroy());
    });
    await new Promise<void>((resolve) => asmServer.listen(asmPath, resolve));
  });

  afterEach(async () => {
    if (savedExpectedUid === undefined) {
      delete process.env.HAAP_SDK_EXPECTED_PEER_UID;
    } else {
      process.env.HAAP_SDK_EXPECTED_PEER_UID = savedExpectedUid;
    }
    if (savedAuthOverride === undefined) {
      delete process.env.HAAP_AUTH_CONTROL_SOCK;
    } else {
      process.env.HAAP_AUTH_CONTROL_SOCK = savedAuthOverride;
    }
    await auth.close();
    await new Promise<void>((resolve) => asmServer.close(() => resolve()));
    fs.rmSync(baseDir, { recursive: true, force: true });
  });

  it("drives Authenticator control socket and returns a connected HawcxAgent", async () => {
    const agent = await HawcxAgent.enroll({
      name: "researcher",
      orgToken: "ot-test-token-XYZ",
      principalAllowlist: ["alice"],
      ipcDir: baseDir,
    });
    try {
      expect(auth.receivedPayload).toEqual({
        agent_class: "default",
        subject_user_id: "researcher",
        org_token: "ot-test-token-XYZ",
        prepared_agent_id: "researcher",
      });
      expect(agent.enrollment).toEqual({
        agentInstanceId: "aid-001",
        clientId: "client-001",
        ikFingerprint: "ab".repeat(32),
        sessionId: "sess-001",
        alreadyEnrolled: false,
      });
      const resp = await agent.invoke({
        actingForUser: "alice",
        targetRsUrl: "https://api.example.com/ping",
        httpMethod: "GET",
        tool: "ping",
      });
      expect(resp.body.toString()).toBe("enrolled-ok");
    } finally {
      agent.close();
    }
  });

  it("handles AlreadyEnrolled as a success path", async () => {
    auth.respondWith({
      type: "AlreadyEnrolled",
      agent_instance_id: "aid-001",
      client_id: "client-001",
      ik_fingerprint: "ab".repeat(32),
      session_id: "sess-001",
      trust_level: "Enrolled",
    });
    const agent = await HawcxAgent.enroll({
      name: "researcher",
      orgToken: "ot-test",
      principalAllowlist: [],
      ipcDir: baseDir,
    });
    try {
      expect(agent.enrollment?.alreadyEnrolled).toBe(true);
      expect(agent.enrollment?.trustLevel).toBe("Enrolled");
    } finally {
      agent.close();
    }
  });

  it("throws EnrollmentRejected on Degraded response with agentInstanceId", async () => {
    auth.respondWith({
      type: "Degraded",
      agent_instance_id: "aid-001",
      reason: "tqs policy push failed: connection refused",
    });
    await expect(
      HawcxAgent.enroll({
        name: "researcher",
        orgToken: "ot-test",
        principalAllowlist: [],
        ipcDir: baseDir,
      }),
    ).rejects.toSatisfy(
      (err: unknown) =>
        err instanceof EnrollmentRejected &&
        err.reason.includes("tqs policy push") &&
        err.agentInstanceId === "aid-001",
    );
  });

  it("throws EnrollmentRejected on generic error envelope", async () => {
    auth.respondWith({ error: "invalid RegisterAgent payload" });
    await expect(
      HawcxAgent.enroll({
        name: "researcher",
        orgToken: "ot-test",
        principalAllowlist: [],
        ipcDir: baseDir,
      }),
    ).rejects.toSatisfy(
      (err: unknown) =>
        err instanceof EnrollmentRejected &&
        err.reason.includes("invalid") &&
        err.agentInstanceId === null,
    );
  });

  it("rejects empty name or empty orgToken before IPC", async () => {
    await expect(
      HawcxAgent.enroll({
        name: "",
        orgToken: "ot-x",
        principalAllowlist: [],
        ipcDir: baseDir,
      }),
    ).rejects.toBeInstanceOf(HawcxError);
    await expect(
      HawcxAgent.enroll({
        name: "researcher",
        orgToken: "",
        principalAllowlist: [],
        ipcDir: baseDir,
      }),
    ).rejects.toBeInstanceOf(HawcxError);
    expect(auth.receivedPayload).toBeNull();
  });

  it("rejects mismatched peer UID on Authenticator control socket before sending orgToken", async () => {
    process.env.HAAP_SDK_EXPECTED_PEER_UID = String(process.getuid!() + 1);
    await expect(
      HawcxAgent.enroll({
        name: "researcher",
        orgToken: "ot-must-not-leak",
        principalAllowlist: [],
        ipcDir: baseDir,
      }),
    ).rejects.toBeInstanceOf(IpcError);
    expect(auth.receivedPayload).toBeNull();
  });
});
