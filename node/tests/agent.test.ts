/**
 * HawcxAgent tests against the in-process MockAssembler.
 */

import { Buffer } from "node:buffer";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  HawcxAgent,
  RequestRejected,
  TokenTransport,
  defaultEndpointFor,
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

  it("omits acting_for_user from the wire when not set", async () => {
    // Backward-compat: existing callers must observe identical wire shape.
    const agent = await HawcxAgent.connect(mock.socketPath, {
      principalAllowlist: ["alice", "bob"],
    });
    try {
      await agent.invoke({
        targetRsUrl: "https://api.example.com/echo",
        httpMethod: "POST",
        tool: "echo",
        body: Buffer.from("x"),
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
});
