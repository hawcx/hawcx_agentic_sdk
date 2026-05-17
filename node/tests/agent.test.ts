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

describe("HawcxAgent", () => {
  let mock: MockAssembler;

  beforeEach(async () => {
    mock = new MockAssembler();
    await mock.start();
  });

  afterEach(async () => {
    await mock.close();
  });

  it("invoke round-trip echoes the body", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath);
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
    const agent = await HawcxAgent.connect(mock.socketPath);
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
    const agent = await HawcxAgent.connect(mock.socketPath);
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
    const agent = await HawcxAgent.connect(mock.socketPath);
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
    const agent = await HawcxAgent.connect(mock.socketPath);
    agent.close();
    expect(() => agent.close()).not.toThrow();
  });

  it("uppercases the http method", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath);
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

describe("invoke transports", () => {
  let mock: MockAssembler;

  beforeEach(async () => {
    mock = new MockAssembler();
    await mock.start();
  });

  afterEach(async () => {
    await mock.close();
  });

  it("snake_cases TokenTransport.McpMeta on the wire", async () => {
    const agent = await HawcxAgent.connect(mock.socketPath);
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
