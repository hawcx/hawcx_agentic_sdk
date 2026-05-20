/**
 * Minimal HawcxAgent example.
 *
 * Prerequisites:
 *
 * - The customer-side `haap-supervisor` pipeline must be running (installed
 *   via the `hx_agentic_sdk` release tarball or Docker image).
 * - The agent identity must be pre-provisioned via the Hawcx Admin Console
 *   (Console → CAA → Authenticator flow per CS v6.7.4 §4.6.3).
 * - `HAAP_AGENT_ID` (or pass it explicitly) identifies which provisioned
 *   agent's socket to attach to.
 */

import { Buffer } from "node:buffer";
import * as process from "node:process";

import { HawcxAgent, RequestRejected } from "@hawcx/hawcx-haap";

async function main(): Promise<number> {
  const agentId = process.env.HAAP_AGENT_ID;
  if (!agentId) {
    console.error("set HAAP_AGENT_ID to the provisioned agent identity");
    return 2;
  }

  // H-3: pass `principalAllowlist: []` because this example never uses
  // runtime principal switching. A real deployment that fans out tool
  // calls per end-user populates this from operator config.
  const agent = await HawcxAgent.connectByAgentId(agentId, {
    principalAllowlist: [],
  });
  try {
    const response = await agent.invoke({
      targetRsUrl: "https://api.example.com/search",
      httpMethod: "POST",
      headers: { "Content-Type": "application/json" },
      tool: "search",
      action: ["read"],
      body: Buffer.from('{"query": "agent authentication"}'),
    });
    console.log(`http_status=${response.httpStatus}`);
    console.log(`body[:200]=${response.body.subarray(0, 200).toString()}`);
    return 0;
  } catch (err) {
    if (err instanceof RequestRejected) {
      console.error(`Assembler rejected: ${err.reason}`);
      return 1;
    }
    throw err;
  } finally {
    agent.close();
  }
}

main().then((code) => process.exit(code));
