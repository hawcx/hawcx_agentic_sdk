"""Minimal HawcxAgent example.

Prerequisites:

- The customer-side ``haap-supervisor`` pipeline must be running (installed
  via the hx_agentic_sdk release tarball or Docker image).
- The agent identity must be pre-provisioned via the Hawcx Admin Console
  (Console → CAA → Authenticator flow per CS v6.7.4 §4.6.3).
- ``HAAP_AGENT_ID`` (or pass it explicitly) identifies which provisioned
  agent's socket to attach to.
"""

from __future__ import annotations

import os
import sys

from hawcx_haap import HawcxAgent


def main() -> int:
    agent_id = os.environ.get("HAAP_AGENT_ID")
    if not agent_id:
        print("set HAAP_AGENT_ID to the provisioned agent identity", file=sys.stderr)
        return 2

    with HawcxAgent.connect_by_agent_id(agent_id) as agent:
        response = agent.invoke(
            target_rs_url="https://api.example.com/search",
            http_method="POST",
            headers={"Content-Type": "application/json"},
            tool="search",
            action=["read"],
            body=b'{"query": "agent authentication"}',
        )
        print(f"http_status={response.http_status}")
        print(f"body[:200]={response.body[:200]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
