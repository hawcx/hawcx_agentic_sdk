"""hawcx-haap — customer SDK for the Hawcx Agent Authentication Protocol (HAAP).

Per CS v6.7.4 §39, Profile E uses a five-process customer-side pipeline
(Authenticator, TQS-precompute, TQS-jit, Assembler, Supervisor). This SDK is
the Python entry point: it connects to a customer-deployed ``haap-supervisor``
via the Assembler's agent IPC socket and proxies tool calls through it.

The SDK does **not** spawn the supervisor — that's a separate operational
concern (Docker / systemd / SCM). Customers install the supervisor via the
``hx_agentic_sdk`` release tarball or Docker image (see the top-level
``hx_agentic_sdk`` README); this SDK connects to its already-running
Assembler over the agent socket.

Prerequisites:

- The 5-process pipeline must be running and the Assembler's agent socket
  reachable. Default path on Unix:
  ``{ipc_dir}/{agent_id}/agent-assembler-{index}.sock``. On Windows:
  ``\\\\.\\pipe\\haap-{agent_id}-agent-assembler-{index}``.
- The agent identity must be pre-provisioned via the Hawcx Admin Console
  (Console → CAA → Authenticator flow per CS §4.6.3) before the Authenticator
  can establish a session with the AS.

Quick start::

    from hawcx_haap import HawcxAgent

    with HawcxAgent.connect(
        "/var/run/haap/research-u1/agent-assembler-0.sock",
        principal_allowlist=[],  # or ["alice", "bob"] to permit runtime principal switching
    ) as agent:
        response = agent.invoke(
            target_rs_url="https://api.example.com/search",
            http_method="POST",
            headers={"Content-Type": "application/json"},
            tool="search",
            action=["read"],
            body=b'{"query": "agents"}',
        )
        # response.http_status, response.headers, response.body (bytes)

Per CS §39, the Python process never holds session keys (``response_key``,
``K_req``, ``K_resp``). All cryptographic operations happen inside the
Assembler process; the SDK exchanges only plaintext request bodies and
decrypted response bodies over the local IPC socket.
"""

from hawcx_haap.agent import HawcxAgent
from hawcx_haap.errors import (
    HandshakeError,
    HawcxError,
    IpcError,
    RequestRejected,
)
from hawcx_haap.ipc import (
    HAWCX_HAAP_V7_2_5_CAPABILITY,
    AssemblerClient,
    TokenTransport,
    ToolCallRequest,
    ToolCallResponse,
)

__version__ = "0.1.0a10"
__all__ = [
    "HawcxAgent",
    "AssemblerClient",
    "ToolCallRequest",
    "ToolCallResponse",
    "TokenTransport",
    "HAWCX_HAAP_V7_2_5_CAPABILITY",
    "HawcxError",
    "HandshakeError",
    "IpcError",
    "RequestRejected",
    "__version__",
]
