"""hawcx-haap — customer SDK for the Hawcx Agent Authentication Protocol (HAAP).

Per CS v7.2.5 §39, Profile E uses a five-process customer-side pipeline
(Authenticator, TQS-precompute, TQS-jit, Assembler, Supervisor). This SDK is
the Python entry point: it connects to a customer-deployed ``haap-supervisor``
via the Assembler's agent IPC socket and proxies tool calls through it.

The ``hawcx-manager`` binary (supervisor, authenticator, assembler, and all
pipeline components) is bundled with this package and installed automatically
via pip. Use ``hawcx_haap.get_binary_path()`` to obtain its path for
subprocess invocation or supervisor management.

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

Calling an MCP server through HAAP is a layer up from ``invoke``: see
:mod:`hawcx_haap.mcp_caller` for :class:`Caller`, :class:`McpTool` and
:class:`Decision`, which build the JSON-RPC ``tools/call`` document and — the
part worth not rewriting per agent — classify the answer, including a denial
delivered inside an HTTP 200 or wrapped in an SSE frame.

``hawcx init`` scaffolds the deployment config that layer consumes (the tools,
the provider, the principal allowlist). ``FILL_ME`` and ``require_filled`` are
what make an unfilled value in it raise at import rather than look configured.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from hawcx_haap._binary import get_binary_path
from hawcx_haap.agent import HawcxAgent
from hawcx_haap.auth_ipc import (
    AuthenticatorClient,
    EnrollmentRejected,
    EnrollmentResult,
)
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
from hawcx_haap.mcp_caller import (
    FILL_ME,
    HAWCX_REJECT_CODES,
    Caller,
    Decision,
    McpTool,
    close_agent,
    env_principal_allowlist,
    get_agent,
    require_filled,
)

# Single source of truth is [project] version in pyproject.toml; resolved from
# the installed distribution so it cannot drift from the published wheel.
try:
    __version__ = _dist_version("hawcx-haap")
except PackageNotFoundError:  # imported from a source tree without an install
    __version__ = "0.0.0+unknown"
__all__ = [
    "get_binary_path",
    "HawcxAgent",
    "AssemblerClient",
    "AuthenticatorClient",
    "EnrollmentResult",
    "EnrollmentRejected",
    "ToolCallRequest",
    "ToolCallResponse",
    "TokenTransport",
    "HAWCX_HAAP_V7_2_5_CAPABILITY",
    # MCP tool calling (hawcx_haap.mcp_caller)
    "Caller",
    "McpTool",
    "Decision",
    "get_agent",
    "close_agent",
    "env_principal_allowlist",
    "HAWCX_REJECT_CODES",
    # Scaffolded config (`hawcx init`)
    "FILL_ME",
    "require_filled",
    "HawcxError",
    "HandshakeError",
    "IpcError",
    "RequestRejected",
    "__version__",
]
