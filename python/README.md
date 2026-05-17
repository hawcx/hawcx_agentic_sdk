# hawcx-haap

Customer SDK for the **Hawcx Agent Authentication Protocol** (HAAP Canonical
Specification v6.7.4, Profile E). Pure-Python, no native build.

> **Status:** alpha (0.1.0a1). Public API may change. End-to-end testing
> against the real binary pipeline is pending alpha-2 closure of the RSV
> cascade adapter; the SDK is currently validated against a mock Assembler.

## What it does

`HawcxAgent` connects to a customer-deployed `haap-supervisor`'s
Assembler-agent socket and proxies Profile E tool calls. The supervisor and
its child processes are installed separately (via the `hx_agentic_sdk` release
tarball or Docker image); this SDK is just the language-side client.

Per CS §39, all cryptographic operations happen in the Assembler / TQS /
Authenticator processes. The Python process never holds session keys or token
material — process isolation is enforced by OS boundaries (Unix Domain Sockets
on Linux/macOS, Named Pipes with DACL on Windows per CS §39.12).

## Install

```bash
pip install hawcx-haap
```

Single pure-Python wheel; supports Python 3.10–3.13 on Linux, macOS, and
Windows.

## Prerequisites

- The `haap-supervisor` pipeline (Authenticator + TQS-precompute + TQS-jit +
  Assembler + Supervisor) must be running locally, installed from the
  `hx_agentic_sdk` release.
- The agent identity must be pre-provisioned via the Hawcx Admin Console
  (Console → CAA → Authenticator flow per CS §4.6.3).

## Quickstart

```python
from hawcx_haap import HawcxAgent

with HawcxAgent.connect("/var/run/haap/research-u1/agent-assembler-0.sock") as agent:
    response = agent.invoke(
        target_rs_url="https://api.example.com/search",
        http_method="POST",
        headers={"Content-Type": "application/json"},
        tool="search",
        action=["read"],
        body=b'{"query": "agents"}',
    )
    print(response.http_status, response.body[:200])
```

If you want the SDK to derive the socket path from an agent id:

```python
with HawcxAgent.connect_by_agent_id("research-u1") as agent:
    ...
```

This uses the conventional path
`{XDG_RUNTIME_DIR or /tmp}/hawcx/{agent_id}/agent-assembler-0.sock` on Unix
and `\\.\pipe\haap-{agent_id}-agent-assembler-0` on Windows.

## API

### `HawcxAgent.connect(endpoint, *, timeout_secs=5.0) -> HawcxAgent`

Open the agent IPC socket at `endpoint` and complete the version handshake.

### `HawcxAgent.connect_by_agent_id(agent_id, *, index=0, ipc_dir=None, timeout_secs=5.0)`

Resolve the conventional path, then `connect`.

### `.invoke(...) -> ToolCallResponse`

| Argument | Type | Notes |
|---|---|---|
| `target_rs_url` | `str` | RS endpoint URL (required) |
| `http_method` | `str` | Default `"POST"` |
| `headers` | `dict[str, str] \| None` | Extra HTTP headers |
| `tool` | `str` | Tool / endpoint identifier |
| `action` | `Iterable[str] \| None` | Permitted operations (CS §39.7) |
| `resource` | `str` | Default `"*"` |
| `constraints` | `dict \| None` | TBAC constraints |
| `body` | `bytes \| None` | Request body (maps to `plaintext_request_body`) |
| `claimed_intent_hash` | `str \| None` | For §39.4 intent verification |
| `tool_arguments` | `Any` | Structured arguments |
| `content_type` | `str \| None` | Request content type |
| `transport` | `TokenTransport \| None` | `HTTP_HEADER` (default) or `MCP_META` |
| `request_id` | `str \| None` | Defaults to `req-<uuid4-hex16>` |

Returns `ToolCallResponse(request_id, http_status, headers, body)`. The `body`
field is the decrypted RS response (`bytes`).

Raises `RequestRejected(request_id, reason)` if the Assembler rejects.

### `TokenTransport`

```python
class TokenTransport(str, Enum):
    HTTP_HEADER = "http_header"   # Authorization: HAAP <b64>
    MCP_META = "mcp_meta"         # MCP params._meta["haap/tbac"].token
```

Per CS v6.7.4 §34. Default per-call selector is omitted on the wire → the
Assembler uses `HttpHeader`.

## Wire protocol

The SDK speaks the same wire as the in-process Rust crates:

```
[msg_len: u32 BE][msg_type: u8][payload: msg_len-1 bytes]
```

- `0x00` — `IpcHandshake` (binary; see `crates/haap-ipc/src/handshake.rs`)
- `0x52` — `ToolCallRequest` (JSON)
- `0x53` — `ToolCallResponse` (JSON; `body` is base64)
- `0x54` — `RequestRejected` (JSON: `{request_id, reason}`)
- `0x61` — `ClarificationAnswer` (JSON; Profile E first hop)

Reference: `crates/haap-ipc/src/messages/assembler.rs` in `hx_labs`.

## Limitations / known gaps

- End-to-end verification against real binaries is pending alpha-2 closure of
  the RSV cascade adapter. Tests use a mock Assembler over a Unix socket.
- Framework adapters (CrewAI `BaseTool`, LangChain `Tool`) are deferred to a
  Priority 2a follow-up.
- Windows Named Pipe support uses `ctypes` against `kernel32`; pytest fixtures
  exercise the Unix path only. Windows is exercised via unit tests of the
  framing layer.

## License

Apache-2.0.
