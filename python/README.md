# hawcx-haap

Customer SDK for the **Hawcx Agent Authentication Protocol** (HAAP Canonical
Specification v7.2.0, Profile E). Pure-Python, no native build.

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
  Assembler + External Identity Broker + Supervisor — per HAAP CS v7.2.0
  §45.2) must be running locally, installed from the `hx_agentic_sdk`
  release.
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

Per CS v7.2.0 §34. Default per-call selector is omitted on the wire → the
Assembler uses `HttpHeader`.

## Calling an MCP server — `hawcx_haap.mcp_caller`

`invoke()` is the transport. `mcp_caller` is the layer above it for agents
whose destination is an MCP server: it builds the JSON-RPC 2.0 `tools/call`
document, routes it through `invoke()`, and — the part worth not rewriting per
agent — decides whether the answer was an allow or a deny.

```python
from hawcx_haap import Caller, McpTool, close_agent, get_agent

MAILBOX = McpTool(
    tool_id="mail.read",                             # the scope policy is written against
    url="https://mcp.example.com/servers/mail",
    name="list_messages",                            # the downstream MCP tool name
    actions=("read",),
    resource="mailbox",
    arguments={"top": 5},
)

caller = Caller(agent=get_agent(["alice@example.com"]), provider="microsoft")
try:
    decision = caller.call(MAILBOX, "alice@example.com")
    print(decision.summary())   # "ALLOW mail.read  as alice@example.com http=200"
finally:
    close_agent()
```

`Decision` is `(tool, principal, allowed, reason, reason_code, http_status,
body, request_id)`. A refusal is an outcome, not an exception — nothing here
needs a `try` around it.

**Why classification is in the SDK.** A HAAP denial arrives in three shapes and
only the first looks like a failure:

| Shape | Where it was refused | What a naive reader sees |
|---|---|---|
| `RequestRejected` (0x54) | token mint, before egress | an exception — hard to miss |
| JSON-RPC `error.code` in `-32005…-32000` (§45.7.5) | RSV MCP gateway | **HTTP 200** |
| the same error inside an SSE frame | RSV MCP gateway | **HTTP 200**, and a body that is not JSON |

The third shape is the trap. Streamable HTTP lets the server answer with a JSON
body *or* an event stream, and a real SSE frame opens with `event: message` —
so sniffing for a leading `data:` decides it is not a stream, finds no error,
and reports a denial as an allow. `_json_documents()` tries the whole body as
JSON and then scans every `data:` line unconditionally, and
`tests/test_mcp_caller.py` pins the `event: message` case.

Fail-closed both ways: `principal_allowlist` stays required all the way down,
and a body that yields no JSON-RPC document at all — empty, truncated, HTML,
non-UTF-8 — is a **deny**. Not being able to tell is not the same as being told
yes. A JSON-RPC error *outside* the HAAP range (`-32601` "method not found",
say) is a downstream fault and stays an allow; reporting it as a policy denial
would manufacture evidence of a decision nobody made.

`Caller.invoke_kwargs()` returns the `invoke()` kwargs without calling
anything, so a scope review can print the request that *would* go — feed it to
`ToolCallRequest(plaintext_request_body=body, **kwargs).to_wire()`.

The module is pure-Python and adds no dependency, so a consumer built on it
still bundles with `hawcx bundle`.

## Scaffolding an agent's config — `hawcx init`

`mcp_caller` is the code. `config.py` is the part only your tenant knows: where
each MCP server is, what the downstream tool is called, which resource, which
provider, and which principals the agent may act for. `hawcx init` writes both
halves from one `hawcx/agent-template/v1`:

```bash
hawcx init agent-template.yaml -d ./myagent
```

| File | Owner | Re-running `hawcx init` |
|---|---|---|
| `hawcx_tools.py` | `@generated` — do not edit | rewritten with `--force` |
| `config.py` | **yours** — edit and keep it | **kept**, always; `--force` does not reach it |

One `--force` cannot serve both files, which is why this is `init` rather than
a `wrap --config` flag: a flag you pass to regenerate the module would
eventually eat a config someone had spent a day filling in.

Every deployment-specific value is scaffolded as `FILL_ME`, and the file ends
in `require_filled(...)`. So an untouched config does not run:

```
ValueError: 8 unfilled config value(s): PROVIDER, PRINCIPAL_ALLOWLIST,
TOOLS['o365.mail.read'].url, TOOLS['o365.mail.read'].name, ...
```

Every gap at once, each named by its path. A commented placeholder
(`# TODO: your RS URL`) would have survived review and reached the Assembler as
a real target; this cannot leave the import.

`PRINCIPAL_ALLOWLIST` is emitted with **no default**. It is the fail-closed gate
on `acting_for_user`, so a default would be a default answer to which users the
agent may impersonate. `[]` is a real answer — "forbid runtime principal
switching entirely" — and must be something a human chose, not something the
scaffolder assumed.

Not scaffolded, on purpose: the HTTP method (MCP `tools/call` over Streamable
HTTP is POST, and `Caller.invoke_kwargs` sets it — a knob whose only correct
value is the default is a knob someone turns), and per-tool providers (a
`Caller` carries one `provider` for the destination it talks to; an agent
spanning two providers builds two `Caller`s). The generated config imports only
`hawcx_haap`, so an agent carrying it still bundles with `hawcx bundle`.

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

## Threat model — runtime principal

`HawcxAgent` supports per-call principal switching via the
``acting_for_user`` field, which the Assembler projects into
``scope_json.user_principal_id`` on the minted token (CS v6.9.0
line 163). This lets one supervisor pipeline serve multiple end-users
without re-enrolling the agent identity per user.

``acting_for_user`` is sensitive: a value that came from an LLM (or
any input the model can influence) MUST NOT be allowed to silently
switch the effective user. As of 0.1.0a2 (H-3 hardening 2026-05-20):

- ``HawcxAgent.connect(endpoint, principal_allowlist=[...])`` is
  required. The allowlist is a closed set of permitted principal IDs
  sourced from operator config.
- ``agent.invoke(acting_for_user=...)`` and ``agent.invoke_for(...)``
  validate against the allowlist before any IPC bytes are written.
  Out-of-list principals raise ``HawcxError`` synchronously with a
  redacted SHA-256 fingerprint instead of echoing the rejected
  principal back in plaintext.
- Pass ``principal_allowlist=[]`` to forbid runtime principal
  switching entirely.

Operator obligations:

1. Source the allowlist from operator-controlled config — never
   derive from LLM output, request bodies, MCP tool arguments, or any
   input a model can influence.
2. If the principal axis spans more than ~100 users, fan out to
   per-user agents rather than one agent with a wide allowlist; the
   Cedar policy on the gateway should still gate per-user access, but
   reducing the SDK-side allowlist closes the blast radius of a
   compromised supervisor.
3. The previous code that accepted ``acting_for_user`` from any
   caller (without an allowlist) is **deprecated**. See
   `../CHANGELOG.md` for the migration recipe.

## Egress transport (optional) — route agent HTTP through the broker

When a HAAP agent runs under the OS sandbox from ADR-0048, its entire
outbound network is pinned to a single per-agent UNIX-domain socket — a
SOCKS5 egress broker — and that socket is its *only* network path. A SOCKS
proxy URL has nowhere to put a filesystem path
(`socks5h:///…/egress-broker.sock` parses to an empty host), so stock SOCKS
transports, which dial `(host, port)`, cannot reach it. This SDK ships a
small transport shim that opens the UDS, performs the SOCKS5 `CONNECT`, and
hands the connected stream to `httpx` for **end-to-end** TLS + HTTP. The
broker never terminates TLS and neither does the shim — your certificate
verification is unchanged, and the broker holds no plaintext.

`httpx` is an **optional** extra (the SDK core stays zero-dependency):

```bash
pip install 'hawcx-haap[httpx]'
```

Opt in with one line — `client()` returns a ready-to-use `httpx.Client`:

```python
import hawcx_haap.egress as egress

with egress.client() as http:                 # async_client() for asyncio
    r = http.get("https://api.example.com/v1/models")
```

The broker socket is discovered from `$HAAP_EGRESS_BROKER_SOCKET`, or from
`$HAAP_AGENT_SOCKET_DIR/$HAAP_AGENT_INSTANCE_ID/egress-broker.sock` (the
paths the supervisor sets), or pass `socket_path=`. If none resolves to an
existing socket, `client()` **raises** rather than falling back to the direct
network — a silent fallback would defeat the control.

Per ADR-0048 the shim always sends the hostname as `ATYP=0x03` (DOMAINNAME)
and never resolves DNS itself, so the broker enforces its allowlist against
the name the agent actually asked for. Failures map to distinguishable
exceptions (all subclass `HawcxError`): `EgressPolicyDenied` (host:port not
in the signed policy), `EgressHostUnreachable` (includes the SSRF refusal),
`EgressPeerCredError` (the peer-credential check failed), and
`EgressProtocolError` (malformed handshake). This transport is a
network-reachability control only — it is **not** a second authorization
gate; the RSV still enforces the tool-call mandate (ADR-0048 D48-6).

## Limitations / known gaps

- End-to-end verification against real binaries is pending alpha-2 closure of
  the RSV cascade adapter. Tests use a mock Assembler over a Unix socket.
- Framework adapters (CrewAI `BaseTool`, LangChain `Tool`) are deferred to a
  Priority 2a follow-up.
- Windows Named Pipe support uses `ctypes` against `kernel32`; pytest fixtures
  exercise the Unix path only. Windows is exercised via unit tests of the
  framing layer.

## License

Hawcx Proprietary License. See [LICENSE](../LICENSE).
