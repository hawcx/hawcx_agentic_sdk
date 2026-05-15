# Integration

## For agent runtimes (MCP host integration)

Two integration patterns:

### Pattern 1: Supervisor-managed (recommended)

Use `haap_supervisor::AgentRuntime` to spawn the three child processes
on demand. The agent runtime only needs to interact with the
`AgentRuntime::send_request(body, audience)` async API.

```rust
use haap_supervisor::{AgentRuntime, SupervisorConfig};

let mut runtime = AgentRuntime::new(SupervisorConfig::new(
    "/usr/local/bin/haap-authenticator".into(),
    "/usr/local/bin/haap-tqs".into(),
    "/usr/local/bin/haap-assembler".into(),
)).await?;

let response_plaintext = runtime.send_request(
    serde_json::to_vec(&mcp_request)?,
    audience_url,
).await?;
```

### Pattern 2: External Supervisor + IPC client

If the agent runtime is itself a long-lived daemon, spawn the three
Hawcx binaries via systemd / launchd / a process manager, and connect
to `assembler.sock` directly:

```rust
use haap_sdk_ipc::{IpcClient, ipc_socket_path};
use haap_sdk_types::IpcMessage;

let path = ipc_socket_path("assembler.sock")?;
let mut conn = IpcClient::connect(&path).await?;
conn.send(&IpcMessage::AssembleRequest { body, audience }).await?;
// ...
```

The IPC layer enforces SO_PEERCRED, so a daemon running as a different
UID will be rejected.

## For MCP servers (server-side integration)

Use `haap_rsv::Rsv` as middleware:

```rust
use haap_rsv::{Rsv, ReplayStore, VerifiedRequest};
use haap_substrate_reader::CustomerSubstrateReader;

let substrate = CustomerSubstrateReader::connect(&customer_redis_url).await?;
let replay = ReplayStore::new(substrate.connection(), 4096);
let mut rsv = Rsv::new(substrate, replay, my_audience_hash);

// per request:
let verified: VerifiedRequest = rsv.verify_and_decrypt(&token_bytes).await?;
let plaintext = verified.plaintext_body;
// ... handle the MCP call ...
let encrypted_response = rsv.encrypt_response(&verified, &response_bytes)?;
```

The 16-step cascade is encapsulated inside `verify_and_decrypt`. Each
negative path returns a distinct `VerifyError` variant; treat all as
"reject the request" rather than branching on the specific error.

## For CAA developers (`hx_agent_client_admin_service`)

The CAA writes `SubstrateMaterial` to customer Redis under
`haap:session:{u64_session_id:016x}` using bincode serialization. The
SDK's `CustomerSubstrateReader` reads from the same key with matching
bincode deserialization.

`SubstrateMaterial` schema (Rust):

```rust
pub struct SubstrateMaterial {
    pub session_id: u64,
    pub k_session_root: [u8; 32],
    pub verifier_secret: [u8; 32],
    pub scope: String,
    pub billing_context: String,
    pub current_epoch_id: u64,
    pub aud_hash: [u8; 32],
}
```

Keep the field order stable — bincode is positional and reordering
breaks the wire format. Add new fields at the end.

## Examples

End-to-end runnable examples are in [`../examples/`](../examples/):

- `basic_registration.rs` — minimal env-driven agent registration
- `full_pipeline.rs` — end-to-end MCP request through Supervisor
- `rsv_standalone.rs` — standalone HTTP-listening RSV
- `mcp_server_integration.rs` — full MCP server using RSV as middleware
