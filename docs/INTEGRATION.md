# Integration

Three paths depending on what you're integrating:

## Path 1 — Customer agent runtime (MCP host)

Install the tarball or Docker image. Run `haap-supervisor` (directly
or via `haap-sdk run-pipeline`). The agent runtime talks to the
Assembler over a UDS — refer to the `hx_labs` Assembler IPC docs for
the protocol.

## Path 2 — Rust MCP server with `haap-rsv` library embed

```toml
[dependencies]
haap-rsv = "0.1.0-alpha.1"
haap-sdk-types = { path = "..." } # private during alpha
tokio = { version = "1", features = ["full"] }
```

```rust
use haap_rsv::Rsv;
use haap_sdk_types::RsvConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rsv = Rsv::new(RsvConfig::from_env()?).await?;

    // Per-request:
    let verified = rsv.verify_and_decrypt(&token_bytes).await?;
    let plaintext = &verified.plaintext_body;
    // ... your MCP server handler runs here ...
    let response_bytes = handle(plaintext).await?;
    let encrypted = rsv.encrypt_response(&verified, &response_bytes)?;

    // Return encrypted bytes over your transport.
    Ok(())
}
```

See [`crates/haap-rsv/examples/embedded_rsv.rs`](../crates/haap-rsv/examples/embedded_rsv.rs)
for a runnable skeleton.

## Path 3 — Cross-language MCP server with HTTP sidecar

Spawn `haap-rsv` (the binary) alongside your MCP server. The server
makes HTTP calls to the sidecar — see [`RSV_HTTP_API.md`](RSV_HTTP_API.md).

```python
# Python example
import base64, httpx

async with httpx.AsyncClient() as client:
    r = await client.post(
        "http://127.0.0.1:8443/verify",
        json={"token_b64": base64.b64encode(token_bytes).decode()},
    )
    if r.status_code != 200:
        raise RuntimeError(f"verify rejected: {r.json()}")
    verified = r.json()
    plaintext = base64.b64decode(verified["plaintext_b64"])
    handle = verified["verification_handle"]

    # ... handle the request ...
    response = handle_request(plaintext)

    enc = await client.post(
        "http://127.0.0.1:8443/encrypt-response",
        json={"verification_handle": handle,
              "plaintext_b64": base64.b64encode(response).decode()},
    )
    encrypted = base64.b64decode(enc.json()["ciphertext_b64"])
    # ... return encrypted over your transport ...
```

## For CAA developers (`hx_agent_client_admin_service`)

The CAA writes `SubstrateMaterial` to customer Redis under
`haap:session:<u64_session_id_decimal>` using bincode serialization.
The SDK's `haap-substrate-reader` reads from the same key with
matching bincode deserialization. `SubstrateMaterial` schema:

```rust
pub struct SubstrateMaterial {
    pub session_id: u64,
    pub k_session_root: [u8; 32],
    pub verifier_secret: [u8; 32],
    pub scope: String,
    pub policy_epoch: u64,
}
```

Keep field order stable. Add new fields at the end.

## Examples

- [`crates/haap-rsv/examples/embedded_rsv.rs`](../crates/haap-rsv/examples/embedded_rsv.rs) —
  Rust MCP server embedding RSV in-process.
- [`crates/haap-sdk-cli/examples/full_pipeline.rs`](../crates/haap-sdk-cli/examples/full_pipeline.rs) —
  customer-runtime end-to-end demo.
