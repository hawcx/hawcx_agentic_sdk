# haap-rsv

Hawcx HAAP Verifier — embeddable §9 16-step verification cascade for
MCP server operators.

## What it does

Wraps `haap_core::cascade::verify_and_decrypt_request` (the canonical
16-step cascade implementation from hx_labs) with two additional
concerns specific to MCP server deployments:

1. **Customer Redis substrate access** — looks up `SessionRecord` for
   the session_id parsed from the incoming token.
2. **Replay enforcement** — two-tier (in-process LRU + Redis SETNX with
   per-token TTL).

The cascade itself is NOT reimplemented; this crate is a thin
orchestration layer.

## Usage

```rust
use haap_rsv::Rsv;
use haap_sdk_types::RsvConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut rsv = Rsv::new(RsvConfig::from_env()?).await?;

    // Per-request:
    let verified = rsv.verify_and_decrypt(&token_bytes).await?;
    let plaintext = &verified.plaintext_body;
    // ... handle MCP call, produce response_bytes ...
    let encrypted = rsv.encrypt_response(&verified, &response_bytes)?;
    Ok(())
}
```

## See also

For a network-fronted variant (HTTP API sidecar), see the
`haap-rsv-bin` companion crate in the SDK workspace.
