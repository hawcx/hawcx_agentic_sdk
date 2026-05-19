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

## Authorizer selection

The cascade's `Authorizer` decision belongs to the operator. The
default constructor (`Rsv::new`) uses `PermissiveAuthorizer` —
suitable for alpha deployments where the cascade's Step 10 ceiling
check is the protection floor. Operators ready to enforce
registration-scope binding (CS v6.8.0 §9.1.X, W4) have three options:

- `Rsv::new_with_authorizer(config, Box::new(RegistrationScopeAuthorizer))`
  — explicit, no env coupling.
- `Rsv::new_from_env(config)` — reads `HAWCX_RSV_AUTHORIZER`:

  | Value           | Authorizer                          |
  |-----------------|-------------------------------------|
  | (unset / empty) | `PermissiveAuthorizer` (default)    |
  | `permissive`    | `PermissiveAuthorizer`              |
  | `strict`        | `RegistrationScopeAuthorizer`       |

  Matching is ASCII case-insensitive (`strict`, `STRICT`, ` strict ` all
  work). Unknown values are rejected fail-fast — silent
  fallback-to-permissive is the classic "I thought strict was on but
  it isn't" foot-gun, so we refuse to start.

- Custom impl — wrap any `dyn haap_core::types::Authorizer` and pass
  via `new_with_authorizer`. Cedar-backed, composite, etc.

**Strict-mode prerequisite.** Switching to `strict` requires that
enrolled agents have `registered_scope_json` populated in substrate
(populated by the AS at v6.9.0 `/v3/register_agent` per the W4
workstream). Pre-v6.9.0 sessions without it fall through to
permissive semantics at the per-session level via
`RegistrationScopeAuthorizer`'s `None` branch — this is the
documented graceful-fallback contract. The global selector says
"strict"; the per-session fall-through avoids bricking verification
on a mixed-vintage substrate during rollout.

## See also

For a network-fronted variant (HTTP API sidecar), see the
`haap-rsv-bin` companion crate in the SDK workspace. The bin reads
`HAWCX_RSV_AUTHORIZER` at startup (via `Rsv::new_from_env`) so the
sidecar inherits the same selection model.
