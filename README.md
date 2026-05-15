# HAAP Agentic SDK

Customer-side and MCP-server-side Rust SDK for the **Hawcx Agent
Authentication Protocol** (HAAP Canonical Specification v6.7.4).

> **Status: alpha (initial population).** Public API may change.
> This repository was created from an empty remote on 2026-05-28 and
> path-deps to its sibling `~/Projects/hx_labs/` for protocol crypto.

## What it provides

HAAP needs five customer-deployable components (plus a shared substrate
reader). This SDK packages them:

| Crate | Side | Role |
|---|---|---|
| `haap-authenticator` | MCP host | Holds IK_i; performs X3DH against AS; exposes K_session via IPC |
| `haap-tqs` | MCP host | Pre-mints batches of access tokens (RECOMMENDED 10/batch, 60s TTL) |
| `haap-assembler` | MCP host | Single-flight enforcement; K_req encrypt + K_resp decrypt |
| `haap-supervisor` | MCP host | Spawns the three child processes; AgentRuntime facade |
| `haap-rsv` | MCP server | HAAP Verifier — 16-step cascade per §9 |
| `haap-substrate-reader` | shared | Reads SessionMaterial from customer Redis |

Plus three SDK-internal crates:

- `haap-sdk-types` — shared types, errors, env-var config readers
- `haap-sdk-ipc` — Unix domain socket IPC with SO_PEERCRED enforcement
- `haap-sdk-sealer` — `AgentIdentitySealer` trait + FileSealer +
  OsKeychainSealer + KmsWrappedSealer (stub)
- `haap-sdk-cli` — `haap-sdk` testing/demo CLI binary

## Build prerequisites

The SDK uses path-deps to `~/Projects/hx_labs/` for the canonical HAAP
protocol crates (`haap-core`, `haap-crypto`, `haap-ipc`, `haap-auth`,
`haap-wire`, `haap-keystore`, `haap-redis`, `haap-as-client`). Both
repos must live side-by-side under `~/Projects/`.

For customer Redis (used by the RSV for SessionMaterial lookup and the
replay store), see [`docs/REDIS_SETUP.md`](docs/REDIS_SETUP.md).
A ready-to-use Docker Compose file lives at
[`compose/docker-compose.dev.yml`](compose/docker-compose.dev.yml).

Build:

```bash
cargo check --workspace
cargo test --workspace
```

The `haap-sdk-cli` binary builds as:

```bash
cargo build --release --bin haap-sdk
```

## Quick-start

```rust
use haap_sdk_types::AuthenticatorConfig;
use haap_supervisor::{AgentRuntime, SupervisorConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Read all HAAP_* env vars.
    let _config = AuthenticatorConfig::from_env()?;

    // Launch the 3-process pipeline; AgentRuntime is the top-level facade.
    let mut runtime = AgentRuntime::new(SupervisorConfig::new(
        "/usr/local/bin/haap-authenticator".into(),
        "/usr/local/bin/haap-tqs".into(),
        "/usr/local/bin/haap-assembler".into(),
    )).await?;

    let response = runtime.send_request(
        b"hello".to_vec(),
        "https://mcp.example.com".to_string(),
    ).await?;

    println!("response: {} bytes", response.len());
    Ok(())
}
```

For end-to-end examples, see [`examples/`](examples/) (post-alpha).

## Architecture (4-process + RSV)

```
       ┌──────────────────────────── MCP host (customer-deployed) ──────────────────────────────┐
       │                                                                                         │
       │   Supervisor (zero crypto, manages lifecycle)                                           │
       │       │                                                                                 │
       │       ├── Authenticator ── IK_i, performs X3DH, exposes K_session via UDS              │
       │       │                                                                                 │
       │       ├── TQS ─── pre-mints tokens from K_session, hands them out via UDS              │
       │       │                                                                                 │
       │       └── Assembler ─ encrypts request body under K_req, decrypts response             │
       │                       under K_resp, single-flight enforced                              │
       │                                                                                         │
       └─────────────────────────────────────────────────────────────────────────────────────────┘
                                              │
                                              │ HTTPS (encrypted bodies + tokens)
                                              ▼
       ┌────────────────────── MCP server (third-party tool service) ────────────────────────────┐
       │                                                                                         │
       │   RSV (HAAP Verifier) — 16-step cascade per §9                                          │
       │       ├── Customer Redis substrate (read SessionMaterial)                               │
       │       └── Replay store (LRU + Redis SETNX)                                              │
       │                                                                                         │
       │   MCP server core (after RSV: receives plaintext body, returns encrypted response)      │
       │                                                                                         │
       └─────────────────────────────────────────────────────────────────────────────────────────┘
```

IPC between the four host-side processes is over Unix domain sockets in
`$XDG_RUNTIME_DIR/hawcx/` (Linux) or `$TMPDIR/hawcx/` (macOS). Sockets
are mode 0600 and SO_PEERCRED-enforced — the OS verifies the peer
process's UID matches the expected UID at connection time.

Deeper architecture notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
Deployment guide: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).
Integration guide for agent runtimes and MCP servers:
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Environment variables

| Var | Required | Description |
|---|---|---|
| `HAAP_AS_URL` | yes | AS endpoint (HTTPS unless `HAAP_ALLOW_HTTP_FOR_DEV=true`) |
| `HAAP_ADMIN_CONSOLE_URL` | yes | Admin console endpoint for OrgToken fetch |
| `HAAP_PINNED_IK_SP` | yes | 32-byte hex AS identity public key for SPK_sig pinning |
| `HAAP_SEALER_BACKEND` | no | `file` (default), `os-keychain`, or `kms` |
| `HAAP_SEALER_FILE_PATH` | for file backend | Where to read/write the sealed agent bundle |
| `HAAP_SEALER_PASSPHRASE` | for file backend | (env var name configurable via `HAAP_SEALER_PASSPHRASE_ENV`) |
| `HAAP_SEALER_KEYCHAIN_SERVICE` | for os-keychain | Defaults to `haap-agentic-sdk` |
| `HAAP_SEALER_KEYCHAIN_ACCOUNT` | for os-keychain | Defaults to `default` |
| `HAAP_SEALER_KMS_KEY_ID` | for kms | (stub; post-alpha) |
| `HAAP_ALLOW_HTTP_FOR_DEV` | no | `true` to permit `http://` AS/admin URLs |
| `HAAP_CUSTOMER_REDIS_URL` | for RSV/substrate-fetch | e.g. `redis://localhost:6379` |
| `HAAP_SEALED_AGENT_PATH` | no | If set and file exists, Authenticator unseals on startup |

## License

Apache-2.0.

## CI

GitHub Actions CI is intentionally out of scope for this initial
population. A follow-up PR will add a workflow that runs
`cargo check --workspace`, `cargo clippy --workspace -- -D warnings`,
and `cargo test --workspace` on push and pull request.

## What this SDK does NOT do (today)

- Publish to crates.io.
- Provide Python or TypeScript bindings.
- Implement AWS/GCP KMS integration (KmsWrappedSealer is a stub).
- Implement the customer-side substrate writer — that lives in
  `hx_agent_client_admin_service` (per the v6.6.0 MCP topology, the CAA
  writes; only the reader lives here).
- Reimplement protocol crypto. The SDK path-deps to `hx_labs` for X3DH,
  HKDF v3, AEAD, Schnorr, token wire format, and the 16-step cascade.

See [`docs/initial_population_closure_report_2026-05-28.md`](docs/initial_population_closure_report_2026-05-28.md)
for the full closure breakdown.
