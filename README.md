# hx_agentic_sdk

Customer-facing distribution of the **Hawcx Agent Authentication
Protocol** (HAAP Canonical Specification v7.2.0).

> **Status**: alpha rebuild (Option X / Mechanism 2). Public API may
> change. The `haap-rsv` library is publishable; everything else in
> this workspace is internal scaffolding.

## What ships in a release

Each `vX.Y.Z` tag produces eight binaries packaged per-platform plus
a multi-arch Docker image:

| Binary | Source | Role |
|---|---|---|
| `haap-auth-bin` | `hx_labs` | Authenticator — holds IK_i, performs X3DH against AS |
| `haap-tqs-precompute-bin` | `hx_labs` | TQS pre-compute side — Schnorr commitment pre-minting |
| `haap-tqs-jit-bin` | `hx_labs` | TQS just-in-time side — request-time token completion |
| `haap-assembler-bin` | `hx_labs` | Assembler — K_req/K_resp + single-flight |
| `haap-eib-bin` | `hx_labs` | External Identity Broker — holds OAuth bearer tokens (Pattern Z, §45) |
| `haap-supervisor` | `hx_labs` | Pipeline orchestrator — spawns the five child processes |
| `haap-rsv` | SDK (`haap-rsv-bin`) | MCP-server-side HAAP Verifier HTTP API |
| `haap-sdk` | SDK (`haap-sdk-cli`) | Testing/demo CLI |

Six binaries come from `hx_labs` directly (Option X distribution
model — the SDK is a distribution source, not a wrapper layer).
Two binaries come from this repo's library crates.

In addition, the [`haap-rsv`](https://crates.io/crates/haap-rsv)
library is publishable to crates.io for Rust MCP servers that want
in-process embedding.

## Install

### Tarball (recommended for customer hosts)

```bash
curl -L https://github.com/hawcx/hx_agentic_sdk/releases/download/v0.1.0-alpha.7/hx-agent-sdk-v0.1.0-alpha.7-x86_64-unknown-linux-gnu.tar.gz \
    | tar -xz -C /usr/local
export PATH=/usr/local/hx-agent-sdk-v0.1.0-alpha.7-x86_64-unknown-linux-gnu/bin:$PATH
```

### Docker

```bash
docker pull ghcr.io/hawcx/hx-agent-sdk:v0.1.0-alpha.7
# Default ENTRYPOINT is haap-supervisor; override with --entrypoint for the others.
```

### From source (development)

Requires `~/Projects/hx_labs/` as a sibling checkout:

```bash
cd ~/Projects
git clone git@github.com:hawcx/hx_labs.git        # private repo
git clone git@github.com:hawcx/hx_agentic_sdk.git
cd hx_agentic_sdk
cargo build --release --workspace
```

## Architecture (6-process customer-side pipeline + RSV)

```
┌─── MCP host (customer-deployed) ─────────────────────────────────────┐
│                                                                      │
│   haap-supervisor                                                    │
│     ├── haap-auth-bin                  (Authenticator: IK_i)         │
│     ├── haap-tqs-precompute-bin        (TQS pre-compute)             │
│     ├── haap-tqs-jit-bin               (TQS JIT)                     │
│     ├── haap-assembler-bin             (Assembler: K_req/K_resp)     │
│     └── haap-eib-bin                   (EIB: OAuth bearer tokens)    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (encrypted token + body)
                              ▼
┌─── MCP server (third-party tool service) ─────────────────────────────┐
│                                                                      │
│   haap-rsv  (HTTP sidecar)            OR     `haap_rsv::Rsv` library │
│                                              (in-process embed)      │
│                                                                      │
│   MCP server handler                                                 │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

The Supervisor is the customer-facing entrypoint — it manages the
five child processes that together form the request-side pipeline.
The MCP server side runs the RSV (either as a sidecar HTTP API or
as an in-process Rust library) to verify and decrypt incoming
requests.

Deep dive: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick-start

After installing the tarball or Docker image:

```bash
# Configure customer Redis substrate (see docs/REDIS_SETUP.md):
export HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379

# Launch the customer-side pipeline:
haap-sdk run-pipeline

# Or run the RSV HTTP API on an MCP server host:
export HAAP_AUDIENCE_HASH=<32-byte sha256 of audience URL in hex>
haap-sdk run-rsv --listen 0.0.0.0:8443
```

For end-to-end examples: [`crates/haap-sdk-cli/examples/`](crates/haap-sdk-cli/examples/).

For RSV embedding into a Rust MCP server: [`crates/haap-rsv/examples/`](crates/haap-rsv/examples/).

## License

Apache-2.0.

## Status / known limitations

- The RSV cascade adapter (calling
  `haap_core::cascade::verify_and_decrypt_request`) is wired up in a
  focused follow-up PR. Today `verify_and_decrypt` returns
  `Internal("RSV cascade adapter wire-up lands in a focused follow-up PR")`;
  the supporting infrastructure (substrate reader, replay store, HTTP
  endpoint shape, handle caching) is in place and tested.
- `KmsWrappedSealer` is a stub. `FileSealer` and `OsKeychainSealer` are
  fully functional.
- Mobile FFI (iOS/Android) is alpha+1 scope.
- System packages (`.deb`, `.rpm`, Homebrew, scoop) are post-alpha.

See [`docs/clean_slate_rebuild_closure_2026-06-01.md`](docs/clean_slate_rebuild_closure_2026-06-01.md)
for the full closure breakdown.

## Historical reference

Pre-Option-X work (PR #1, PR #2) is preserved on the
[`main-legacy-pre-option-x`](https://github.com/hawcx/hx_agentic_sdk/tree/main-legacy-pre-option-x)
branch.
