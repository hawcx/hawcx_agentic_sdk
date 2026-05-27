# hawcx_agentic_sdk

Customer-facing distribution channel for the **Hawcx Agent Authentication
Protocol** (HAAP Canonical Specification v7.2.5).

> **Status (2026-05-21):** this repo is **release-only**. It carries no
> Rust source code. The Dockerfile, GitHub Actions workflow, compose
> bundle, and docs live here; the binaries are built out of sibling
> repos at release time. See "What ships in a release" below.

## What ships in a release

Each `vX.Y.Z` tag produces **one real binary** (`hawcx-manager`) + 7
legacy-name aliases per platform plus a multi-arch Docker image. The
companion `haap-rsv` artifact ships from `hx_agent_authorizer`'s own
pipeline (see the bottom of this section).

Phase 3-5 cutover (2026-05-22): the SDK used to ship 7 standalone
binaries; it now ships one **multi-call binary** (`hawcx-manager`,
BusyBox-style argv0 dispatch) with 7 symlinks (Unix) / .exe copies
(Windows) under the legacy names. Existing customer scripts continue
to work unchanged. Tarball size dropped from ~150 MB to ~40 MB on
Unix targets.

| Legacy name | Multi-call form | Role |
|---|---|---|
| `haap-authenticator` | `hawcx-manager authenticator` | Authenticator — holds IK_i, performs X3DH against AS |
| `haap-tqs-precompute` | `hawcx-manager tqs-precompute` | TQS pre-compute side — Schnorr commitment pre-minting |
| `haap-tqs-jit` | `hawcx-manager tqs-jit` | TQS just-in-time side — request-time token completion |
| `haap-assembler` | `hawcx-manager assembler` | Assembler — K_req/K_resp + single-flight |
| `haap-eib` | `hawcx-manager eib` | External Identity Broker — OAuth bearer tokens (Pattern Z, §45) |
| `haap-supervisor` | `hawcx-manager supervisor` | Pipeline orchestrator — spawns the five child processes |
| `haap-sdk` | `hawcx-manager sdk` | Testing / demo CLI |

All legacy names are filesystem symlinks (Unix) to the single
`hawcx-manager` binary; the dispatcher inspects `argv[0]` basename
and routes to the corresponding role. On Windows the legacy names
are full `.exe` copies (Windows symlinks require admin / dev-mode).
Source: `hx_agent_client_auth_service/crates/hawcx-manager/`.

Image: `ghcr.io/hawcx/hx-agent-sdk:vX.Y.Z` (linux/amd64 + linux/arm64).
Default ENTRYPOINT = `/usr/local/bin/haap-supervisor` (symlink → routes
to supervisor mode).

**MCP server-side verifier** (`haap-rsv`) ships from a separate image
as of 2026-05-21:

- Source: `hx_agent_authorizer/crates/haap-rsv-bin`
- Image: `ghcr.io/hawcx/haap-rsv:vX.Y.Z` (linux/amd64 + linux/arm64)
- Release workflow: `hx_agent_authorizer/.github/workflows/release.yml`

The split is structural: `haap-rsv` calls the §45.7-ahead cascade in
authorizer's `haap-core` (TBAC↔OAuth scope-gate + MCP JSON-RPC error
mapping), and that cascade is the authoritative implementation. Shipping
it from authorizer eliminates the drift that the SDK's old build path
introduced.

## Install

### Tarball (recommended for customer hosts)

```bash
TAG=v0.1.0-alpha.10
ARCH=x86_64-unknown-linux-gnu
curl -L https://github.com/hawcx/hawcx_agentic_sdk/releases/download/${TAG}/hx-agent-sdk-${TAG}-${ARCH}.tar.gz \
    | tar -xz -C /usr/local
export PATH=/usr/local/hx-agent-sdk-${TAG}-${ARCH}/bin:$PATH

# Verify (both invocations produce identical output):
hawcx-manager --version
haap-supervisor --help            # argv0-dispatched via symlink
hawcx-manager supervisor --help   # explicit subcommand form
```

### Docker

```bash
# Customer-side pipeline (supervisor + 5 protected children + haap-sdk CLI)
docker pull ghcr.io/hawcx/hx-agent-sdk:v0.1.0-alpha.10

# MCP-server-side verifier (separate image)
docker pull ghcr.io/hawcx/haap-rsv:v0.1.0-alpha.10
```

Default ENTRYPOINT on the SDK image is `haap-supervisor`; override with
`--entrypoint` for the others. The `haap-rsv` image's ENTRYPOINT is
`haap-rsv` directly.

### From source (development)

Requires `hx_agent_client_auth_service/` and `hx_agent_crypto_core/` as
sibling checkouts. `hx_agent_authorizer/` is the third sibling required
to build `haap-rsv`:

```bash
cd ~/Projects
git clone git@github.com:hawcx/hx_agent_crypto_core.git         # private
git clone git@github.com:hawcx/hx_agent_client_auth_service.git # private
git clone git@github.com:hawcx/hx_agent_authorizer.git          # private

# Customer-side multi-call binary (replaces the prior 7 individual bins).
cd hx_agent_client_auth_service
cargo build --release --bin hawcx-manager

# Optional: create legacy-name symlinks for local testing.
target_dir=target/release
for n in haap-authenticator haap-tqs-precompute haap-tqs-jit \
         haap-assembler haap-eib haap-supervisor haap-sdk; do
    ln -sf hawcx-manager "$target_dir/$n"
done

# MCP-server-side verifier
cd ../hx_agent_authorizer
cargo build --release --bin haap-rsv
```

This SDK repo itself has no `Cargo.toml` and no `crates/` directory.

## Architecture (6-process customer-side pipeline + RSV)

```
┌─── MCP host (customer-deployed) ─────────────────────────────────────┐
│                                                                      │
│   haap-supervisor                                                    │
│     ├── haap-authenticator             (Authenticator: IK_i)         │
│     ├── haap-tqs-precompute            (TQS pre-compute)             │
│     ├── haap-tqs-jit                   (TQS JIT)                     │
│     ├── haap-assembler                 (Assembler: K_req/K_resp)     │
│     └── haap-eib                       (EIB: OAuth bearer tokens)    │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (encrypted token + body)
                              ▼
┌─── MCP server (third-party tool service) ─────────────────────────────┐
│                                                                      │
│   haap-rsv  (HTTP/UDS sidecar from ghcr.io/hawcx/haap-rsv)           │
│                                                                      │
│   MCP server handler                                                 │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

The Supervisor is the customer-facing entrypoint — it manages the five
child processes that together form the request-side pipeline. The MCP
server side runs `haap-rsv` (UDS sidecar) to verify and decrypt incoming
requests.

Deep dive: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick-start

After installing the tarball or pulling the Docker images:

```bash
# Configure customer Redis substrate (see docs/REDIS_SETUP.md):
export HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379

# Launch the customer-side pipeline (from the SDK tarball/image):
haap-sdk run-pipeline

# Or run the RSV HTTP API on an MCP server host (from the haap-rsv image):
docker run -e HAAP_AUDIENCE_HASH=<sha256 hex> \
           -e HAAP_RSV_LISTEN=0.0.0.0:8443 \
           -p 8443:8443 ghcr.io/hawcx/haap-rsv:v0.1.0-alpha.10
```

## License

Hawcx Proprietary License. See [LICENSE](LICENSE).

## Status / known limitations

- `KmsWrappedSealer` is a stub. `FileSealer` and `OsKeychainSealer` are
  fully functional.
- Mobile FFI (iOS/Android) is alpha+1 scope.
- System packages (`.deb`, `.rpm`, Homebrew, scoop) are post-alpha.

See [`docs/clean_slate_rebuild_closure_2026-06-01.md`](docs/clean_slate_rebuild_closure_2026-06-01.md)
for the full closure breakdown.
