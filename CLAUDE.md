# hawcx_agentic_sdk — Claude Code Context

The customer-facing **HAAP release/distribution channel**. As of
2026-05-21 this repo is **release-only**: it hosts no Rust source code,
no `Cargo.toml`, no `crates/` directory. What lives here:

- `Dockerfile` + `Dockerfile.fast` — image build
- `.github/workflows/release.yml` + `release-node.yml` + `release-python.yml` — packaging
- `compose/` + `docker/bundle/` — local-eval compose bundle
- `docs/`, `README.md`, `CHANGELOG.md`, `AUDIT.md`, `CLAUDE.md`
- `node/`, `python/` — pure-language SDK clients (no NAPI / pyo3 /
  WASM — design choice; do not change without spec review)

The binaries assembled into the SDK image, npm platform packages, and
release tarballs are pulled from the private Kellnr registry at
**`cargo.hawcx.com`** via `cargo install hawcx-manager --registry hawcx`
(F-2 sibling-checkout migration closed 2026-05-27). Source repos
(`hx_agent_client_auth_service`, `hx_agent_crypto_core`, etc.) publish
their crates to this registry on tag push; the SDK pipeline pulls
versioned crates. No more in-pipeline sibling checkouts.

**Critical architectural fact:** the **client-side code** in `node/` and
`python/` is pure-language and speaks UDS to a local `hawcx-manager`
(framed binary protocol: `[u32 BE len][u8 type][JSON payload]`, 64 KiB
cap). No network egress from the SDK process itself. However, every
published npm/PyPI package **bundles the `hawcx-manager` binary** for
its target platform (npm via 5 `optionalDependencies` platform packages;
PyPI via platform wheels built with hatchling). The binary, not the SDK
client, owns the network surface — see [[project-door-a-door-b]] for
the two CAA channels.

## Version

- **HAAP Protocol Spec:** v7.2.5 (§45.7.5 MCP transport bearer carriage,
  2026-05-20). Canonical at
  `hx_agent_canonical_spec/spec/canonical/HAAP-Canonical-Specification-v7_2_5.md`
  (sibling repo).
- **SDK version (release line):** `v0.1.0-alpha.13` (current). Used for
  Docker tags, the 6 published npm packages (`@hawcx/hawcx-haap` + 5
  platform packages), and tarballs. `hawcx-manager` ships at crate
  version `0.8.0` from `cargo.hawcx.com`; `haap-rsv` carries its own
  semver from `hx_agent_authorizer`.
- **Canonical architecture reference:** `HAWCX_MANAGER_AUDIT.pdf` v2
  (2026-05-28) in `hx_agent_canonical_spec` — definitive for the
  multi-call binary, network surface, registration flow, and the
  CAA/AS/Orchestrator naming split.

## Repo topology

One of the sibling repos that replaced the retired `hx_labs` monorepo.
Full map: `hx_agent_canonical_spec/HAAP-TOPOLOGY-MAPPING.md`.

This repo is **release-only**. Source ownership map (post 2026-05-21
carve-out):

| Source crate (former SDK home) | New home | Notes |
|---|---|---|
| `haap-sdk-types` | `hx_agent_crypto_core` | Shared type surface (RsvConfig, SealerConfig, SealedBundle, VerifiedRequest, error enums) |
| `haap-substrate-reader` | `hx_agent_authorizer` | Colocated with `haap-rsv`; type coherence with authorizer's `haap-redis` fork |
| `haap-rsv` + `haap-rsv-bin` | `hx_agent_authorizer` | MCP-server-side cascade lives next to the §45.7-ahead `haap-core` |
| `haap-sdk-ipc` | `hx_agent_client_auth_service` | Agent-host IPC client; folds into future `hawcx-manager` |
| `haap-sdk-sealer` | `hx_agent_client_auth_service` | Agent-host at-rest sealer (Argon2 + AES-GCM + OS keychain) |
| `haap-sdk-cli` | `hx_agent_client_auth_service` | `haap-sdk` operator CLI; folds into future `hawcx-manager` |

## Bundle composition

Phase 3-5 multi-call binary cutover (2026-05-22): the SDK image, npm
platform packages, and tarballs ship **one real binary**
(`hawcx-manager`) with 7 legacy-name symlinks (Unix) / .exe copies
(Windows). The 6 legacy `*-bin` crates remain in
`hx_agent_client_auth_service` as deprecated shims; their `[[bin]]`
targets still build but are NOT included in any release artifact. See
`hx_agent_canonical_spec/DESIGN-MEMO-MULTICALL-BINARY.md`,
`hx_agent_canonical_spec/SDK-BUILD-WITH-HAWCX-MANAGER.md`, and the
canonical `HAWCX_MANAGER_AUDIT.pdf` v2.

| Artifact | Source crate | Source repo | Image |
|---|---|---|---|
| `hawcx-manager` (real binary) | `hawcx-manager` | `hx_agent_client_auth_service` | `ghcr.io/hawcx/hx-agent-sdk` |
| `haap-authenticator` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-tqs-precompute` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-tqs-jit` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-assembler` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-eib` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-supervisor` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-sdk` (symlink) | dispatched to `hawcx-manager` via argv0 | same | same |
| `haap-rsv` (real binary) | `haap-rsv-bin` | `hx_agent_authorizer` | **`ghcr.io/hawcx/haap-rsv`** (separate image) |

The `haap-rsv` split is structural: the §45.7.2 TBAC↔OAuth scope-gate
and §45.7.5 JSON-RPC error mapping live in authorizer's `haap-core`
fork (authorizer-ahead). Building `haap-rsv` from authorizer eliminates
the silent-stale-cascade hazard that the pre-2026-05-21 SDK build path
had (it pinned an older `haap-core` snapshot via the crypto_core
path-dep, masking the drift).

### npm distribution (alpha.13+)

Six packages published under the `@hawcx` org, all dist-tagged `alpha`:

- `@hawcx/hawcx-haap` — main package; pure TypeScript UDS client.
  `optionalDependencies` pins the 5 platform packages by exact version.
- `@hawcx/hawcx-haap-{linux-x64,linux-arm64,darwin-arm64,win32-x64,win32-arm64}`
  — platform packages; each bundles the `hawcx-manager` binary for its
  target plus a `LICENSE` file.

Published via `release-node.yml` on `node-v*` tags. **Authentication is
npm Trusted Publishing (OIDC)** — no static tokens. Each package has a
trusted publisher entry on npmjs.com binding it to this repo + workflow
+ `npm-production` environment. License field is
`"SEE LICENSE IN LICENSE"` (Hawcx Proprietary, never Apache-2.0 — see
[[project-license-proprietary]]). PyPI is wired in `release-python.yml`
but not yet published (alpha.13+ uses hatchling, not maturin).

## Cross-repo topology

| Repo / system | Relationship |
|---|---|
| `hx_agent_canonical_spec` | Spec source of truth (v7.2.5) + canonical `HAWCX_MANAGER_AUDIT.pdf` v2. |
| `hx_agent_client_auth_service` | Source of `hawcx-manager` (the multi-call binary covering supervisor/authenticator/tqs/assembler/eib/sdk roles). Publishes to `cargo.hawcx.com`. |
| `hx_agent_authorizer` | Source of `haap-rsv` (separate image; authorizer-ahead `haap-core` fork). |
| `hx_agent_client_admin_service` (CAA = **Client Admin Authenticator**) | Cloud-edge wire peer for the customer-side runtime. Reference image `ghcr.io/hawcx/hx-caa` in the local-eval bundle. NOT bundled in the main SDK image. See [[project-caa-acronyms]]. |
| `hx_agent_crypto_core` | Shared substrate (haap-core, haap-crypto, haap-wire, haap-redis, haap-sdk-types). Publishes to `cargo.hawcx.com`. |
| `cargo.hawcx.com` (Kellnr) | Private cargo registry — single distribution channel for cross-repo Rust crates. Auth via `CARGO_HAWCX_TOKEN`. Sparse index at `sparse+https://cargo.hawcx.com/api/v1/crates/`. |

## Conventions

- This repo has no Rust source. Do NOT add `crates/`, `Cargo.toml`, or
  `Cargo.lock`. If you need to make a source-level change, it goes in a
  sibling repo, gets published to `cargo.hawcx.com`, and this repo's
  workflows install it via `cargo install --registry hawcx`.
- Pure-language SDK *clients*. No NAPI / pyo3 / WASM in `node/src` or
  `python/src`. The TS/Python code only opens UDS and speaks the framed
  wire protocol — design choice; do not introduce native bindings. The
  `hawcx-manager` binary that ships alongside is a separate platform
  package (npm) / platform wheel (PyPI), not a native module dlopen'd
  by the client.
- All published packages ship under the **Hawcx Proprietary License**:
  `"license": "SEE LICENSE IN LICENSE"` + `LICENSE` in the `files` list.
  Never label any artifact Apache-2.0 (see [[project-license-proprietary]]).
- `protoc` SHA-pinned in Dockerfile (L-2 hardening, 2026-05-20). Don't
  swap to apt without re-pinning.
- Distroless `cc-debian12` runtime. ENTRYPOINT defaults to
  `haap-supervisor`. The `rsv` compose service now pulls
  `ghcr.io/hawcx/haap-rsv` directly (no entrypoint override).
- npm publishes via OIDC Trusted Publishing on Node 24 / npm 11+. Don't
  reintroduce `NODE_AUTH_TOKEN` or `setup-node` `always-auth` — they
  block the OIDC handshake. Don't add `--omit=optional` to the
  test-matrix step (it skips vitest's platform-specific rollup and
  breaks the build).

## Ownership notes

- The **CAA Admin Authenticator binary is the responsibility of
  `hx_agent_client_admin_service`**, not bundled here.
- Postgres migrations for the broader HAAP stack live in
  `hx_agent_admin_console/backend/crates/haap-console/migrations/`.
  The SDK does not touch Postgres directly; the supervisor pipeline
  reads customer KV (Redis) substrate.
- §38 OAuth Bridge is SUPERSEDED by §45 Pattern Z (v7.2.0). §45.7.5 MCP
  transport bearer carriage (v7.2.5) impacts the RSV's HTTP/JSON-RPC
  surface; update `docs/RSV_HTTP_API.md` to cover the
  `-32001..-32005` mapping.

## What NOT to assume

- The **SDK client** (the TS/Python code in `node/`, `python/`) does
  not speak gRPC, HTTP, or any network protocol. Local UDS only — to
  the bundled `hawcx-manager` binary on the same host.
- The **bundled `hawcx-manager` binary** absolutely DOES talk to the
  CAA: `manager` subcommand → CAA `/v1/enroll` (Door A, identity
  enrollment via OIDC device flow), and `supervisor` subcommand → CAA
  `:7443` mTLS gRPC (Door B, persistent control channel via
  `SupervisorControl` → `RegisterSupervisor` + `OperationStream`). The
  old "CAA writes substrate to Redis; supervisor reads it on startup"
  framing is OUT OF DATE — Door B is the wire today. See
  [[project-door-a-door-b]].
- This repo is the release channel. Protocol logic belongs in
  `hx_agent_crypto_core`, `hx_agent_authorizer`,
  `hx_agent_client_auth_service`, and `hx_agent_client_admin_service`.
- Don't conflate CAA / Admin Orchestrator / Auth Server. CAA = Client
  Admin Authenticator; it is the *single cloud edge* the customer
  runtime talks to in steady state. See [[project-caa-acronyms]].

## Quick links

- [AUDIT.md](AUDIT.md) — migration audit
- [CHANGELOG.md](CHANGELOG.md) — aggregate cross-surface changelog
- [README.md](README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- `hx_agent_canonical_spec/HAWCX_MANAGER_AUDIT.pdf` (v2, 2026-05-28) —
  canonical reference for the multi-call binary and Door A / Door B.
