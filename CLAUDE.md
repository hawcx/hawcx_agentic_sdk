# hawcx_agentic_sdk — Claude Code Context

The customer-facing **HAAP SDK and distribution channel**. Packages a
language-binding surface (Node + Python UDS clients), the RSV library +
binary (`haap-rsv` / `haap-rsv-bin`), and a multi-binary bundle of the
customer-side MCP host process group as platform tarballs +
`ghcr.io/hawcx/hx-agent-sdk` OCI image.

**Critical architectural fact:** the Node and Python SDKs are **pure-
language UDS IPC clients**, not native (NAPI / pyo3 / WASM) modules.
They speak a framed binary protocol (`[u32 BE len][u8 type][JSON
payload]`, 64 KiB cap) to the local Assembler binary. No network
egress. Everything network happens downstream of the supervisor.

## Version

- **HAAP Protocol Spec:** v7.2.5 (§45.7.5 MCP transport bearer carriage,
  2026-05-20). Canonical at
  `/Users/raviramaraju/Projects/hx_agent_canonical_spec/spec/canonical/HAAP-Canonical-Specification-v7_2_5.md`.
  README + CLAUDE + pyproject in this repo currently cite v7.2.0 — bump
  pending.
- **SDK version (this repo):** `0.1.0-alpha.7` across crates / npm /
  PyPI lines. `hx_labs` historically cited "SDK Version: 0.8.0", which
  referred to the legacy in-monorepo `packages/@hx/*` + `ts/haap-ipc/`
  versions — independent timeline; resolve before public publish (see
  blockers).

## Repo topology

One of 11 sibling repos replacing the retiring `hx_labs` monorepo. Full
map:
`/Users/raviramaraju/Projects/hx_agent_canonical_spec/HAAP-TOPOLOGY-MAPPING.md`.

This repo sits on the **customer (data plane) embed-side** of the trust
boundary — it ships the artifacts customer integrators install. It owns
SDK ergonomics around **§5.2 session setup**, **§7 token mint API
surface**, **§9 RSV cascade (via `haap-rsv` crate, publishable to
crates.io)**, **§24 clarification callbacks**, **§34 MCP gateway client**,
and the **packaged bundle** of the (planned) `hx_agent_client_auth_service`
MCP host binaries. Does NOT own the protocol crates themselves — those
are consumed from `hx_labs` (today) and will move to the planned
`hx_agent_crypto_core` repo.

## Product URLs

- **npm:** `@hawcx/hawcx-haap` (NOT yet published; registry 404)
- **PyPI:** `hawcx-haap` (publish workflow exists; status unconfirmed)
- **crates.io:** `haap-rsv` (publish flag set, not yet pushed)
- **OCI:** `ghcr.io/hawcx/hx-agent-sdk` (via `Dockerfile`)

## Structure

7-member Cargo workspace + sibling Node + Python packages:

```
crates/
  haap-sdk-types/         Shared SDK types (substrate, errors, IPC payloads)
  haap-sdk-ipc/           UDS framed protocol; peer-UID verification (SO_PEERCRED)
  haap-sdk-sealer/        At-rest sealing: Argon2 + AES-GCM + OS keychain
  haap-substrate-reader/  Redis-backed substrate reader (§40 split)
  haap-rsv/               §9 cascade library — publish = true (crates.io)
  haap-rsv-bin/           Standalone haap-rsv HTTP/UDS binary
  haap-sdk-cli/           haap-sdk operator CLI binary
node/                     @hawcx/hawcx-haap — pure TypeScript UDS client (no NAPI)
python/                   hawcx-haap — pure Python UDS client (no pyo3); pipe_win.py for Windows
docker/bundle/            docker-compose-driven local eval bundle (CAA + RSV + Redis)
compose/                  docker-compose.dev.yml
.github/workflows/
  release.yml             Rust + Docker tarballs
  release-node.yml        npm publish
  release-python.yml      PyPI publish
```

## Key Commands

- `cargo build --release` (needs sibling `hx_labs/` — see blockers)
- `cargo test --workspace`
- `cargo clippy --workspace -- -D warnings`
- `pnpm --filter @hawcx/hawcx-haap test` (in `node/`)
- `pytest` (in `python/`)
- `cargo bench -p haap-rsv` — cascade perf

## Conventions

- Pure-language SDKs only. No NAPI / pyo3 / WASM in `node/` or
  `python/`. If you find yourself reaching for `napi-rs`, stop — the
  design choice is deliberate (local UDS speaks the wire protocol
  natively in any language).
- `subtle = "2.6"` hard-pinned for constant-time compare via the
  vetted hx_labs chain. Preserve.
- `aes-gcm 0.10` AEAD only; AEAD modes only across the stack. No MD5,
  no SHA-1, no DIY crypto.
- `protoc` SHA-pinned in Dockerfile (L-2 hardening, 2026-05-20). Don't
  swap to apt without re-pinning.
- Distroless `cc-debian12` runtime. ENTRYPOINT defaults to
  `haap-supervisor`; the `rsv` compose service explicitly overrides it
  to run RSV. This composition smell is tracked (F-9).
- Workspace-level `[workspace.dependencies]` is the single pin-point
  for third-party crate versions. Add new deps there.

## Bundle composition

| Binary | Source crate | Source repo | Bundled? |
|---|---|---|---|
| `haap-authenticator` | `haap-auth-bin` | `hx_labs` (today) → `hx_agent_client_auth_service` (planned) | yes |
| `haap-tqs-precompute` | `haap-tqs-precompute-bin` | same | yes |
| `haap-tqs-jit` | `haap-tqs-jit-bin` | same | yes |
| `haap-assembler` | `haap-assembler-bin` | same | yes |
| `haap-eib` | `haap-eib-bin` | same | yes |
| `haap-supervisor` | `haap-supervisor` | same | yes |
| `haap-rsv` | `haap-rsv-bin` | THIS repo | yes |
| `haap-sdk` | `haap-sdk-cli` | THIS repo | yes |
| CAA Admin Authenticator | `haap-admin-auth-bin` | `hx_agent_client_admin_service` | NO (correctly excluded; CAA ships from its own repo) |

## Cross-repo topology

| Repo | Relationship |
|---|---|
| `hx_agent_canonical_spec` | Spec source of truth (v7.2.5). |
| `hx_agent_client_auth_service` | (planned) Source of the 6 MCP host binaries bundled here. |
| `hx_agent_client_admin_service` (CAA) | Reference image `ghcr.io/hawcx/hx-caa` in local-eval bundle. NOT bundled in the main SDK image. |
| `hx_agent_authorizer` (RSV reference) | Sibling implementation; `haap-rsv` here mirrors the same §9 cascade surface. Diff drift across `domains.rs` is tracked. |
| `hx_agent_crypto_core` | (planned) Future home for `haap-core`, `haap-crypto`, `haap-ipc`, `haap-wire`, `haap-redis` — the 5 path-deps. |
| `hx_labs` | **RETIRED (build refs cleared 2026-05-21).** Workspace path-deps now resolve via `hx_agent_crypto_core`; `Dockerfile` + `release.yml` checkout `hx_agent_client_auth_service` + `hx_agent_crypto_core` for the 6 MCP host binaries. Leaked `HX_LABS_READ_TOKEN` PAT no longer referenced by any workflow and is eligible for retirement. |

## Ownership notes (carried forward from hx_labs)

- The **CAA Admin Authenticator binary is the responsibility of
  `hx_agent_client_admin_service`**, not bundled here. Don't add it to
  the SDK image; that bundle's CAA reference (`ghcr.io/hawcx/hx-caa`) is
  pulled at compose-up, not built here.
- Postgres migrations for the broader HAAP stack live in
  `hx_agent_admin_console/backend/crates/haap-console/migrations/`. The
  SDK does not touch Postgres directly; the supervisor pipeline reads
  customer KV (Redis) substrate.
- §38 OAuth Bridge is SUPERSEDED by §45 Pattern Z (v7.2.0). §45.7.5 MCP
  transport bearer carriage (v7.2.5) impacts the RSV's HTTP/JSON-RPC
  surface; update `docs/RSV_HTTP_API.md` to cover the
  `-32001..-32005` mapping.
- The 30-crate `hx_labs` inventory is being split across 11 repos. SDK
  is downstream of the protocol crates; do not host protocol logic
  here. `haap-rsv` is the one exception — it's the cascade library and
  has to be publish-ready on crates.io.

## Known issues / blockers (top of audit, full list in AUDIT.md)

1. **RESOLVED 2026-05-21 — repo build refs to `hx_labs` cleared.**
   Workspace `Cargo.toml` now path-deps into
   `../hx_agent_crypto_core/crates/{haap-core,haap-crypto,haap-ipc,haap-wire,haap-redis}`.
   `Dockerfile` + `release.yml` check out `hx_agent_client_auth_service`
   (source of the 6 MCP host binaries) and `hx_agent_crypto_core`
   (sibling-path-dep target) instead of `hx_labs`. The leaked
   `HX_LABS_READ_TOKEN` PAT is no longer referenced by any workflow in
   this repo — eligible for retirement at the org level. Remaining
   F-2 follow-up: replace the sibling-checkout pattern with
   crates.io-published `hawcx-*` versioned deps so customer-side
   `cargo build` works without three private-repo checkouts. **F-2
   (build-ref half resolved; version-pin half remains).**
2. **HIGH — SDK version skew.** `hx_labs/CLAUDE.md` line "SDK Version:
   0.8.0" referred to legacy in-monorepo packages, not to this repo.
   Crates / npm / PyPI here are `0.1.0-alpha.{1,7}`. Customers reading
   the hx_labs string will hit `@hawcx/hawcx-haap@0.8.0` 404 on npm.
   Decide: (a) rev this repo to `0.8.0` at first public release, or
   (b) declare `0.1.0-alpha` authoritative and erase the `0.8.0`
   reference from `hx_labs` retirement docs. **F-1.**
3. **MEDIUM — surface mismatch with the migration brief.** The brief
   frames this repo as the migration target for `crates/haap-napi`,
   `crates/haap-pyo3`, `crates/haap-wasm`, `crates/haap-cli`,
   `crates/haap-manager`. Reality: bindings here are pure-language
   UDS clients — no NAPI, no pyo3, no WASM target. Diff
   `hx_labs/crates/haap-napi/src/`, `haap-pyo3/src/`, `haap-wasm/src/`
   against `node/src/` + `python/src/` to confirm zero functional gap.
   If the legacy crates are unused, mark them dead in the `hx_labs`
   retirement PR. **F-4.**

Smaller blockers (spec refs v7.2.0 not v7.2.5, no PR-level CI workflow,
local-eval bundle pinned to one CAA image variant, `__pycache__/` +
`*.egg-info/` build droppings checked in, supervisor + RSV sharing one
image with entrypoint override) catalogued in [AUDIT.md](AUDIT.md) §8.

## What NOT to assume

- The Node / Python SDKs do not speak gRPC, HTTP, or any network
  protocol. Local UDS only.
- The SDK does not talk to the CAA directly. CAA writes substrate to
  Redis; supervisor reads it on startup. Different code paths.
- `@hawcx/hawcx-haap` is not yet on npm. Vendor or use `file:` deps
  until publish.
- This repo is the SDK distribution channel, not the protocol home.
  Protocol logic belongs in the planned `hx_agent_crypto_core` and in
  `hx_agent_client_auth_service`.

## Quick links

- [AUDIT.md](AUDIT.md) — full 2026-05-21 migration audit
- [CHANGELOG.md](CHANGELOG.md) — aggregate cross-surface changelog
- [README.md](README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- [docs/INTEGRATION.md](docs/INTEGRATION.md)
- [docs/RSV_HTTP_API.md](docs/RSV_HTTP_API.md)
- [docker/bundle/](docker/bundle/) — local-eval CAA + RSV + Redis compose
- [.github/workflows/release.yml](.github/workflows/release.yml)
