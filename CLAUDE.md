# hawcx_agentic_sdk — Claude Code Context

The customer-facing **HAAP release/distribution channel**. As of
2026-05-21 this repo is **release-only**: it hosts no Rust source code,
no `Cargo.toml`, no `crates/` directory. What lives here:

- `Dockerfile` + `Dockerfile.fast` — image build (sources from siblings)
- `.github/workflows/release.yml` + sibling workflows — packaging
- `compose/` + `docker/bundle/` — local-eval compose bundle
- `docs/`, `README.md`, `CHANGELOG.md`, `AUDIT.md`, `CLAUDE.md`
- `node/`, `python/` — pure-language UDS IPC clients (no NAPI / pyo3 /
  WASM — design choice; do not change without spec review)

The binaries assembled into the SDK image and release tarballs are
built from sibling repos at release time (Dockerfile copies the sibling
trees; release.yml checks them out and runs `cargo build` against
their workspaces).

**Critical architectural fact:** the Node and Python SDKs are
**pure-language UDS IPC clients**, not native modules. They speak a
framed binary protocol (`[u32 BE len][u8 type][JSON payload]`, 64 KiB
cap) to the local Assembler binary. No network egress. Everything
network-side happens downstream of the supervisor.

## Version

- **HAAP Protocol Spec:** v7.2.5 (§45.7.5 MCP transport bearer carriage,
  2026-05-20). Canonical at
  `/Users/raviramaraju/Projects/hx_agent_canonical_spec/spec/canonical/HAAP-Canonical-Specification-v7_2_5.md`.
- **SDK version (release line):** `v0.1.0-alpha.10` for tarballs +
  Docker tags. The `haap-sdk` and `haap-rsv` binaries shipped from this
  channel carry their own per-crate semver from their source repos.

## Repo topology

One of the sibling repos that replaced the retired `hx_labs` monorepo.
Full map:
`/Users/raviramaraju/Projects/hx_agent_canonical_spec/HAAP-TOPOLOGY-MAPPING.md`.

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

Phase 3-5 multi-call binary cutover (2026-05-22): the SDK image and
tarballs ship **one real binary** (`hawcx-manager`) with 7 legacy-name
symlinks (Unix) / .exe copies (Windows). The 6 legacy `*-bin` crates
remain in `hx_agent_client_auth_service` as deprecated shims; their
`[[bin]]` targets still build but are NOT included in the release
artifact. See `/hx_agent_canonical_spec/DESIGN-MEMO-MULTICALL-BINARY.md`
and `/hx_agent_canonical_spec/SDK-BUILD-WITH-HAWCX-MANAGER.md`.

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

## Cross-repo topology

| Repo | Relationship |
|---|---|
| `hx_agent_canonical_spec` | Spec source of truth (v7.2.5). |
| `hx_agent_client_auth_service` | Source of the 6 MCP host binaries + `haap-sdk` CLI bundled in this image. |
| `hx_agent_authorizer` | Source of `haap-rsv` (separate image). |
| `hx_agent_client_admin_service` (CAA) | Reference image `ghcr.io/hawcx/hx-caa` in local-eval bundle. NOT bundled in the main SDK image. |
| `hx_agent_crypto_core` | Shared substrate (haap-core, haap-crypto, haap-wire, haap-redis, haap-sdk-types). |

## Conventions

- This repo has no Rust source. Do NOT add `crates/`, `Cargo.toml`, or
  `Cargo.lock`. If you need to make a source-level change, it goes in a
  sibling repo and the Dockerfile / workflow here pulls the new tag.
- Pure-language SDKs only. No NAPI / pyo3 / WASM in `node/` or
  `python/`. If you find yourself reaching for `napi-rs`, stop — the
  design choice is deliberate (local UDS speaks the wire protocol
  natively in any language).
- `protoc` SHA-pinned in Dockerfile (L-2 hardening, 2026-05-20). Don't
  swap to apt without re-pinning.
- Distroless `cc-debian12` runtime. ENTRYPOINT defaults to
  `haap-supervisor`. The `rsv` compose service now pulls
  `ghcr.io/hawcx/haap-rsv` directly (no entrypoint override).

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

- The Node / Python SDKs do not speak gRPC, HTTP, or any network
  protocol. Local UDS only.
- The SDK does not talk to the CAA directly. CAA writes substrate to
  Redis; supervisor reads it on startup.
- This repo is the release channel. Protocol logic belongs in
  `hx_agent_crypto_core`, `hx_agent_authorizer`, and
  `hx_agent_client_auth_service`.

## Quick links

- [AUDIT.md](AUDIT.md) — migration audit
- [CHANGELOG.md](CHANGELOG.md) — aggregate cross-surface changelog
- [README.md](README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
