# Clean-slate rebuild — closure report

**Date:** 2026-06-01
**Branch:** `feature/initial-option-x-population-2026-06-01`
**New `main`** (orphan, no shared history with the legacy branch).
**Legacy preserved at:** `main-legacy-pre-option-x`.

## Phase 0 source audit verdict: **CLEAN**

The pre-existing SDK (PR #1 + PR #2 work) contained no protocol
implementation code. The 7-pattern audit found zero hits in
`crates/*/src/` for HKDF, X3DH, AEAD outside sealer, Schnorr,
hardcoded byte vectors, or hx_labs function names (apart from two
doc-comment mentions).

The wipe is therefore **structural**, not contamination-driven.
Option X mandates removing the wrapper crates
(`haap-authenticator`, `haap-tqs`, `haap-assembler`, `haap-supervisor`)
because the corresponding hx_labs binaries ship directly. PR #1's
ChaCha20Poly1305-based sealer is rebuilt with AES-256-GCM to align
with hx_labs's AEAD conventions. The RSV is split into a publishable
library + HTTP binary instead of a single combined crate.

Full audit details: see commit `29fdd8f` on the legacy branch and
`/tmp/sdk_salvage/source_audit_findings.md`.

## Salvage decisions

**Mandatory salvage** (copied to `/tmp/sdk_salvage/` in Phase 1):
- `docs/phase_0_helper_signatures.md` (PR #1 forensic preflight)
- `docs/initial_population_closure_report_2026-05-28.md` (PR #1 closure)
- `compose/docker-compose.dev.yml` (dev Redis container)
- `docs/REDIS_SETUP.md` (deployment guidance)
- PR #1's `ARCHITECTURE.md`, `DEPLOYMENT.md`, `INTEGRATION.md` (rewritten)

**Conditional salvage** (audit was clean → eligible):
- `crates/haap-sdk-ipc/` — restored from salvage, refactored to drop
  `haap-sdk-types::IpcMessage` coupling (since the wrapper crates that
  defined those IpcMessage variants are gone under Option X). Now a
  generic byte-payload UDS framing primitive.
- `crates/haap-substrate-reader/` — rebuilt fresh (the salvaged version
  was tightly coupled to old type names; rebuilding was cleaner).

**Explicit discards:**
- All wrapper crates (`haap-authenticator`, `haap-tqs`, `haap-assembler`,
  `haap-supervisor`) — Option X removes them entirely.
- `haap-sdk-sealer` — rebuilt fresh with AES-256-GCM (PR #1 used ChaCha20Poly1305).
- `haap-rsv` — rebuilt fresh with library+binary split.
- `haap-sdk-cli` — rebuilt fresh with Option X subcommand set.
- `examples/`, `tests/` — rebuilt fresh.

## Wipe execution

Phase 2 completed:
- `feature/initial-sdk-full-population-2026-05-28` (de facto main, since
  the operator had set it as default) renamed locally to
  `main-legacy-pre-option-x` and pushed.
- Old local stale `main` (with only the Phase 0 forensic commit) deleted.
- New orphan `main` created locally with one bootstrap commit (`191bbfc`),
  pushed to remote.

**Required operator action (not completed by the agent):** the
`gh` CLI user `ravi-hawcx` lacks the `admin`/`maintain` permissions
needed to change the default branch. Via the GitHub web UI, the
operator should:

1. Visit https://github.com/hawcx/hx_agentic_sdk/settings/branches
2. Change default branch from `feature/initial-sdk-full-population-2026-05-28`
   to `main`.
3. (Optional) Delete `feature/initial-sdk-full-population-2026-05-28`.

The halt-state document at `/tmp/sdk_salvage/halt_state_phase_2.md`
captures this in more detail.

## Rebuild structure (7 crates)

| Crate | publish | Role |
|---|---|---|
| `haap-sdk-types` | false | RsvConfig, SealerConfig, SubstrateMaterial, VerifiedRequest, errors |
| `haap-sdk-ipc` | false | UDS framing + SO_PEERCRED helper |
| `haap-sdk-sealer` | false | AES-256-GCM sealer (3 backends) |
| `haap-substrate-reader` | false | Customer Redis SessionMaterial reader |
| `haap-rsv` | **true** | Publishable HAAP Verifier library |
| `haap-rsv-bin` | false | HTTP API sidecar (`haap-rsv` binary) |
| `haap-sdk-cli` | false | Testing/demo CLI (`haap-sdk` binary) |

Only `haap-rsv` is publishable to crates.io. The publication step
itself is **not** performed in this PR; the crate is publication-ready
pending crate name reservation and an explicit `cargo publish` call.

## Customer-facing release artifact

Per Mechanism 2 CI (`.github/workflows/release.yml`):

- Six platform-specific tarballs containing 7 binaries each (5 from
  `hx_labs`, 2 from this repo).
- Multi-arch Docker image at `ghcr.io/hawcx/hx-agent-sdk:<tag>`.
- Tag-triggered (`v*`) with `workflow_dispatch` fallback.
- Requires `HX_LABS_READ_TOKEN` repo secret (PAT with read access to
  the private `hawcx/hx_labs`).

The Dockerfile + CI workflow are configured but the secret is not
provisioned by the agent (requires operator action via repository
settings).

## Mechanism 2 CI status

| Item | Status |
|---|---|
| `.github/workflows/release.yml` | committed |
| `Dockerfile` (multi-stage) | committed |
| `docs/RELEASE.md` (operator guide) | committed |
| `HX_LABS_READ_TOKEN` secret | **operator action required** |
| First release tag | pending operator |

## PR closure plan

PR #1 and PR #2 are already MERGED (2026-05-15). They are not "open"
PRs awaiting closure — their commits are preserved on
`main-legacy-pre-option-x`. The new PR opened by this rebuild
references them in the description as historical context.

## Test coverage

- `haap-sdk-sealer`: 3/3 tests pass (FileSealer round-trip,
  tamper rejection, wrong-passphrase rejection).
- Other crates: no unit tests yet — added alongside the RSV cascade
  adapter wire-up.

`cargo check --workspace --all-targets` clean (no warnings, no errors).

## Open follow-ups

1. **RSV cascade adapter** (Phase 7 wire-up). Calling
   `haap_core::cascade::verify_and_decrypt_request` requires
   constructing `CascadeContext` and impl-ing `ReplayCheck` +
   `Authorizer` traits against the hx_labs surface. The 6-step
   adapter blueprint is documented in
   `crates/haap-rsv/src/rsv.rs`. Lands in a focused follow-up PR
   with the integration test fixture.
2. **Default-branch swap on GitHub** (operator web-UI action).
3. **`HX_LABS_READ_TOKEN` secret provisioning** (operator).
4. **First release tag**: `v0.1.0-alpha.1`.
5. **Mobile FFI** via UniFFI (alpha+1).
6. **System packages** (.deb, .rpm, Homebrew, scoop) — post-alpha.
7. **Native TLS variants** for environments that mandate it.
8. **Integration test fixtures**: depend on hx_labs Supervisor
   pipeline orchestration support; the integration test landed as
   an `#[ignore]` stub here and lands properly alongside the
   cascade adapter follow-up.
9. **`haap-rsv` crates.io publication** (manual; reserve the name
   first).
10. **Language wrappers** (Python, TypeScript, Go) around the
    HTTP API — opportunistic; no spec dependency.

## Cross-references

- AS-side cascade implementation: `hx_labs/crates/haap-core/src/cascade.rs::verify_and_decrypt_request`.
- Client-side X3DH ceremony: `hx_labs/crates/haap-auth/src/v6_3_registration.rs::perform_agent_registration`.
- Customer Redis writer (CAA): `hx_agent_client_admin_service` (separate repo).
- Five customer-side binaries: `hx_labs/crates/haap-auth-bin`,
  `haap-tqs-precompute-bin`, `haap-tqs-jit-bin`, `haap-assembler-bin`,
  `haap-supervisor`.
- Phase 0 forensic preflight (legacy): preserved on
  `main-legacy-pre-option-x` as `docs/phase_0_helper_signatures.md`.

## What this PR does NOT do

- Modify `~/Projects/hx_labs/`.
- Delete the GitHub repository.
- Delete PR #1 or PR #2 (already merged; preserved historically).
- Delete the `main-legacy-pre-option-x` branch.
- Publish `haap-rsv` to crates.io.
- Implement mobile FFI.
- Create system packages.
- Modify the v6.7.4 canonical spec.
- Auto-merge any PR.
- Fix gaps in hx_labs's Supervisor pipeline orchestration.
- Provision GitHub secrets or change the default branch (operator
  permissions needed).
