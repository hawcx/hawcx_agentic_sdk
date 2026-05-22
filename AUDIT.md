# hx_agentic_sdk — Migration Audit (vs hx_labs)
**Audit date:** 2026-05-21
**Canonical spec ref:** v7.2.5 (`hx_agent_canonical_spec/spec/canonical/HAAP-Canonical-Specification-v7_2_5.md`)
**Auditor:** backend-eng (Claude Opus 4.7)
**Repo under audit:** `/Users/raviramaraju/Projects/hx_agentic_sdk/`
**Reference:** `/Users/raviramaraju/Projects/hx_labs/`

---

## 1. Repo Purpose

`hx_agentic_sdk` is the **customer-facing SDK and distribution channel** for HAAP. It packages:

1. A **language-binding surface** that customer agent code links against:
   - `node/` — `@hawcx/hawcx-haap` npm package, a thin Unix-domain-socket (UDS) IPC client. Pure TypeScript, no NAPI / native module.
   - `python/` — `hawcx-haap` PyPI package, equivalent pure-Python UDS IPC client with a `pipe_win.py` for Windows named-pipe transport.
2. A **binary bundle** for `hx_agent_client_auth_service` — the 5-binary customer-side supervisor pipeline (`haap-authenticator` + `haap-tqs-precompute` + `haap-tqs-jit` + `haap-assembler` + `haap-eib` + `haap-supervisor`) plus two SDK-owned binaries (`haap-rsv` + `haap-sdk`). Shipped as platform-specific tarballs (via `release.yml`) and as a distroless OCI image at `ghcr.io/hawcx/hx-agent-sdk` (via `Dockerfile` + `Dockerfile.fast`).
3. The **RSV (Resource Server Verifier)** library + binary (`crates/haap-rsv` + `crates/haap-rsv-bin`) for MCP-server operators to verify §9 16-step cascade tokens — `publish = true` on `haap-rsv`, intended for crates.io.

Target consumers: customer agent integrators (Node/Python) and MCP RS operators (Rust crate + standalone `haap-rsv` binary).

**Critical architectural fact from `CLAUDE.md`:** the Node/Python SDKs never make network calls. All network egress is downstream of the supervisor. The SDK is a local UDS client speaking a framed binary protocol (`[u32 BE len][u8 type][JSON payload]`, 64 KiB cap) to the local Assembler.

---

## 2. Contents Inventory

Top-level tree of `/Users/raviramaraju/Projects/hx_agentic_sdk/`:

| Path | Purpose |
|---|---|
| `Cargo.toml` | Workspace root (7 SDK-internal crates) |
| `Cargo.lock` | Locked dependency graph |
| `Dockerfile` | Multi-stage distroless build, requires `hx_labs/` as sibling in build context |
| `Dockerfile.fast` | Local-dev variant |
| `crates/haap-sdk-types/` | Shared SDK types (substrate, errors, IPC payloads) |
| `crates/haap-sdk-ipc/` | UDS framed protocol, peer-UID verification (`SO_PEERCRED`) |
| `crates/haap-sdk-sealer/` | At-rest sealing for pinned identity (Argon2 + AES-GCM + OS keychain) |
| `crates/haap-substrate-reader/` | Redis-backed substrate reader (CS §40 split) |
| `crates/haap-rsv/` | §9 verification cascade library — **publishable to crates.io** |
| `crates/haap-rsv-bin/` | Standalone `haap-rsv` HTTP/UDS binary |
| `crates/haap-sdk-cli/` | `haap-sdk` operator CLI |
| `node/` | npm package `@hawcx/hawcx-haap` (TypeScript, vitest, 4 src files, 1089 LOC) |
| `python/` | PyPI package `hawcx-haap` (Python 3.10+, pytest, agent/ipc/errors/pipe_win) |
| `docker/bundle/` | docker-compose-driven local eval bundle (CAA + RSV + Redis) |
| `compose/docker-compose.dev.yml` | Dev compose |
| `docs/` | 16 markdown documents (ARCHITECTURE, DEPLOYMENT, INTEGRATION, RSV_HTTP_API, etc.) |
| `.github/workflows/` | `release.yml` (Rust binaries), `release-node.yml` (npm), `release-python.yml` (PyPI) |
| `CHANGELOG.md` | Aggregate cross-surface changelog; latest entry **v0.1.0-alpha.7 (2026-05-21)** |
| `CLAUDE.md` | Repo-local agent context |
| `README.md` | Public README (refs v7.2.0) |

**SDK version (claimed):** This repo's CHANGELOG and crate versions are all `0.1.0-alpha.7` / `0.1.0-alpha.1`. The hx_labs `CLAUDE.md` states "SDK Version: 0.8.0", and this is the **first material version-skew finding** — see §8 F-1.

No `dist/` for binary artifacts in-tree; binaries are produced by `release.yml` and uploaded as GitHub release assets. Python `src/hawcx_haap/__pycache__` and a `.egg-info` are checked-in build droppings (minor hygiene issue, see F-7).

---

## 3. Surface Mapping (hx_labs → hx_agentic_sdk)

| hx_labs path | hx_agentic_sdk equivalent | Status |
|---|---|---|
| `crates/haap-napi` | (none) | **Not migrated.** Node SDK here is pure-TS UDS client, no NAPI. Two completely different designs. |
| `crates/haap-pyo3` | (none) | **Not migrated.** Python SDK here is pure-Python UDS client, no pyo3 native module. |
| `crates/haap-wasm` | (none) | **Not migrated.** No WASM target in this repo at all. |
| `crates/haap-cli` | `crates/haap-sdk-cli` (binary `haap-sdk`) | Renamed surface; intent overlaps but cannot confirm feature parity without diffing both `src/`. |
| `crates/haap-manager` | (none) | **Not migrated.** Not present here. |
| `ts/haap-ipc/` (194-line `ipc-client.ts`, 110-line `types.ts`, ~543 LOC total) | `node/src/` (635-line `ipc.ts`, 341-line `agent.ts`, 1089 LOC total) | **Diverged and rewritten, not ported.** The SDK version is roughly 2x the line count and carries new H-3/H-4 hardening (`principalAllowlist`, `SO_PEERCRED`, socket-parent stat checks) that does not exist in `hx_labs/ts/haap-ipc/`. |
| `ts/nemoclaw/` | (none) | **Not migrated.** OpenClaw plugin stays NemoClaw-specific and is unrelated to the customer SDK surface. |
| `packages/@hx/shared-types`, `@hx/cedar-wasm`, `@hx/ui-components`, `@hx/api-client`, `@hx/auth` | (none) | **None migrated.** These are admin-console / user-console workspace packages, correctly out of scope for the customer SDK. They belong with the console repos (`hx_agent_admin_console`, `hx_user_console` per related audits). |
| `crates/haap-auth-bin`, `haap-tqs-precompute-bin`, `haap-tqs-jit-bin`, `haap-assembler-bin`, `haap-eib-bin`, `haap-supervisor` | (none — built **from** hx_labs, **bundled** here) | The Dockerfile + release.yml clone `hx_labs` as a sibling, run `cargo build --release --bin …` against it, then `COPY` the binaries into the SDK image / tarball. **Bundle is not source-resident in this repo.** |

**File-count diff per directory** (informational — for full surface diff, run `diff -rq` after both repos are pinned to release tags):

| Area | hx_labs | hx_agentic_sdk |
|---|---|---|
| Rust `.rs` files in `crates/` | 700+ across 30 crates | 30 across 7 crates |
| TS files in node-equivalent | 5 (`ts/haap-ipc/src/`) | 4 (`node/src/`) |
| Python files | 0 | 6 (`python/src/hawcx_haap/`, incl. `__init__.py`, `pipe_win.py`) |

---

## 4. Binary Bundle Audit

**This is the critical migration risk.** The Dockerfile (`/Users/raviramaraju/Projects/hx_agentic_sdk/Dockerfile`) and `release.yml` (`/Users/raviramaraju/Projects/hx_agentic_sdk/.github/workflows/release.yml`) **both require `hx_labs` to be checked out as a sibling directory**.

Bundle build steps (verbatim from `release.yml`, lines 35–80):

```yaml
- name: Checkout hx_labs (sibling)
  uses: actions/checkout@v4
  with:
    repository: hawcx/hx_labs
    token: ${{ secrets.HX_LABS_READ_TOKEN }}
    path: hx_labs
    ref: main
...
- name: Build hx_labs binaries
  working-directory: hx_labs
  run: |
    cargo build --release --target ${{ matrix.target }} \
      --bin haap-authenticator \
      --bin haap-tqs-precompute \
      --bin haap-tqs-jit \
      --bin haap-assembler \
      --bin haap-eib \
      --bin haap-supervisor
- name: Build SDK binaries
  working-directory: hx_agentic_sdk
  run: |
    cargo build --release --target ${{ matrix.target }} \
      --bin haap-rsv --bin haap-sdk
```

### Which hx_labs `*-bin` crates are built and bundled

| hx_labs binary crate | Bundled? | Build location |
|---|---|---|
| `haap-auth-bin` (binary `haap-authenticator`) | yes | hx_labs |
| `haap-tqs-precompute-bin` (binary `haap-tqs-precompute`) | yes | hx_labs |
| `haap-tqs-jit-bin` (binary `haap-tqs-jit`) | yes | hx_labs |
| `haap-assembler-bin` (binary `haap-assembler`) | yes | hx_labs |
| `haap-eib-bin` (binary `haap-eib`) | yes | hx_labs |
| `haap-supervisor` (binary `haap-supervisor`) | yes | hx_labs |
| `haap-admin-auth-bin` (CAA Admin Authenticator) | **no** | — (correctly excluded; CAA ships from `hx_agent_client_admin_service`, see hx_labs `CLAUDE.md` ownership note) |
| `haap-rsv` (SDK-owned) | yes | hx_agentic_sdk |
| `haap-sdk` (SDK-owned) | yes | hx_agentic_sdk |

### Is the bundle reproducible from sources in this repo?

**No.** The workspace `Cargo.toml` (lines 21–26) explicitly declares path-deps to `../hx_labs`:

```toml
haap-core   = { path = "../hx_labs/crates/haap-core", default-features = false, features = ["redis-backend"] }
haap-crypto = { path = "../hx_labs/crates/haap-crypto" }
haap-ipc    = { path = "../hx_labs/crates/haap-ipc" }
haap-wire   = { path = "../hx_labs/crates/haap-wire" }
haap-redis  = { path = "../hx_labs/crates/haap-redis" }
```

The repo cannot build standalone. When `hx_labs` retires (per the migration brief), every CI release, every local developer build, and every customer-side `docker build` here breaks. This is **F-2, the load-bearing migration blocker**.

The Dockerfile is hardened — protoc is pinned by SHA-256 (L-2 hardening, 2026-05-20), distroless cc-debian12 runtime, ENTRYPOINT defaults to `haap-supervisor`. Good craft. None of that helps if the input sources disappear.

### docker/bundle (local eval, not production)

`docker/bundle/docker-compose.yml` references two pre-built images: `ghcr.io/hawcx/hx-caa` (from `hx_agent_client_admin_service`) and `ghcr.io/hawcx/hx-agent-sdk` (this repo). Compose-up spins CAA + RSV + Redis for local cascade exercise. Useful for customer onboarding; not a production deployment shape.

---

## 5. Language Binding Coverage

| Surface | Build artifact | Native module? | Version | Publishing config | Published? |
|---|---|---|---|---|---|
| Node | `dist/index.{js,d.ts}` from `tsc` | **No** — pure TypeScript, no NAPI binding.gyp / no `.node` file | `0.1.0-alpha.1` (per `node/package.json`) | npm provenance, `--access public`, registry `npmjs.org` (workflow `release-node.yml`) | **Not yet** — per CLAUDE.md, npm registry returns 404 |
| Python | sdist + wheel from `python -m build` (setuptools backend) | **No** — pure Python, no pyo3, no compiled `.so` | `0.1.0a1` | `twine check` validates; publish step truncated in head 60 lines but workflow exists | unconfirmed; build/test matrix verified |
| WASM | (none) | n/a | n/a | n/a | **Not shipped** |
| Rust crate | `haap-rsv` from `cargo publish` (other 6 crates marked `publish = false`) | n/a | `0.1.0-alpha.1` | crates.io–publishable per `publish = true` flag | unconfirmed |

**Version alignment:** All TS / Python / Rust SDK crates carry an alpha-1 family version. **None of them are `0.8.0`.** The hx_labs `CLAUDE.md` line "SDK Version: 0.8.0" refers to the legacy in-repo TS package versions in `packages/@hx/*` / `ts/haap-ipc`, **not** to the `hx_agentic_sdk` numbering. The two are completely independent version timelines and there is no cross-repo coherence today. See F-1.

---

## 6. Workspace & Dependency Audit

`Cargo.toml` is well-structured: 7-member workspace, workspace-level `[workspace.package]` for edition/license/authors/repository/rust-version (1.75), workspace-level `[workspace.dependencies]` for all third-party crates so versions are pinned in one place. Pinning discipline is at Tailscale/Cloudflare level — `subtle = "2.6"` carries an inline comment explaining why constant-time compare is hard-pinned through hx_labs's vetted version chain, and `hyper`/`hyper-util`/`tower` have a paragraph explaining why axum 0.7's UDS-incompatible `serve()` forces the per-connection hyper wiring.

### Path-deps to hx_labs (these will break on retirement)

Lines 22–26 of `/Users/raviramaraju/Projects/hx_agentic_sdk/Cargo.toml`:

- `haap-core   = { path = "../hx_labs/crates/haap-core", default-features = false, features = ["redis-backend"] }`
- `haap-crypto = { path = "../hx_labs/crates/haap-crypto" }`
- `haap-ipc    = { path = "../hx_labs/crates/haap-ipc" }`
- `haap-wire   = { path = "../hx_labs/crates/haap-wire" }`
- `haap-redis  = { path = "../hx_labs/crates/haap-redis" }`

Comment on line 21 acknowledges the dependency: `# Path-deps to hx_labs (RSV needs cascade + types; sealer + ipc + substrate-reader are SDK-owned)`.

**`hx-crypto-core` resolution:** Not directly used here. `haap-crypto` (in hx_labs) is the consumer of `hx-crypto-core` and re-exports the necessary primitives. When hx_labs retires, `haap-crypto`'s 45 HAAP + 8 HAAPI + 55 EID domain separators (per hx_labs `CLAUDE.md`) must travel with it — either bundled into a new `hawcx-protocol-lib` crate or split into `crates.io`-published crates (per the canonical migration brief).

---

## 7. Production Readiness

| Item | State |
|---|---|
| README.md | Present (60 KB-ish from `wc`-like estimate, content references **v7.2.0** — stale, see F-3) |
| CHANGELOG.md | Present, well-maintained, latest **2026-05-21 v0.1.0-alpha.7** with explicit Security / Migration sections. **Stripe-level discipline.** |
| CLAUDE.md | Present, accurate on architectural facts, references **v7.2.0** (stale, see F-3) |
| Dockerfile | Present, pinned protoc, distroless runtime, multi-stage. **Reproducibility blocker: requires sibling hx_labs.** |
| Dockerfile.fast | Present, dev build variant |
| Publishing config | npm provenance + PyPI twine + crates.io (`publish = true` on `haap-rsv`) all set up; GH workflows in place |
| CI | Three workflows: `release.yml` (Rust + Docker tarballs), `release-node.yml` (npm test matrix across Linux/mac/Win × Node 18/20/22 then publish), `release-python.yml` (sdist + wheel + py 3.10–3.13 matrix). No PR-level test/lint workflow visible from filename inspection — see F-5. |
| docs/ | 16 documents incl. RSV_HTTP_API, INTEGRATION, DEPLOYMENT, ARCHITECTURE, plus dated closure reports (`docker_bundle_closure_2026-05-15`, `priority2_foundation_closure_2026-05-17`, etc.) — good operational discipline |

---

## 8. Findings — Gaps & Risks

### F-1 [SEV-HIGH] SDK version skew between hx_labs and hx_agentic_sdk
- hx_labs `CLAUDE.md` declares `SDK Version: 0.8.0`. **hx_agentic_sdk crate / npm / PyPI versions are all `0.1.0-alpha.{1,7}`.** These are independent timelines with no shared truth.
- **Risk:** Customers reading hx_labs docs ("SDK 0.8.0") and looking for `@hawcx/hawcx-haap@0.8.0` on npm will not find it. Even after migration to a published surface, the version is `0.1.0-alpha`.
- **Action:** Decide whether to (a) rev `hx_agentic_sdk` to `0.8.0` to match the legacy designation at the point of public release, or (b) declare the `0.1.0-alpha` line authoritative and erase the `0.8.0` reference from all retiring hx_labs docs. Either way, do this before public publish.

### F-2 [SEV-CRITICAL] Repo cannot build without hx_labs as a sibling checkout
- Workspace `Cargo.toml` has 5 path-deps into `../hx_labs/crates/`. Dockerfile and `release.yml` both clone hx_labs first.
- **Risk:** When hx_labs retires (the explicit goal of this migration), this repo's CI, Docker builds, and customer-side `cargo build` all break instantly. **This is the migration's load-bearing dependency.**
- **Action:** Per the cross-repo migration brief, extract a `hawcx-protocol-lib` (carrying `haap-core` + `haap-crypto` + `haap-ipc` + `haap-wire` + `haap-redis`) into either (a) a new shared library repo with versioned releases, or (b) crates.io-published crates under the `hawcx-*` namespace. Then replace the 5 path-deps with `version = "…"`-pinned deps. Do this before the hx_labs retirement cut-over.

### F-3 [SEV-MED] Spec version references stale (v7.2.0 not v7.2.5)
- README.md, CLAUDE.md, `python/pyproject.toml`, and likely inline `// CS v7.2.0 §…` comments throughout reference v7.2.0. Canonical spec is **v7.2.5 as of 2026-05-20** (§45.7.5 MCP transport bearer carriage).
- **Risk:** Customers integrating today get docs that point at a superseded spec. MCP JSON-RPC `-32001…-32005` error mapping (new in v7.2.5) is not documented here.
- **Action:** Sweep README / CLAUDE / pyproject / `git grep "v7\.2\.0"` and update to v7.2.5. Add a v7.2.5 mention to CHANGELOG (next release entry).

### F-4 [SEV-MED] Surface mismatch — hx_labs lists `haap-napi`, `haap-pyo3`, `haap-wasm` as the migration source
- The migration brief frames this repo as "Corresponds to hx_labs surface: `crates/haap-napi`, `crates/haap-pyo3`, `crates/haap-wasm`, `crates/haap-cli`, `crates/haap-manager`". In reality, the bindings here are **pure-language UDS clients** and do not link to any Rust core. There is no NAPI, no pyo3, no WASM target.
- **Risk:** Mismatched expectation in migration plan. Either (a) the legacy NAPI/pyo3/WASM crates were dropped from the product surface intentionally and this needs to be documented as a deprecation, or (b) functionality that lives in those legacy crates needs to be ported into the pure-TS / pure-Python clients before hx_labs retirement.
- **Action:** Diff `hx_labs/crates/haap-napi/src/`, `haap-pyo3/src/`, `haap-wasm/src/` against `node/src/`, `python/src/` to confirm zero functional gap before retiring hx_labs. If the legacy crates are unused, mark them dead in hx_labs's retirement PR.

### F-5 [SEV-LOW] No PR-level CI workflow visible
- The three workflows in `.github/workflows/` are all `release-*.yml`, gated on tag pushes. There appears to be no `ci.yml` running `cargo test --workspace`, `cargo clippy`, `tsc`, `pytest` on pull-request open.
- **Risk:** Regressions land on main undetected until release tag.
- **Action:** Verify (this audit did not exhaustively read `.github/`); if absent, add a `ci.yml` matching the test matrix already used in the release workflows.

### F-6 [SEV-LOW] `haap-manager` from hx_labs has no equivalent here
- hx_labs ships `crates/haap-manager` (per `CLAUDE.md` it's one of the 30 crates and explicitly called out in the migration brief). Not present in `hx_agentic_sdk`.
- **Risk:** Functional gap if `haap-manager` is required by any customer-facing flow. If it's an internal admin tool, fine.
- **Action:** Confirm `haap-manager` ownership — likely belongs in `hx_agent_admin_console` or `hx_agent_client_admin_service`, not the SDK. Document the placement in the migration plan.

### F-7 [SEV-LOW] Build droppings checked into `python/src/`
- `python/src/hawcx_haap/__pycache__/` and `hawcx_haap.egg-info/` directories present from `ls`. `.gitignore` (78 bytes, very short) may not be excluding these.
- **Risk:** Build droppings inflate repo size, can leak host-specific paths, and break reproducibility.
- **Action:** Add `__pycache__/`, `*.egg-info/`, `dist/`, `build/`, `.venv/` to `.gitignore`; remove tracked copies with `git rm -r --cached`.

### F-8 [SEV-MED] Docker bundle pins to a single CAA image but CAA has three production-tracked sibling repos
- `docker/bundle/docker-compose.yml` pins `ghcr.io/hawcx/hx-caa:${HAAP_VERSION}`. Per hx_labs `CLAUDE.md`, the deployed CAA lives in `hx_agent_client_admin_service` with `_n8` (NVIDIA-NemoClaw) and `_w4b` (W4-broad-audit) sibling branches.
- **Risk:** Bundle consumers using NemoClaw or W4b deployments will get the wrong CAA image. Not strictly a SDK bug, but customer-facing confusion.
- **Action:** Either document image-tag variants in `docker/bundle/README.md`, or expose `CAA_IMAGE` as a compose env var and default to the broadest base.

### F-9 [SEV-LOW] `haap-supervisor` ENTRYPOINT in main Dockerfile but bundle's RSV service overrides it
- `Dockerfile` line 64: `ENTRYPOINT ["/usr/local/bin/haap-supervisor"]`. The compose file's `rsv` service comments "Override SDK image's default entrypoint (haap-supervisor) to run RSV instead." This works, but composing two roles into a single image and switching by entrypoint override is a smell.
- **Risk:** Image bloat (every customer deploying the supervisor also pulls the RSV binary, and vice versa); attack-surface widening.
- **Action:** Consider splitting into `ghcr.io/hawcx/haap-supervisor` and `ghcr.io/hawcx/haap-rsv` images at the next minor. Stripe / Cloudflare ship one binary per image as a rule.

---

## 9. Recommended Actions (priority order)

1. **F-2 (CRITICAL):** Define the post-hx_labs source of `haap-core` + `haap-crypto` + `haap-ipc` + `haap-wire` + `haap-redis`. This blocks every other action. Recommended: lift them into a new `hawcx-protocol-lib` repo published to crates.io under the `hawcx-*` namespace, with version-pinned (not path-) deps.
2. **F-1 (HIGH):** Reconcile the `0.8.0` (hx_labs claim) vs `0.1.0-alpha.7` (this repo) version-skew before any public publish. Pick one timeline.
3. **F-4 (MED):** Confirm whether legacy `haap-napi` / `haap-pyo3` / `haap-wasm` crates carry any unported functionality. If they don't, delete them from hx_labs in the retirement PR.
4. **F-3 (MED):** Bump all docs and inline comments from v7.2.0 → v7.2.5; add §45.7.5 MCP JSON-RPC error-mapping coverage to `docs/RSV_HTTP_API.md` (the RSV currently does HTTP error responses, not JSON-RPC).
5. **F-5 (LOW):** Add a PR-gate `ci.yml` running the same test matrix as `release-*.yml`.
6. **F-8 (MED):** Document or parameterize CAA image variant for the local-eval bundle.
7. **F-7, F-6, F-9 (LOW):** Hygiene — gitignore the Python build droppings, document `haap-manager` placement, plan image-split for next minor.

Once F-1 / F-2 / F-3 land, this repo is ready to be the canonical customer-facing SDK distribution channel post-hx_labs.

---

## 10. Appendix — Crate + Package Inventory

### Rust crates (workspace members, all `version = "0.1.0-alpha.1"`)

| Crate | `publish` | Binary | Path-deps to hx_labs |
|---|---|---|---|
| `haap-sdk-types` | false | — | `haap-redis` |
| `haap-sdk-ipc` | false | — | (none — external only: tokio/nix/libc) |
| `haap-sdk-sealer` | false | — | (none — external only: argon2/aes-gcm/keyring) |
| `haap-substrate-reader` | false | — | `haap-redis` |
| `haap-rsv` | **true** | — (library) | `haap-core`, `haap-wire`, `haap-crypto` |
| `haap-rsv-bin` | false | `haap-rsv` | (transitively via `haap-rsv`) |
| `haap-sdk-cli` | false | `haap-sdk` | (transitively via `haap-rsv` + `haap-sdk-sealer`) |

### Language packages

| Package | Version | Registry | Native code? |
|---|---|---|---|
| `@hawcx/hawcx-haap` | `0.1.0-alpha.1` | npm (provenance, public) | No — pure TS |
| `hawcx-haap` | `0.1.0a1` | PyPI | No — pure Python |
| (none) | — | crates.io: `haap-rsv` planned (`publish = true`) | yes (RSV cascade) |

### Bundled binaries from hx_labs (built by Dockerfile / release.yml)

| Binary | hx_labs source crate | Bundled? |
|---|---|---|
| `haap-authenticator` | `haap-auth-bin` | yes |
| `haap-tqs-precompute` | `haap-tqs-precompute-bin` | yes |
| `haap-tqs-jit` | `haap-tqs-jit-bin` | yes |
| `haap-assembler` | `haap-assembler-bin` | yes |
| `haap-eib` | `haap-eib-bin` | yes |
| `haap-supervisor` | `haap-supervisor` | yes |

### SDK-owned binaries (built from this repo)

| Binary | Crate | Bundled? |
|---|---|---|
| `haap-rsv` | `haap-rsv-bin` | yes |
| `haap-sdk` | `haap-sdk-cli` | yes |

### CI/CD workflows

| Workflow | Trigger | Output |
|---|---|---|
| `release.yml` | tag `v*` | Per-target tarballs (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`) + Docker image |
| `release-node.yml` | tag `node-v*` | npm publish with provenance |
| `release-python.yml` | tag `python-v*` | PyPI publish via twine |
