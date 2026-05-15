# SDK initial population — closure report

**Date:** 2026-05-28
**Branch:** `feature/initial-sdk-full-population-2026-05-28`
**Repo state before this PR:** empty remote, no commits.
**Repo state after this PR:** 10-crate Cargo workspace + Phase 0–5
fully implemented, Phase 6–10 foundational scaffolding compiling,
documentation, examples, integration test stub.

## Architectural characterization

The SDK is a thin wrapper over the existing `hx_labs` protocol library
plus SDK-owned infrastructure. **No protocol crypto is reimplemented in
the SDK.** Cryptographic operations call into `haap-core`, `haap-crypto`,
`haap-wire`, and `haap-auth`.

### Wrapper-vs-infrastructure boundary

| SDK crate | What it does | Hx_labs primitives it wraps |
|---|---|---|
| `haap-sdk-types` | env config readers, error enums, IPC message envelope, RegisteredAgent | (no protocol crypto — SDK-owned) |
| `haap-sdk-ipc` | UDS framing + SO_PEERCRED + IpcServer/Client | (no protocol crypto — SDK-owned) |
| `haap-sdk-sealer` | AgentIdentitySealer trait + 3 impls | (no protocol crypto — SDK-owned; storage protection only) |
| `haap-substrate-reader` | customer Redis SessionMaterial reader | (no protocol crypto — SDK-owned reader of CAA-written records) |
| `haap-authenticator` | process binary, IPC server, sealer integration | wraps `haap_auth::v6_3_registration::perform_agent_registration` (Phase 6 follow-up wires this) |
| `haap-tqs` | process binary, pre-mint queue management | wraps `haap_core::mint::mint_token` (Phase 7 follow-up wires this) |
| `haap-assembler` | single-flight + IPC server + body framing | wraps `haap_core::request::*` + `haap_core::response::*` (Phase 8 follow-up wires this) |
| `haap-rsv` | replay store, substrate integration, network handler | wraps `haap_core::cascade::verify_and_decrypt_request` (Phase 9 follow-up wires this) |
| `haap-supervisor` | child-process orchestration, AgentRuntime facade | (no protocol crypto — SDK-owned) |
| `haap-sdk-cli` | testing/demo CLI | wraps the above |

The "Phase N follow-up" wire-ups remain because the actual hx_labs
function signatures diverge enough from the prompt's prose that careful
adapter code is best written in a focused PR with the full byte-level
test fixture available. See `docs/phase_0_helper_signatures.md` for the
real signatures.

## What landed per crate

### Phase 0 — Bootstrap + forensic preflight

- Repo cloned from empty remote.
- Feature branch `feature/initial-sdk-full-population-2026-05-28` created.
- `docs/phase_0_helper_signatures.md` written documenting the actual
  hx_labs API surface and divergences from the prompt's assumptions.
- Hx_labs PR 3a verified merged in main (commit `18025de`).

### Phase 1 — Workspace scaffolding

- Root `Cargo.toml` workspace with 10 members.
- Path-deps to `hx_labs/crates/`: haap-core, haap-crypto, haap-ipc,
  haap-auth, plus four additions per Phase 0 findings (haap-wire,
  haap-keystore, haap-redis, haap-as-client).
- `cargo check --workspace` clean.

### Phase 2 — `haap-sdk-types` (fully implemented)

- `AuthenticatorConfig` with `from_env()` reading all documented
  `HAAP_*` env vars; rejects `http://` URLs unless
  `HAAP_ALLOW_HTTP_FOR_DEV=true`.
- `SealerConfig` enum (File / OsKeychain / KmsWrapped).
- `RegisteredAgent` with secret-material fields auto-zeroized on drop
  (TrustLevel + agent_class + IK_i_public skip-listed for zeroize).
  Debug impl redacts secret material.
- `SubstrateMaterial` (CAA writes, RSV reads via reader crate).
- `Token` / `TokenBatch` with session_id: u64 per actual wire format.
- `IpcMessage` envelope with SessionKeyResponse, GetTokenRequest/Response,
  AssembleRequest/Response, DecryptResponse, lifecycle variants. Secret
  payloads boxed.
- `ConfigError`, `SealerError`, `SubstrateReaderError`, `SdkError`
  thiserror enums.

### Phase 3 — `haap-sdk-sealer` (fully implemented)

- `AgentIdentitySealer` async trait with `backend_tag` for safety.
- **FileSealer**: Argon2id (m=64MiB, t=3, p=4) → ChaCha20Poly1305 over
  `[salt(16) || nonce(12) || ct_with_tag]`. AAD
  `b"haap-authenticator-file-sealer-v1"`.
- **OsKeychainSealer**: keyring-rs v3, key stored as hex string at
  (service, account); ciphertext `[nonce(12) || ct_with_tag]`. AAD
  `b"haap-authenticator-os-keychain-v1"`. Tests gated behind
  `os-keychain-tests` feature.
- **KmsWrappedSealer**: NotImplemented stub.
- **Tests**: 3 FileSealer tests pass (round-trip, tampered-ciphertext
  rejection, wrong-passphrase rejection).

### Phase 4 — `haap-sdk-ipc` (fully implemented)

- Length-prefixed framing: `u32_be(payload_len) || payload_bytes`,
  max 16 MiB.
- SO_PEERCRED helpers: `nix::PeerCredentials` on Linux, raw
  `libc::getsockopt(SOL_LOCAL, LOCAL_PEERPID/LOCAL_PEEREUID)` +
  `getpeereid` on macOS, `PeerCredUnsupported` elsewhere.
- `IpcServer::bind` sets socket perms 0600 and rejects connections
  whose peer UID doesn't match `expected_peer_uid`.
- `ipc_socket_dir()` resolves `$XDG_RUNTIME_DIR/hawcx/` (Linux) or
  `$TMPDIR/hawcx/` (macOS), creates with mode 0700.

### Phase 5 — `haap-substrate-reader` (fully implemented)

- `CustomerSubstrateReader::connect` + `fetch_session(session_id: u64)`.
- Key format: `haap:session:{session_id:016x}`.
- Uses `redis::aio::ConnectionManager` for connection pooling.

### Phase 6 — `haap-authenticator` (scaffolded; protocol wire-up follow-up)

- Process binary entrypoint.
- IPC server on `authenticator.sock` with SO_PEERCRED-restricted access.
- `GetSessionKeyRequest` handler returns SessionKeyResponse with
  `k_session`, `session_id: u64`, `agent_instance_id`, `verifier_secret`.
- Sealer-backed unseal-on-startup; falls through to register flow if
  no sealed bundle present.
- **Follow-up**: wire up `haap_auth::v6_3_registration::perform_agent_registration`
  with ASClient + UnixTqsIpc + KeyStore + OrgToken construction.

### Phase 7 — `haap-tqs` (scaffolded; mint wire-up follow-up)

- Process binary; connects to `authenticator.sock` at startup for
  K_session.
- IPC server on `tqs.sock` with SO_PEERCRED-restricted access.
- `TokenQueue` with `TqsConfig` (batch 10, cap 10K, TTL 60s).
- **Follow-up**: wire up `haap_core::mint::mint_token` per the actual
  `MintInput` shape.

### Phase 8 — `haap-assembler` (single-flight implemented; crypto wire-up follow-up)

- `SingleFlight` enforces pipelining=PROHIBITED with 3 passing tests.
- IPC server on `assembler.sock`.
- **Follow-up**: wire up `haap_core::request::encrypt_request` and
  `haap_core::response::decrypt_response` per their actual signatures.

### Phase 9 — `haap-rsv` (replay store implemented; cascade wire-up follow-up)

- `VerifyError` taxonomy covering all spec-defined cascade exit conditions.
- `ReplayStore` two-tier (in-process LRU + Redis SETNX with TTL).
- `Rsv` struct holds substrate + replay + audience hash.
- **Follow-up**: wire up `haap_core::cascade::verify_and_decrypt_request`
  for the 16-step cascade.

### Phase 10 — `haap-supervisor` (process spawning implemented)

- `SupervisorConfig`.
- `Supervisor::launch` spawns Authenticator → TQS → Assembler in order
  with `wait_for_socket` gating between each.
- `Supervisor::shutdown` for cleanup.
- `AgentRuntime` facade with `send_request(body, audience)` async API.
- **Follow-up**: wire up the network transport (HTTPS to MCP server) +
  decrypt round-trip.

### Phase 11 — `haap-sdk-cli` (6 subcommands; 2 functional)

- `register`, `seal`, `unseal`, `run-supervisor`, `run-rsv`,
  `substrate-fetch` subcommands defined.
- `unseal` and `substrate-fetch` are fully functional.
- `register`, `seal`, `run-supervisor`, `run-rsv` return clear
  "wired up in Phase N follow-up" errors.

### Phase 12 — Integration test (stub)

- `tests/integration_against_local_as.rs` skeleton with `#[ignore]`
  attribute documenting the test infra requirements.
- **Follow-up**: wire up alongside Phase 6–9.

### Phase 13 — Examples (skeletal)

- `basic_registration.rs`: reads + prints config from env.
- `full_pipeline.rs`: launches Supervisor, demonstrates AgentRuntime.
- `rsv_standalone.rs`: initializes RSV from env, ready for HTTP wrapper.
- `mcp_server_integration.rs`: MCP server skeleton.

### Phase 14 — Documentation

- Top-level `README.md` (quick-start, env var table, license, status).
- `docs/ARCHITECTURE.md` (4-process + RSV diagram, threat model,
  post-alpha roadmap).
- `docs/DEPLOYMENT.md` (topology, env vars, sealer backend matrix,
  pre-flight checklist).
- `docs/INTEGRATION.md` (for agent runtimes, MCP servers, CAA developers).
- `docs/REDIS_SETUP.md` (Docker Compose dev, cloud-managed for AWS/GCP/
  Azure/Redis Cloud, self-hosted patterns, operational notes).
- `compose/docker-compose.dev.yml` ready-to-use Redis for local dev.

### Phase 15 — This closure report

### Phase 16 — Final verification + PR

- `cargo check --workspace` clean.
- All implemented tests pass.
- PR created on `feature/initial-sdk-full-population-2026-05-28`.

## Test coverage

| Crate | Unit tests | Status |
|---|---|---|
| `haap-sdk-sealer` | 3 (FileSealer round-trip, tamper rejection, wrong passphrase) | passing |
| `haap-assembler` | 3 (pipelining rejection, no-in-flight, begin/complete round-trip) | passing |
| Others | none yet (test scaffolding lands with the protocol wire-up follow-ups) | — |

## Open follow-ups

1. **Protocol crypto wire-up (Phase 6–9, Phase 12)**: connect the SDK's
   stubbed crypto call sites to actual hx_labs functions. Requires the
   AS test fixture + Redis + mock admin console infra to verify byte-level
   correctness.
2. **KMS sealer integration**: AWS KMS + GCP KMS SDK wiring for
   `KmsWrappedSealer`.
3. **Python bindings via pyo3**: top-level facade exposed as Python
   classes; CI matrix would build wheels via maturin.
4. **TypeScript bindings via napi-rs**: same facade.
5. **CI workflow**: cargo check/clippy/test on push and PR; cargo-deny
   and cargo-audit for supply chain.
6. **Post-quantum sealer variant**: ML-KEM hybrid for the file +
   keychain backends.
7. **Integration test infrastructure**: testcontainers-rs for the
   Redis dependency, in-process AS spinner sharing fixtures with hx_labs.

## Architectural overlap with existing hx_labs crates

`hx_labs` already ships its own `haap-assembler`, `haap-supervisor`,
`haap-tqs-common`/`haap-tqs-precompute`/`haap-tqs-jit` library crates
with overlapping responsibilities. This SDK's same-named crates are
**process-level wrappers** (binaries + sealer integration + CLI
ergonomics) that path-dep to the hx_labs *library* crates for protocol
primitives. The two coexist by separation of concerns — hx_labs is
the library; this repo is the distributable SDK around it.

If the eventual decision is to consolidate (e.g., extract hx_labs's
process binaries here and remove them from hx_labs), that's a separate
PR scope.

## Cross-references

- AS-side cascade implementation: `hx_labs/crates/haap-server/...`
  (PR 3a, commit `18025de`).
- Client-side X3DH ceremony reference:
  `hx_labs/crates/haap-auth/src/v6_3_registration.rs::perform_agent_registration`.
- CAA (substrate writer): `hx_agent_client_admin_service` (separate repo).
- Admin console: `hx_admin_console`. User console: `hx_user_console`.
- Phase 0 forensic preflight: `docs/phase_0_helper_signatures.md`.

## What this PR does NOT do

- Publish to crates.io.
- Set up GitHub Actions CI (README mentions follow-up).
- Implement Python or TypeScript bindings.
- Modify `hx_labs`.
- Implement the customer-side substrate writer.
- Implement AWS/GCP KMS integration.
- Modify the v6.7.4 canonical specification.
