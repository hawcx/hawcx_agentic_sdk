# RSV Cascade Adapter — Closure Report

**Date:** 2026-05-15
**Branch:** `feature/rsv-cascade-adapter-2026-05-15`
**Base:** `main` (PR #3 clean-slate rebuild merged 2026-05-15)
**Release target:** v0.1.0-alpha.2 (alpha-1 ships with stubbed RSV)

## Summary

Replaces the two stub methods in `haap-rsv` (`verify_and_decrypt`,
`encrypt_response`) with actual wire-up to `haap_core::cascade::verify_and_decrypt_request`
and `haap_core::response::encrypt_response`. RSV becomes functionally
operational; v0.1.0-alpha.2 is the first functional release.

## What landed

### Phase 0 — Forensic preflight + Phase 0.4 verdict

`docs/rsv_adapter_helper_signatures.md` pins the actual hx_labs API
(verified against hx_labs HEAD `17da98a`). Documents critical
divergences from the prompt's blueprint:

- **JTI is `[u8; 16]`** (raw CSPRNG from TokenBody), NOT `[u8; 22]`
  (22-byte base64url wire form lives only on `ParsedToken`).
- **ReplayCheck is synchronous** with `replay_precheck` + `replay_consume`
  methods, not async.
- **Authorizer signature** `authorize(scope, operation, resource) -> bool`
  has no access to `SessionRecord`.
- **SubstrateMaterial is substantially incomplete** vs `SessionRecord`
  — missing `tqs_public`, `sek_secret`/`sek_public`, `sek_valid_from`/`until`,
  `status`, etc. Resolution: re-export `haap_redis::RawSessionRecord`.
- **Registration-scope semantics not implementable** without trait
  extension or substrate-schema extension. Resolution:
  `PermissiveAuthorizer` for alpha; cascade-internal step-13
  enforcement (`scope_ceiling`) remains active.

### Phase 1 — Substrate schema correction

`crates/haap-sdk-types/src/material.rs` now re-exports
`haap_redis::RawSessionRecord` as `SubstrateMaterial`. The substrate
reader (`crates/haap-substrate-reader/src/lib.rs`) delegates to
`haap_redis::get_session` — byte-identical schema handling (HGETALL
over `hawcx:session:{session_id}`), not bincode-blob GET.

`VerifiedRequest.jti` schema corrected from `[u8; 22]` to `[u8; 16]`.

### Phase 2 — Replay enforcement

`crates/haap-rsv/src/replay.rs`:

- `InMemReplayCheck`: HashSet-backed for unit tests
- `RedisReplayCheck`: sync Redis SETNX via `redis::Connection`, using
  `haap_redis::replay_key_v070` for key naming. Mirrors hx_labs's
  `replay_adapter::RedisReplayCheck` pattern so the SDK doesn't take a
  dep on haap-server (which has unrelated AS concerns).

5 unit tests cover precheck, consume, replay rejection, distinct-jti.

### Phase 3 — Authorizer

`crates/haap-rsv/src/authorizer.rs`:

- `PermissiveAuthorizer`: returns true unconditionally.
- Module-level doc comment captures the rationale and the two
  prerequisites for `RegistrationScopeAuthorizer` (substrate-schema
  extension + Authorizer-trait extension).

### Phase 4 — verify_and_decrypt

`crates/haap-rsv/src/rsv.rs`:

- 6-step adapter: `decode_token` → `fetch_session` →
  `SessionRecord::try_from` → `CascadeContext` → `ReplayCheck` /
  `Authorizer` → `verify_and_decrypt_request`.
- Three entry points:
  - `verify_and_decrypt(token_bytes)` — token-only, Redis replay
  - `verify_and_decrypt_with_body(token_bytes, encrypted_request, request_aad)`
    — token + encrypted body
  - `verify_and_decrypt_with_in_mem_replay(token_bytes, &mut replay, ...)`
    — for unit tests
- `Rsv` holds dual Redis clients: async `ConnectionManager` (substrate)
  + sync `redis::Client` (cascade replay).

### Phase 5 — encrypt_response

`crates/haap-rsv/src/rsv.rs`:

- Single delegating call to `haap_core::response::encrypt_response`
  with `verified.response_key` + `verified.session_id`.

### Phase 6 — CascadeRejectReason mapping coverage

`crates/haap-rsv/tests/cascade_rejections.rs`:

- 3 tests pass: `cascade_reject_reasons_all_have_mapping`,
  `malformed_token_returns_framing_error`,
  `rsv_new_requires_reachable_redis`.
- Mapping coverage is enforced by the exhaustive `match` in
  `rsv.rs::map_cascade_reject`. A new `CascadeRejectReason` variant
  added to hx_labs without updating the SDK's mapping function
  triggers a compile error here.
- Per-variant positive tests (one for each rejection condition)
  require full token-mint machinery — defer to the integration test
  suite (Phase 7).

### Phase 7 — Full-pipeline integration test (feature-gated)

`crates/haap-rsv/tests/full_pipeline.rs`:

- Gated behind `integration-tests` feature flag.
- Test is `#[ignore]` and currently `panic!`s with a doc reference.
- Wire-up depends on hx_labs Supervisor pipeline orchestration
  support (see `docs/STATUS_2026-06-02.md` for the dependency).
- `docs/INTEGRATION_TEST_SETUP.md` documents the env vars + binary
  prerequisites + invocation.

## Key design decisions

### PermissiveAuthorizer for alpha

The Authorizer trait signature `authorize(scope, operation, resource) -> bool`
has no access to `SessionRecord`, and the SDK's substrate (now
`RawSessionRecord` from `haap-redis`) carries no `registered_scope`
field. Two prerequisites for `RegistrationScopeAuthorizer`:

1. Substrate schema extension: add `registered_scope` field to
   `RawSessionRecord` (hx_labs PR), have the CAA write it.
2. Authorizer trait extension OR stateful per-request Authorizer
   constructed from the substrate.

Cascade-internal `scope_ceiling` enforcement at step 13 remains
active — `PermissiveAuthorizer` only short-circuits the
operation+resource policy evaluation that belongs to a future Cedar
layer.

### Dual Redis clients in Rsv

Async `ConnectionManager` for substrate (fits the async `fetch_session`
API) + sync `redis::Client` for replay (the cascade's `ReplayCheck`
trait is sync, called from sync `verify_and_decrypt_request`). This
avoids `block_on()` hazards and matches hx_labs's `RedisReplayCheck`
pattern.

### `[u8; 16]` JTI in `VerifiedRequest`

Matches the post-cascade `TokenBody.jti`. The 22-byte base64url wire
form is internal to `haap_wire::ParsedToken` and isn't surfaced to
SDK callers.

## What this PR does NOT do

- Does NOT modify `~/Projects/hx_labs/`.
- Does NOT touch the `cargo package -p haap-rsv` publication blocker
  (PR B will handle path-dep version metadata).
- Does NOT add Cedar policy evaluation.
- Does NOT alter the IPC protocol between the 4 customer-side
  binaries.
- Does NOT release a new SDK version (v0.1.0-alpha.2 is a separate
  tag-push operation the operator performs after merge).

## Release impact

- **v0.1.0-alpha.1**: ships with stubbed RSV. First HTTP request to
  `/verify` returns 401 with "RSV cascade adapter wire-up lands in a
  focused follow-up PR..." Distribution-mechanics validation only.
- **v0.1.0-alpha.2** (this PR + tag): functional RSV. First release
  where customers can run an end-to-end pipeline.

## Test coverage

| Coverage area | Tests | Status |
|---|---|---|
| `InMemReplayCheck` | 5 unit | pass |
| `RedisReplayCheck` impl | compile-time | pass |
| `PermissiveAuthorizer` | 1 unit | pass |
| `FileSealer` (pre-existing) | 3 unit | pass |
| `cascade_rejections` integration | 3 | pass |
| `full_pipeline` integration (feature-gated) | 1 | `#[ignore]` (wire-up pending) |

`cargo test --workspace` passes 12/12.
`cargo clippy --workspace --all-targets -- -D warnings` clean.

## Open follow-ups

1. **PR B** (separate): haap-rsv crates.io publication readiness —
   version metadata on hx_labs path-deps, optional `cargo publish`.
2. **RegistrationScopeAuthorizer**: substrate schema + Authorizer
   trait pattern as prerequisites.
3. **Cedar Authorizer**: production scope-policy enforcement
   replacing PermissiveAuthorizer.
4. **Cascade-context configurability**: RsvConfig knobs for
   `operation`, `resource`, `token_ttl_secs` overrides if MCP server
   operators need them per-request.
5. **Full-pipeline integration test wire-up**: depends on hx_labs
   Supervisor pipeline orchestration verification.
6. **`/verify` HTTP API request-body parameter**: extend
   `haap-rsv-bin` to accept optional encrypted-request bytes; today
   the endpoint passes `None` for `encrypted_request`.

## hx_labs version pinning

hx_labs HEAD at adapter implementation: `17da98a` (Merge PR #62,
2026-05-27 mode-c-provision-session-material-dispatch).

Future hx_labs changes to `verify_and_decrypt_request` signature,
`CascadeRejectReason` variants, `SessionRecord` field list, or
`RawSessionRecord` schema may require adapter updates.
`docs/rsv_adapter_helper_signatures.md` captures the API surface as
of this commit for diff-checking.
