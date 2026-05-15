# Integration Test Setup

The `full_pipeline` test exercises the SDK's RSV against the
5-process hx_labs binary pipeline. Default `cargo test` skips this
test (feature flag `integration-tests` is off by default).

## Prerequisites

1. **hx_labs binaries built**:

   ```bash
   cd ~/Projects/hx_labs
   cargo build --release \
       --bin haap-authenticator --bin haap-tqs-precompute \
       --bin haap-tqs-jit --bin haap-assembler --bin haap-supervisor
   ```

2. **SDK binaries built**:

   ```bash
   cd ~/Projects/hx_agentic_sdk
   cargo build --release --workspace --bins
   ```

3. **Test Redis available** — local instance or docker-compose:

   ```bash
   docker run --rm -d -p 6379:6379 redis:7-alpine
   ```

4. **Running AS** — the test needs an Authentication Service for the
   Authenticator to register against. Either:
   - Run hx_labs's `haap-server` locally with test fixtures
   - Point at a development environment AS
   - Use an embedded test AS (planned, not yet wired)

## Running

```bash
HAAP_INTEGRATION_REDIS_URL=redis://localhost:6379 \
HAAP_INTEGRATION_HX_LABS_BIN_DIR=~/Projects/hx_labs/target/release \
HAAP_INTEGRATION_SDK_BIN_DIR=~/Projects/hx_agentic_sdk/target/release \
HAAP_INTEGRATION_AS_URL=https://agent-auth.dev.hawcx.com \
cargo test --features integration-tests \
    --test full_pipeline -- --ignored
```

## What this validates (once wired)

- The 5-process pipeline launches (Authenticator → TQS-precompute →
  TQS-JIT → Assembler + Supervisor orchestrator)
- The Authenticator successfully completes `/v3/register_agent` against
  the AS
- TQS-precompute pre-mints token commitments; TQS-JIT finalizes them
  at request time
- The Assembler encrypts a request body with K_req
- RSV decodes the token, fetches `RawSessionRecord` from customer
  Redis, decompresses to `SessionRecord`, runs the 16-step cascade,
  decrypts the request body
- RSV encrypts a response with the per-request `response_key`; the
  Assembler decrypts on the other side
- Byte-identity round-trip end-to-end

## What this does NOT validate

- Cedar policy evaluation (alpha uses `PermissiveAuthorizer`)
- Multi-tenant isolation (single-agent test)
- Failure modes beyond the happy path (see `cascade_rejections.rs`
  for per-variant mapping coverage)
- Registration-scope semantics (deferred per Phase 0.4 of the
  cascade adapter PR)

## Why this lives on a feature flag

The test takes minutes to set up (binary builds, Redis container,
AS connectivity verification) and isn't useful for the typical
`cargo test` invocation that runs after every edit. The
`integration-tests` feature is enabled by CI's nightly job and by
explicit local runs when adapter changes are being validated.

## Status

The skeleton lives at `crates/haap-rsv/tests/full_pipeline.rs` and
currently `panic!`s with a reference to this doc. Wire-up depends on
hx_labs Supervisor pipeline orchestration support — see
`docs/STATUS_2026-06-02.md` for the dependency.
