//! End-to-end pipeline integration test (feature-gated).
//!
//! Spawns the 5-process customer-side pipeline (haap-supervisor +
//! 4 children) plus haap-rsv as MCP-server-side sidecar. Round-trips
//! a test MCP body and asserts byte-identity.
//!
//! Run with:
//! ```bash
//! cargo test --features integration-tests --test full_pipeline -- --ignored
//! ```
//!
//! Required env vars (test is `#[ignore]` if any are missing):
//! - HAAP_INTEGRATION_REDIS_URL (e.g., redis://localhost:6379)
//! - HAAP_INTEGRATION_HX_LABS_BIN_DIR (path to hx_labs/target/release/)
//! - HAAP_INTEGRATION_SDK_BIN_DIR (path to hx_agentic_sdk/target/release/)
//! - HAAP_INTEGRATION_AS_URL (URL of a running AS — or use embedded
//!   test AS once that's wired up)

#![cfg(feature = "integration-tests")]

#[tokio::test]
#[ignore = "requires running AS, Redis, and built binaries — set HAAP_INTEGRATION_* env vars and remove --ignored"]
async fn full_pipeline_round_trip() {
    // Wire-up depends on hx_labs Supervisor pipeline orchestration support.
    // Per docs/STATUS_2026-06-02.md, that's a separate dependency that needs
    // verification before this test can produce meaningful coverage.
    //
    // Skeleton:
    //
    //   1. Spawn haap-supervisor (which spawns 4 children — Authenticator,
    //      TQS-precompute, TQS-JIT, Assembler — in pipeline order).
    //   2. Wait for Assembler to advertise readiness (the Supervisor's
    //      internal IPC handshake).
    //   3. POST a test MCP request to the Supervisor's HTTP endpoint
    //      (or the Assembler's, depending on pipeline egress design).
    //   4. The Assembler emits an encrypted-body + token over HTTPS
    //      to the audience URL we're hosting (the test process).
    //   5. The test process is an axum HTTP server that received the
    //      token + encrypted body, calls Rsv::verify_and_decrypt_with_body,
    //      asserts plaintext_body equals the original test bytes.
    //   6. Encrypt a response, send back; the Assembler decrypts on the
    //      other side; the test asserts the round-trip.
    //
    // Build prerequisites + invocation documented in
    // docs/INTEGRATION_TEST_SETUP.md.

    panic!("integration test wire-up lands alongside hx_labs Supervisor pipeline orchestration verification");
}
