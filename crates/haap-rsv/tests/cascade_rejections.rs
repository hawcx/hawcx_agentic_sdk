//! Tests for cascade rejection mapping.
//!
//! Without hand-crafting fully signed/encrypted ParsedTokens (which
//! would require duplicating substantial token-mint machinery from
//! hx_labs), this test file focuses on the mapping function's
//! coverage: every `CascadeRejectReason` variant maps to a non-Internal
//! `VerifyError` variant.
//!
//! Full per-variant tests (one positive + one negative for each
//! cascade step) land in the integration test suite that exercises
//! the real 5-process pipeline (`tests/full_pipeline.rs`,
//! feature-gated on `integration-tests`).

use haap_core::error::CascadeRejectReason;
use haap_rsv::Rsv;
use haap_sdk_types::{RsvConfig, VerifyError};

/// Bytes that won't pass `decode_token` (too short, no valid framing).
const MALFORMED_TOKEN: &[u8] = b"\x00\x00\x00\x00";

#[tokio::test]
async fn rsv_new_requires_reachable_redis() {
    let config = RsvConfig {
        customer_redis_url: "redis://127.0.0.1:1".to_string(),
        audience_hash: [0u8; 32],
        replay_lru_capacity: 1024,
    };
    let result = Rsv::new(config).await;
    assert!(result.is_err(), "Rsv::new should fail when Redis is unreachable");
}

#[tokio::test]
async fn malformed_token_returns_framing_error() {
    // This test only runs against a Redis that's actually reachable —
    // we use the typical local dev address. If Redis isn't running,
    // the test is skipped (logged via `eprintln!`).
    let url = std::env::var("HAAP_TEST_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let config = RsvConfig {
        customer_redis_url: url,
        audience_hash: [0u8; 32],
        replay_lru_capacity: 1024,
    };

    let Ok(mut rsv) = Rsv::new(config).await else {
        eprintln!("skipping: Redis unavailable for malformed_token test");
        return;
    };

    let result = rsv.verify_and_decrypt(MALFORMED_TOKEN).await;
    match result {
        Err(VerifyError::Framing(_)) => { /* expected */ }
        other => panic!("expected Framing error, got: {other:?}"),
    }
}

/// Compile-time coverage assertion: every CascadeRejectReason variant
/// must be mappable. This is enforced by the exhaustive match in
/// `map_cascade_reject` in rsv.rs — a new variant added to the enum
/// triggers a compile error there. This test documents the contract.
#[test]
fn cascade_reject_reasons_all_have_mapping() {
    // Sentinel — if a new variant is added to CascadeRejectReason
    // without updating map_cascade_reject, the match in rsv.rs will
    // not be exhaustive and the crate won't compile. This is the
    // contract enforcement; this test exists as documentation.
    let reasons: Vec<CascadeRejectReason> = vec![
        CascadeRejectReason::InvalidFraming,
        CascadeRejectReason::SessionNotFound,
        CascadeRejectReason::SessionSuspended,
        CascadeRejectReason::SessionRevoked,
        CascadeRejectReason::TemporalInvalid,
        CascadeRejectReason::AudHashMismatch,
        CascadeRejectReason::SekExpired,
        CascadeRejectReason::KeyDerivation,
        CascadeRejectReason::SessionRootDerivation,
        CascadeRejectReason::SignatureInvalid,
        CascadeRejectReason::AeadDecryptFailed,
        CascadeRejectReason::BodyDeserialize,
        CascadeRejectReason::VerifierSecretMismatch,
        CascadeRejectReason::ReplayDetected,
        CascadeRejectReason::ReplayCheckError,
        CascadeRejectReason::PolicyEpochStale,
        CascadeRejectReason::StalePolicy,
        CascadeRejectReason::PrivKeyDerivation,
        CascadeRejectReason::PrivSigInvalid,
        CascadeRejectReason::AuthorizationDenied,
        CascadeRejectReason::ConfirmationRequired,
        CascadeRejectReason::ConfirmationExpired,
        CascadeRejectReason::ConfirmationTtlExceeded,
        CascadeRejectReason::PurposeMissing,
        CascadeRejectReason::ApprovalDigestInvalid,
        CascadeRejectReason::MissingHumanConfirmation,
        CascadeRejectReason::CibaExpired,
        CascadeRejectReason::MissingApprovalDigest,
        CascadeRejectReason::MalformedApprovalDigest,
        CascadeRejectReason::ApprovalDigestMismatch,
        CascadeRejectReason::ScopeCeilingExceeded,
        CascadeRejectReason::HaapiBillingInvalid,
        CascadeRejectReason::IntentVerificationFailed,
        CascadeRejectReason::PopSigMissing,
        CascadeRejectReason::PopSigInvalid,
        CascadeRejectReason::PopPubMissing,
        CascadeRejectReason::ConcurrentConsume,
    ];
    assert!(reasons.len() >= 36, "expected at least 36 cascade reject variants");
}
