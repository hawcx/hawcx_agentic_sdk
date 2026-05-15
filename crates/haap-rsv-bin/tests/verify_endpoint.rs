//! Integration tests for the `/verify` HTTP endpoint.
//!
//! These tests cover the pure request-decoding path that runs before
//! the cascade is invoked: token base64 decode, optional encrypted-body
//! + AAD decode, and asymmetric-presence rejection.
//!
//! Full cascade tests (token-only success, token + body returning
//! plaintext, expired-token returning 401) require a live substrate
//! Redis and an issued token. They land alongside the integration-test
//! harness in `crates/haap-rsv/tests/full_pipeline.rs`, which is
//! gated behind the `integration-tests` Cargo feature and ignored by
//! default.

use base64::Engine;
use haap_rsv_bin::{decode_request, should_warn_non_loopback, DecodeError, VerifyReq};
use std::net::SocketAddr;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn decode_token_only_succeeds() {
    let token_bytes = b"this is fake token wire bytes";
    let req = VerifyReq {
        token_b64: b64(token_bytes),
        encrypted_request_b64: None,
        request_aad_b64: None,
    };

    let decoded = decode_request(&req).expect("decode should succeed");
    assert_eq!(decoded.token, token_bytes);
    assert!(decoded.body.is_none(), "body should be None when no encrypted_request_b64");
}

#[test]
fn decode_token_and_body_succeeds() {
    let token_bytes = b"token wire bytes";
    let body_bytes = b"encrypted body bytes (ciphertext + GCM tag)";
    let aad_bytes = b"session_id-or-other-aad";

    let req = VerifyReq {
        token_b64: b64(token_bytes),
        encrypted_request_b64: Some(b64(body_bytes)),
        request_aad_b64: Some(b64(aad_bytes)),
    };

    let decoded = decode_request(&req).expect("decode should succeed");
    assert_eq!(decoded.token, token_bytes);
    let (body, aad) = decoded.body.expect("body should be Some when both fields present");
    assert_eq!(body, body_bytes);
    assert_eq!(aad, aad_bytes);
}

#[test]
fn decode_body_without_aad_rejected() {
    let req = VerifyReq {
        token_b64: b64(b"token"),
        encrypted_request_b64: Some(b64(b"body")),
        request_aad_b64: None,
    };

    let err = decode_request(&req).expect_err("asymmetric body should be rejected");
    assert_eq!(err, DecodeError::Asymmetric);
    assert!(err.message().contains("must be provided together"));
}

#[test]
fn decode_aad_without_body_rejected() {
    let req = VerifyReq {
        token_b64: b64(b"token"),
        encrypted_request_b64: None,
        request_aad_b64: Some(b64(b"aad")),
    };

    let err = decode_request(&req).expect_err("asymmetric aad should be rejected");
    assert_eq!(err, DecodeError::Asymmetric);
}

#[test]
fn decode_invalid_token_base64_rejected() {
    let req = VerifyReq {
        token_b64: "not-valid-base64-!!!@@@".to_string(),
        encrypted_request_b64: None,
        request_aad_b64: None,
    };

    let err = decode_request(&req).expect_err("invalid base64 should be rejected");
    assert!(matches!(err, DecodeError::Token(_)));
    assert!(err.message().contains("invalid base64 token"));
}

#[test]
fn decode_invalid_body_base64_rejected() {
    let req = VerifyReq {
        token_b64: b64(b"token"),
        encrypted_request_b64: Some("not-base64-!!!".to_string()),
        request_aad_b64: Some(b64(b"aad")),
    };

    let err = decode_request(&req).expect_err("invalid body base64 should be rejected");
    assert!(matches!(err, DecodeError::EncryptedRequest(_)));
    assert!(err.message().contains("encrypted_request_b64"));
}

#[test]
fn decode_invalid_aad_base64_rejected() {
    let req = VerifyReq {
        token_b64: b64(b"token"),
        encrypted_request_b64: Some(b64(b"body")),
        request_aad_b64: Some("not-base64-!!!".to_string()),
    };

    let err = decode_request(&req).expect_err("invalid aad base64 should be rejected");
    assert!(matches!(err, DecodeError::RequestAad(_)));
    assert!(err.message().contains("request_aad_b64"));
}

#[test]
fn verify_req_json_accepts_optional_fields_missing() {
    let json = r#"{"token_b64": "dGVzdA=="}"#;
    let req: VerifyReq = serde_json::from_str(json).expect("JSON without optional fields parses");
    assert!(req.encrypted_request_b64.is_none());
    assert!(req.request_aad_b64.is_none());
}

#[test]
fn loopback_v4_does_not_warn() {
    let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    assert!(!should_warn_non_loopback(&addr));
}

#[test]
fn loopback_v6_does_not_warn() {
    let addr: SocketAddr = "[::1]:8443".parse().unwrap();
    assert!(!should_warn_non_loopback(&addr));
}

#[test]
fn unspecified_v4_warns() {
    let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();
    assert!(should_warn_non_loopback(&addr));
}

#[test]
fn unspecified_v6_warns() {
    let addr: SocketAddr = "[::]:8443".parse().unwrap();
    assert!(should_warn_non_loopback(&addr));
}

#[test]
fn lan_address_warns() {
    let addr: SocketAddr = "10.0.0.5:8443".parse().unwrap();
    assert!(should_warn_non_loopback(&addr));
}

#[test]
fn verify_req_json_accepts_optional_fields_present() {
    let json = r#"{
        "token_b64": "dG9rZW4=",
        "encrypted_request_b64": "Ym9keQ==",
        "request_aad_b64": "YWFk"
    }"#;
    let req: VerifyReq = serde_json::from_str(json).expect("JSON with optional fields parses");
    assert_eq!(req.token_b64, "dG9rZW4=");
    assert_eq!(req.encrypted_request_b64.as_deref(), Some("Ym9keQ=="));
    assert_eq!(req.request_aad_b64.as_deref(), Some("YWFk"));
}
