//! Shared types and pure helpers for `haap-rsv-bin`.
//!
//! Field naming conventions:
//! - `*_b64` suffix indicates base64 (STANDARD alphabet, RFC 4648 §4)
//! - `*_hex` suffix indicates hex encoding (lowercase, no prefix)
//! - Bytes-typed fields use _b64; small fixed-size identifiers use _hex
//!
//! Schema evolution:
//! - New optional fields may be added without breaking existing clients
//! - Existing field names and types are stable contract for alpha-2 and beyond
//! - Removed fields will be marked deprecated for at least one alpha cycle
//!   before removal.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// `/verify` request body.
#[derive(Deserialize, Debug)]
pub struct VerifyReq {
    /// Base64-encoded HAAP token wire bytes.
    pub token_b64: String,

    /// Base64-encoded encrypted request body (optional).
    /// When present, the cascade decrypts the body and returns plaintext
    /// in the response's `plaintext_b64` field. Must be paired with
    /// `request_aad_b64` (both present or both absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_request_b64: Option<String>,

    /// Base64-encoded request AAD (Authenticated Additional Data) for
    /// AES-256-GCM (optional). Must be paired with `encrypted_request_b64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_aad_b64: Option<String>,
}

/// `/verify` response body.
#[derive(Serialize, Debug)]
pub struct VerifyResp {
    /// Base64 of the decrypted request body. Empty when the request
    /// supplied no `encrypted_request_b64`.
    pub plaintext_b64: String,
    pub session_id: u64,
    pub jti_hex: String,
    pub verification_handle: String,
}

/// `/encrypt-response` request body.
///
/// `verification_handle` is the opaque UUID returned by a prior `/verify`
/// call; the sidecar uses it to look up the cached per-request
/// `response_key` and `session_id`. Handles TTL at 30s, matching the
/// cascade's request/response window.
#[derive(Deserialize, Debug)]
pub struct EncryptReq {
    pub verification_handle: String,
    pub plaintext_b64: String,
}

/// `/encrypt-response` response body. `ciphertext_b64` is base64 of the
/// AES-256-GCM ciphertext + tag produced by
/// `haap_core::response::encrypt_response`.
#[derive(Serialize, Debug)]
pub struct EncryptResp {
    pub ciphertext_b64: String,
}

#[derive(Serialize, Debug)]
pub struct ErrorResp {
    pub error: String,
}

/// Error variants produced while decoding an `EncryptReq`.
#[derive(Debug, PartialEq, Eq)]
pub enum EncryptDecodeError {
    /// `verification_handle` failed UUID parse.
    Handle(String),
    /// `plaintext_b64` failed base64 decode.
    Plaintext(String),
}

impl EncryptDecodeError {
    pub fn message(&self) -> String {
        match self {
            EncryptDecodeError::Handle(e) => format!("invalid handle uuid: {e}"),
            EncryptDecodeError::Plaintext(e) => format!("invalid base64 plaintext: {e}"),
        }
    }
}

/// Decoded form of an `EncryptReq` — handle UUID plus raw plaintext bytes.
#[derive(Debug)]
pub struct DecodedEncryptRequest {
    pub handle: uuid::Uuid,
    pub plaintext: Vec<u8>,
}

/// Decode an `EncryptReq` from JSON-friendly base64 + UUID-string fields,
/// returning a structured `EncryptDecodeError` for client-error cases.
pub fn decode_encrypt_request(req: &EncryptReq) -> Result<DecodedEncryptRequest, EncryptDecodeError> {
    use base64::Engine;
    let handle = req
        .verification_handle
        .parse::<uuid::Uuid>()
        .map_err(|e| EncryptDecodeError::Handle(e.to_string()))?;
    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(&req.plaintext_b64)
        .map_err(|e| EncryptDecodeError::Plaintext(e.to_string()))?;
    Ok(DecodedEncryptRequest { handle, plaintext })
}

/// Error variants produced while decoding a `VerifyReq`.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// `token_b64` failed base64 decode.
    Token(String),
    /// `encrypted_request_b64` failed base64 decode.
    EncryptedRequest(String),
    /// `request_aad_b64` failed base64 decode.
    RequestAad(String),
    /// One of `encrypted_request_b64`/`request_aad_b64` was supplied
    /// without the other.
    Asymmetric,
}

impl DecodeError {
    pub fn message(&self) -> String {
        match self {
            DecodeError::Token(e) => format!("invalid base64 token: {e}"),
            DecodeError::EncryptedRequest(e) => {
                format!("invalid base64 encrypted_request_b64: {e}")
            }
            DecodeError::RequestAad(e) => format!("invalid base64 request_aad_b64: {e}"),
            DecodeError::Asymmetric => {
                "encrypted_request_b64 and request_aad_b64 must be provided together or both omitted"
                    .to_string()
            }
        }
    }
}

/// Decoded form of a `/verify` request — token bytes plus an optional
/// (encrypted_body, aad) pair.
#[derive(Debug)]
pub struct DecodedRequest {
    pub token: Vec<u8>,
    pub body: Option<(Vec<u8>, Vec<u8>)>,
}

/// Decode a `VerifyReq` from JSON-friendly base64 to byte slices,
/// returning a structured `DecodeError` for client-error cases.
pub fn decode_request(req: &VerifyReq) -> Result<DecodedRequest, DecodeError> {
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD
        .decode(&req.token_b64)
        .map_err(|e| DecodeError::Token(e.to_string()))?;

    let body = match (&req.encrypted_request_b64, &req.request_aad_b64) {
        (Some(body_b64), Some(aad_b64)) => {
            let body = base64::engine::general_purpose::STANDARD
                .decode(body_b64)
                .map_err(|e| DecodeError::EncryptedRequest(e.to_string()))?;
            let aad = base64::engine::general_purpose::STANDARD
                .decode(aad_b64)
                .map_err(|e| DecodeError::RequestAad(e.to_string()))?;
            Some((body, aad))
        }
        (None, None) => None,
        _ => return Err(DecodeError::Asymmetric),
    };

    Ok(DecodedRequest { token, body })
}

/// Whether a listen address should trigger the non-loopback startup
/// warning. Extracted so the predicate is unit-testable without a
/// tracing subscriber.
pub fn should_warn_non_loopback(addr: &SocketAddr) -> bool {
    !addr.ip().is_loopback()
}
