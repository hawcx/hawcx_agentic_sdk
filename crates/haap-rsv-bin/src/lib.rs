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

/// Minimum bearer-token length, in bytes, accepted by the `/verify` and
/// `/encrypt-response` authentication middleware. Anything shorter is
/// refused at process startup (fail-fast — better to never bind than to
/// run with a guessable token).
///
/// 32 bytes ≈ 256 bits — comfortable margin against online guessing once
/// per-connection latency is in the millisecond range, and matches the
/// recommended floor in `docs/RSV_HTTP_API.md`.
pub const MIN_AUTH_TOKEN_LEN: usize = 32;

/// Outcome of [`extract_bearer_token`] — the bearer string sans the
/// `Bearer ` prefix, or an explanatory rejection. Separated from the
/// HTTP-layer middleware so the predicate is testable without standing
/// up an `axum::Router`.
#[derive(Debug, PartialEq, Eq)]
pub enum BearerExtractError {
    /// `Authorization` header absent.
    MissingHeader,
    /// `Authorization` header value not UTF-8.
    NonUtf8Header,
    /// Scheme is not `Bearer` (case-sensitive — RFC 6750 §2.1 leaves
    /// scheme casing implementation-defined; we pin to `Bearer` to
    /// avoid normalization ambiguity).
    WrongScheme,
    /// `Bearer` with empty token after the space.
    EmptyToken,
}

impl BearerExtractError {
    /// Stable client-facing message. Does NOT vary by failure mode —
    /// every 401 surfaces the same `"unauthorized"` string so an
    /// attacker probing the endpoint cannot distinguish "missing
    /// header" from "wrong scheme" from "token mismatch".
    pub fn client_message(&self) -> &'static str {
        "unauthorized"
    }
}

/// Parse a raw `Authorization` header value (`Some(bytes)` if present)
/// and return the bearer token bytes if and only if the header is well
/// formed.
///
/// Whitespace handling: exactly one ASCII space between scheme and
/// token, matching the conservative subset of RFC 7235 §2.1. Trailing
/// whitespace on the token is rejected — a real bearer should never
/// carry it, and treating "tok " as equal to "tok" creates a constant-
/// time-compare foot-gun.
pub fn extract_bearer_token(header_value: Option<&[u8]>) -> Result<&[u8], BearerExtractError> {
    let bytes = header_value.ok_or(BearerExtractError::MissingHeader)?;
    let s = std::str::from_utf8(bytes).map_err(|_| BearerExtractError::NonUtf8Header)?;
    let rest = s
        .strip_prefix("Bearer ")
        .ok_or(BearerExtractError::WrongScheme)?;
    if rest.is_empty() {
        return Err(BearerExtractError::EmptyToken);
    }
    Ok(rest.as_bytes())
}

/// Constant-time equality predicate over the bearer token presented on
/// the wire and the operator-configured expected token. Wraps
/// `subtle::ConstantTimeEq` so unequal-length inputs are still compared
/// in time proportional to `max(len(a), len(b))` — the early-return
/// `if a.len() != b.len()` form leaks length classes.
///
/// The expected token MUST be at least [`MIN_AUTH_TOKEN_LEN`] bytes;
/// the startup code in `main.rs` enforces this before any request is
/// accepted, so the predicate itself does not re-check.
pub fn tokens_match_ct(presented: &[u8], expected: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    presented.ct_eq(expected).unwrap_u8() == 1
}
