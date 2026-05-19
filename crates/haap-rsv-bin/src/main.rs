//! `haap-rsv` HTTP API binary — sidecar for cross-language MCP servers.
//!
//! Endpoints:
//!
//! - `POST /verify` accepts `{ "token_b64": "..." }` plus optional
//!   `encrypted_request_b64` + `request_aad_b64` fields. Returns 200
//!   `{ "plaintext_b64": "...", "session_id": <u64>, "jti_hex": "...", "verification_handle": "uuid" }`
//!   or a 4xx/5xx error JSON.
//! - `POST /encrypt-response` accepts `{ "verification_handle": "uuid", "plaintext_b64": "..." }`
//!   and returns 200 `{ "ciphertext_b64": "..." }` or 404 if the handle expired (30s TTL).
//! - `GET /healthz` returns 200 `"ok"`.
//!
//! See `crates/haap-rsv-bin/src/lib.rs` for the request/response schema
//! definitions and pure helpers that this binary wires up.

use anyhow::Result;
use axum::{routing::{get, post}, Json, Router};
use haap_rsv::Rsv;
use haap_rsv_bin::{
    decode_encrypt_request, decode_request, should_warn_non_loopback, EncryptDecodeError,
    EncryptReq, EncryptResp, ErrorResp, VerifyReq, VerifyResp,
};
use haap_sdk_types::{RsvConfig, VerifiedRequest};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Cached post-verify state needed to fulfil a subsequent `/encrypt-response`
/// call. The response_key is held inside `Zeroizing` so it is wiped on drop.
///
/// `jti` is kept for diagnostics symmetry with `/verify`'s response shape but
/// is not load-bearing for the encryption path — `haap_core::response::encrypt_response`
/// reads only `response_key` and `session_id` (see crates/haap-rsv/src/rsv.rs:235).
struct CachedHandle {
    response_key: Zeroizing<[u8; 32]>,
    session_id: u64,
    jti: [u8; 16],
    expires_at_unix: u64,
}

type HandleCache = Arc<Mutex<std::collections::HashMap<Uuid, CachedHandle>>>;

#[derive(Clone)]
struct AppState {
    rsv: Arc<Mutex<Rsv>>,
    handles: HandleCache,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = RsvConfig::from_env()?;
    let rsv = Rsv::new(config).await?;

    let state = AppState {
        rsv: Arc::new(Mutex::new(rsv)),
        handles: Arc::new(Mutex::new(Default::default())),
    };

    let app = Router::new()
        .route("/verify", post(verify_handler))
        .route("/encrypt-response", post(encrypt_response_handler))
        .route("/healthz", get(healthz))
        .with_state(state);

    let listen = std::env::var("HAAP_RSV_LISTEN").unwrap_or_else(|_| "127.0.0.1:8443".into());
    let addr: SocketAddr = listen.parse()?;

    warn_if_non_loopback(&addr);

    tracing::info!(%addr, "haap-rsv HTTP API listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn warn_if_non_loopback(addr: &SocketAddr) {
    if should_warn_non_loopback(addr) {
        tracing::warn!(
            ip = %addr.ip(),
            "haap-rsv listening on non-loopback address without TLS. \
             This is appropriate for sidecar deployments behind a TLS-terminating \
             reverse proxy. Direct network exposure of this endpoint without TLS \
             is not supported. See docs/RSV_HTTP_API.md for the threat model."
        );
    }
}

async fn verify_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (axum::http::StatusCode, Json<ErrorResp>)> {
    use base64::Engine;

    let decoded = decode_request(&req).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: e.message(),
            }),
        )
    })?;

    let mut rsv = state.rsv.lock().await;
    let verified = match decoded.body.as_ref() {
        Some((body, aad)) => rsv
            .verify_and_decrypt_with_body(&decoded.token, Some(body), aad)
            .await
            .map_err(|e| {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(ErrorResp {
                        error: e.to_string(),
                    }),
                )
            })?,
        None => rsv.verify_and_decrypt(&decoded.token).await.map_err(|e| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(ErrorResp {
                    error: e.to_string(),
                }),
            )
        })?,
    };

    let handle = Uuid::new_v4();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut handles = state.handles.lock().await;
    handles.insert(
        handle,
        CachedHandle {
            response_key: Zeroizing::new(*verified.response_key),
            session_id: verified.session_id,
            jti: verified.jti,
            expires_at_unix: now + 30,
        },
    );
    handles.retain(|_, h| h.expires_at_unix >= now);

    Ok(Json(VerifyResp {
        plaintext_b64: base64::engine::general_purpose::STANDARD.encode(&verified.plaintext_body),
        session_id: verified.session_id,
        jti_hex: verified.jti.iter().map(|b| format!("{b:02x}")).collect(),
        verification_handle: handle.to_string(),
    }))
}

async fn encrypt_response_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<EncryptReq>,
) -> Result<Json<EncryptResp>, (axum::http::StatusCode, Json<ErrorResp>)> {
    use base64::Engine;

    let decoded = decode_encrypt_request(&req).map_err(|e| {
        let status = match e {
            // Both decode failures are client-side input errors.
            EncryptDecodeError::Handle(_) | EncryptDecodeError::Plaintext(_) => {
                axum::http::StatusCode::BAD_REQUEST
            }
        };
        (
            status,
            Json(ErrorResp {
                error: e.message(),
            }),
        )
    })?;

    // Look up cached post-verify state. Drop the lock before the (sync)
    // encrypt_response call so a long encryption does not stall concurrent
    // /verify handlers on the same Mutex.
    let (response_key, session_id, jti) = {
        let handles = state.handles.lock().await;
        let cached = handles.get(&decoded.handle).ok_or((
            axum::http::StatusCode::NOT_FOUND,
            Json(ErrorResp {
                error: "verification handle not found (expired or never created)".into(),
            }),
        ))?;
        ((*cached.response_key), cached.session_id, cached.jti)
    };

    // Rebuild a minimal VerifiedRequest for the library call.
    // `encrypt_response` only consumes `response_key` + `session_id`
    // (see crates/haap-rsv/src/rsv.rs:235); `plaintext_body` and `jti`
    // are not read on the encrypt path. Wrapping in Zeroizing means the
    // local key copy is wiped when this scope exits.
    let verified = VerifiedRequest {
        session_id,
        jti,
        plaintext_body: Vec::new(),
        response_key: Zeroizing::new(response_key),
    };

    let rsv = state.rsv.lock().await;
    let ciphertext = rsv.encrypt_response(&verified, &decoded.plaintext).map_err(|e| {
        // encrypt_response's only failure mode today is an internal AEAD
        // error (see CascadeRejectReason path in haap-core). Surface as
        // 500 with the message; do not leak key material.
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp {
                error: format!("encrypt_response failed: {e}"),
            }),
        )
    })?;
    drop(rsv);

    Ok(Json(EncryptResp {
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    }))
}

async fn healthz() -> &'static str {
    "ok"
}
