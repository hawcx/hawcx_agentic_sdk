//! `haap-rsv` HTTP API binary — sidecar for cross-language MCP servers.
//!
//! Endpoints:
//! - `POST /verify` { "token_b64": "..." }
//!     → 200 { "plaintext_b64": "...", "session_id": <u64>, "jti_hex": "...", "verification_handle": "uuid" }
//!     → 401 { "error": "..." }
//! - `POST /encrypt-response` { "verification_handle": "uuid", "plaintext_b64": "..." }
//!     → 200 { "ciphertext_b64": "..." }
//!     → 404 if handle expired (30s TTL)
//! - `GET /healthz`  → 200 "ok"

use anyhow::Result;
use axum::{routing::{get, post}, Json, Router};
use haap_rsv::Rsv;
use haap_sdk_types::RsvConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    rsv: Arc<Mutex<Rsv>>,
    // verification_handle → (response_key bytes, session_id, expires_at_unix)
    handles: Arc<Mutex<std::collections::HashMap<Uuid, ([u8; 32], u64, u64)>>>,
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

    tracing::info!(%addr, "haap-rsv HTTP API listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)]
struct VerifyReq {
    token_b64: String,
}

#[derive(Serialize)]
struct VerifyResp {
    plaintext_b64: String,
    session_id: u64,
    jti_hex: String,
    verification_handle: String,
}

#[derive(Serialize)]
struct ErrorResp {
    error: String,
}

async fn verify_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<VerifyResp>, (axum::http::StatusCode, Json<ErrorResp>)> {
    use base64::Engine;
    let token_bytes = base64::engine::general_purpose::STANDARD
        .decode(&req.token_b64)
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(ErrorResp {
                    error: format!("invalid base64 token: {e}"),
                }),
            )
        })?;

    let mut rsv = state.rsv.lock().await;
    let verified = rsv.verify_and_decrypt(&token_bytes).await.map_err(|e| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(ErrorResp {
                error: e.to_string(),
            }),
        )
    })?;

    let handle = Uuid::new_v4();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut handles = state.handles.lock().await;
    handles.insert(handle, (*verified.response_key, verified.session_id, now + 30));
    // GC any expired handles to bound memory.
    handles.retain(|_, (_, _, exp)| *exp >= now);

    Ok(Json(VerifyResp {
        plaintext_b64: base64::engine::general_purpose::STANDARD.encode(&verified.plaintext_body),
        session_id: verified.session_id,
        jti_hex: verified.jti.iter().map(|b| format!("{b:02x}")).collect(),
        verification_handle: handle.to_string(),
    }))
}

#[derive(Deserialize)]
struct EncryptReq {
    verification_handle: String,
    plaintext_b64: String,
}

#[derive(Serialize)]
struct EncryptResp {
    ciphertext_b64: String,
}

async fn encrypt_response_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(req): Json<EncryptReq>,
) -> Result<Json<EncryptResp>, (axum::http::StatusCode, Json<ErrorResp>)> {
    use base64::Engine;

    let handle: Uuid = req.verification_handle.parse().map_err(|e: uuid::Error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResp {
                error: format!("invalid handle uuid: {e}"),
            }),
        )
    })?;

    let _plaintext = base64::engine::general_purpose::STANDARD
        .decode(&req.plaintext_b64)
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(ErrorResp {
                    error: format!("invalid base64 plaintext: {e}"),
                }),
            )
        })?;

    let handles = state.handles.lock().await;
    let (_response_key, _session_id, _exp) = handles.get(&handle).copied().ok_or((
        axum::http::StatusCode::NOT_FOUND,
        Json(ErrorResp {
            error: "verification handle not found (expired or never created)".into(),
        }),
    ))?;
    drop(handles);

    // Response encryption is wired up alongside the RSV cascade adapter
    // in a focused follow-up PR (see crates/haap-rsv/src/rsv.rs).
    Err((
        axum::http::StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResp {
            error: "encrypt-response wire-up lands with RSV cascade adapter".into(),
        }),
    ))
}

async fn healthz() -> &'static str {
    "ok"
}

