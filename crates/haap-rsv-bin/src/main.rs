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
//! Transport / authentication (C-1 hardening 2026-05-20):
//!
//! - **Default transport is a Unix Domain Socket** at
//!   `$XDG_RUNTIME_DIR/hawcx/rsv.sock` (or `$TMPDIR/hawcx/rsv.sock` on
//!   macOS-style hosts without XDG_RUNTIME_DIR). Peer credentials are
//!   validated via `SO_PEERCRED` (Linux) / `LOCAL_PEEREUID` (macOS) on
//!   every accept; mismatched UIDs are dropped without a response.
//! - TCP transport requires explicit opt-in: pass `--transport tcp` or
//!   set `HAAP_RSV_TRANSPORT=tcp`. TCP listeners refuse to start unless
//!   `HAAP_RSV_AUTH_TOKEN` is set and at least 32 bytes — every request
//!   on every endpoint (except `GET /healthz`) is gated by a constant-
//!   time bearer-token check.
//! - The previous "loopback is fine" reasoning has been removed from
//!   `docs/RSV_HTTP_API.md`. Loopback is still acceptable as a transport
//!   layer when paired with the bearer-token middleware, but it is no
//!   longer the default and no longer carries authentication by itself.
//!
//! See `crates/haap-rsv-bin/src/lib.rs` for the request/response schema
//! definitions and pure helpers that this binary wires up.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, ValueEnum};
use haap_rsv::Rsv;
use haap_rsv_bin::{
    decode_encrypt_request, decode_request, extract_bearer_token, should_warn_non_loopback,
    tokens_match_ct, BearerExtractError, EncryptDecodeError, EncryptReq, EncryptResp, ErrorResp,
    VerifyReq, VerifyResp, MIN_AUTH_TOKEN_LEN,
};
use haap_sdk_types::{RsvConfig, VerifiedRequest};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroizing;

// ── Configuration types ─────────────────────────────────────────────

/// Wire transport selector. UDS is the default; TCP is opt-in and gated
/// on the bearer-token middleware.
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum Transport {
    /// Unix Domain Socket (default). Peer UID enforced via SO_PEERCRED.
    Unix,
    /// TCP. Requires `HAAP_RSV_AUTH_TOKEN` (>= 32 bytes).
    Tcp,
}

#[derive(Parser, Debug)]
#[command(name = "haap-rsv", about = "Hawcx HAAP RSV sidecar")]
struct Cli {
    /// Wire transport. Overrides `HAAP_RSV_TRANSPORT`.
    #[arg(long, value_enum)]
    transport: Option<Transport>,
}

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
    /// Expected bearer token bytes, or `None` when the listener is UDS
    /// (in which case the middleware short-circuits to "allowed" after
    /// the per-connection peer-cred check has already gated the
    /// accept).
    auth_token: Option<Arc<Vec<u8>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = RsvConfig::from_env()?;
    // Authorizer selection per env: HAWCX_RSV_AUTHORIZER=permissive|strict.
    // Default flipped to `strict` 2026-05-20 (C-2). See
    // crates/haap-rsv/src/rsv.rs:new_from_env.
    let rsv = Rsv::new_from_env(config).await?;

    let transport = resolve_transport(cli.transport);

    let auth_token: Option<Arc<Vec<u8>>> = match transport {
        Transport::Tcp => Some(Arc::new(load_required_auth_token()?)),
        // UDS path: peer-cred check is the authentication primitive;
        // bearer middleware is short-circuited.
        Transport::Unix => None,
    };

    let state = AppState {
        rsv: Arc::new(Mutex::new(rsv)),
        handles: Arc::new(Mutex::new(Default::default())),
        auth_token,
    };

    let app = Router::new()
        .route("/verify", post(verify_handler))
        .route("/encrypt-response", post(encrypt_response_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ))
        // Healthz is intentionally outside the auth layer — it is a
        // liveness probe and exposes no secrets. Pinning it ahead of
        // the route_layer keeps it ungated.
        .route("/healthz", get(healthz))
        .with_state(state);

    match transport {
        Transport::Tcp => serve_tcp(app).await,
        Transport::Unix => serve_unix(app).await,
    }
}

// ── Transport resolution ────────────────────────────────────────────

fn resolve_transport(cli: Option<Transport>) -> Transport {
    if let Some(t) = cli {
        return t;
    }
    match std::env::var("HAAP_RSV_TRANSPORT").ok().as_deref() {
        Some("tcp") => Transport::Tcp,
        Some("unix") | None => Transport::Unix,
        Some(other) => {
            tracing::warn!(
                value = other,
                "HAAP_RSV_TRANSPORT={other:?} unrecognized; defaulting to 'unix'"
            );
            Transport::Unix
        }
    }
}

/// Read the operator-configured bearer token, refusing to start if it
/// is unset or shorter than [`MIN_AUTH_TOKEN_LEN`] bytes.
///
/// Length is measured on the UTF-8 bytes (not graphemes); operators
/// typically generate this via `openssl rand -base64 32` which is well
/// over the floor. We intentionally do not trim whitespace — a token
/// with leading/trailing whitespace was almost certainly mis-copied.
fn load_required_auth_token() -> Result<Vec<u8>> {
    let raw = std::env::var("HAAP_RSV_AUTH_TOKEN").map_err(|_| {
        anyhow!(
            "HAAP_RSV_AUTH_TOKEN is required for TCP transport (must be >= {MIN_AUTH_TOKEN_LEN} bytes); \
             refusing to start an unauthenticated TCP listener"
        )
    })?;
    if raw.len() < MIN_AUTH_TOKEN_LEN {
        return Err(anyhow!(
            "HAAP_RSV_AUTH_TOKEN is too short ({} bytes, need >= {MIN_AUTH_TOKEN_LEN}); \
             refusing to start with a guessable token",
            raw.len()
        ));
    }
    Ok(raw.into_bytes())
}

// ── TCP path ────────────────────────────────────────────────────────

async fn serve_tcp(app: Router) -> Result<()> {
    let listen = std::env::var("HAAP_RSV_LISTEN").unwrap_or_else(|_| "127.0.0.1:8443".into());
    let addr: SocketAddr = listen.parse()?;
    warn_if_non_loopback(&addr);

    tracing::info!(%addr, transport = "tcp", "haap-rsv HTTP API listening (bearer auth required)");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn warn_if_non_loopback(addr: &SocketAddr) {
    if should_warn_non_loopback(addr) {
        tracing::warn!(
            ip = %addr.ip(),
            "haap-rsv listening on non-loopback address. Bearer auth is required; \
             ensure the listener is also behind a TLS-terminating reverse proxy. \
             See docs/RSV_HTTP_API.md."
        );
    }
}

// ── UDS path ────────────────────────────────────────────────────────

async fn serve_unix(app: Router) -> Result<()> {
    let socket_path = resolve_uds_path()?;
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("create UDS parent dir {}", parent.display())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort 0700 on the parent. If the dir already exists
            // with looser modes (e.g., systemd's $XDG_RUNTIME_DIR is
            // already 0700, but a custom dir may not be) we tighten it.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    // Idempotent: remove a stale socket file from a prior run.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("bind UDS {}", socket_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", socket_path.display()))?;
    }

    let expected_peer_uid = load_expected_peer_uid();
    tracing::info!(
        socket = %socket_path.display(),
        transport = "unix",
        expected_peer_uid,
        "haap-rsv HTTP API listening (SO_PEERCRED enforced)"
    );

    loop {
        let (stream, _addr) = listener.accept().await?;
        let peer_uid = match peer_uid_from_stream(&stream) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(error = %e, "SO_PEERCRED lookup failed; dropping connection");
                continue;
            }
        };
        if peer_uid != expected_peer_uid {
            tracing::warn!(
                peer_uid,
                expected_peer_uid,
                "dropping UDS connection: peer UID mismatch"
            );
            // Closing the stream by dropping is intentional — no body, no
            // header, no oracle for an attacker probing for "is the
            // socket bound but rejecting me, or not bound at all?".
            continue;
        }

        let app = app.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req| {
                let app = app.clone();
                async move {
                    let response = tower::ServiceExt::oneshot(app, req).await;
                    Ok::<_, std::convert::Infallible>(response.unwrap_or_else(|_unreachable| {
                        // axum::Router's Service impl is Infallible; the
                        // `unwrap_or_else` arm is unreachable but kept
                        // to satisfy the type checker without an
                        // .unwrap() that could be misread as fallible.
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(axum::body::Body::empty())
                            .expect("static response builder")
                    }))
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "UDS connection terminated");
            }
        });
    }
}

fn resolve_uds_path() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("HAAP_RSV_UDS_PATH") {
        return Ok(PathBuf::from(explicit));
    }
    let base = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .or_else(|| std::env::var("TMPDIR").ok())
        .unwrap_or_else(|| "/tmp".to_string());
    Ok(PathBuf::from(base).join("hawcx").join("rsv.sock"))
}

/// Returns the UID we expect every UDS peer to present. Operators can
/// pin this explicitly via `HAAP_RSV_EXPECTED_PEER_UID`; the default is
/// the process's own UID, which is the right answer for the typical
/// "MCP server + haap-rsv in the same container, same user" deployment.
fn load_expected_peer_uid() -> u32 {
    if let Ok(s) = std::env::var("HAAP_RSV_EXPECTED_PEER_UID") {
        if let Ok(uid) = s.parse::<u32>() {
            return uid;
        }
        tracing::warn!(
            value = %s,
            "HAAP_RSV_EXPECTED_PEER_UID could not be parsed as u32; falling back to getuid()"
        );
    }
    // SAFETY: getuid is always safe; returns a libc::uid_t.
    unsafe { libc::getuid() }
}

fn peer_uid_from_stream(stream: &tokio::net::UnixStream) -> Result<u32> {
    // tokio::net::UnixStream::peer_cred returns a `UCred` on Unix.
    // peer_cred() consults SO_PEERCRED on Linux and LOCAL_PEEREUID on
    // macOS internally; we don't roll our own getsockopt here.
    let cred = stream
        .peer_cred()
        .with_context(|| "tokio UnixStream::peer_cred")?;
    // `uid()` returns the kernel-recorded UID at connect time, which is
    // exactly what we want (no TOCTOU window vs. the peer process
    // setuid'ing after connect).
    let _ = stream.as_raw_fd(); // keep the import warning-clean
    Ok(cred.uid())
}

// ── Middleware ──────────────────────────────────────────────────────

/// Bearer-token middleware. Runs on every authenticated route.
///
/// - For UDS transport, `state.auth_token` is `None`; the per-accept
///   SO_PEERCRED check has already authenticated the caller and the
///   middleware short-circuits to "allowed".
/// - For TCP transport, `state.auth_token` is `Some(...)`; the request
///   MUST carry `Authorization: Bearer <token>` and the presented
///   token bytes MUST equal `state.auth_token` byte-for-byte under a
///   constant-time compare (see `tokens_match_ct`).
///
/// On rejection the response body is a stable `"unauthorized"` string —
/// no scheme/missing-header/mismatch differentiation is exposed.
async fn bearer_auth_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let expected = match state.auth_token.as_ref() {
        Some(tok) => tok,
        // UDS transport: peer-cred check at accept time is the
        // authenticator; the middleware is a pass-through.
        None => return next.run(req).await,
    };

    let header_value = req
        .headers()
        .get(header::AUTHORIZATION)
        .map(|v| v.as_bytes());
    let presented = match extract_bearer_token(header_value) {
        Ok(bytes) => bytes,
        Err(_e) => {
            return unauthorized_response();
        }
    };

    if !tokens_match_ct(presented, expected.as_slice()) {
        return unauthorized_response();
    }

    next.run(req).await
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResp {
            error: BearerExtractError::MissingHeader.client_message().to_string(),
        }),
    )
        .into_response()
}

// ── Handlers ────────────────────────────────────────────────────────

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

// Re-export the unused Path import as a doc-tested constant; suppresses
// the unused-import warning while keeping the type visible for ops docs.
#[allow(dead_code)]
const _PATH_TYPE: Option<&Path> = None;

async fn healthz() -> &'static str {
    "ok"
}
