//! Stage-RSV wire-test mint helper.
//!
//! Given a hex-encoded `--audience-hash` (read from the stage RSV's
//! `haap-rsv-secrets` k8s secret) this binary:
//!
//!   1. Generates fresh substrate material (verifier_secret, k_session,
//!      mutual_auth, response_key) and derives `k_session_root` via
//!      `haap_core::derive_k_session_root` — the same primitive the AS
//!      uses at session establishment.
//!   2. Builds a HAAP wire token over those values via
//!      `haap_core::mint_token`, binding `aud_hash` to the stage RSV's
//!      configured value.
//!   3. Encrypts a plaintext body with AES-256-GCM under the same
//!      `response_key` via `haap_core::encrypt_request`.
//!
//! The output is JSON on stdout:
//!
//! ```json
//! {
//!   "session_id": <u64>,
//!   "issued_at": <u64>,
//!   "expires_at": <u64>,
//!   "policy_epoch": <u64>,
//!   "verifier_secret_hex": "...64...",
//!   "k_session_root_hex": "...64...",
//!   "sek_secret_hex": "...64...",
//!   "tqs_public_hex": "...64...",
//!   "sek_public_hex": "...64...",
//!   "response_key_hex": "...64...",
//!   "token_b64": "...",
//!   "encrypted_request_b64": "...",
//!   "request_aad_b64": "...",
//!   "plaintext_b64": "..."
//! }
//! ```
//!
//! The `*_hex` fields are the substrate row the driver script HSETs into
//! Redis at `hawcx:session:<session_id>`. The cascade pulls them back out
//! to decrypt the wire token.

use base64::Engine;
use clap::Parser;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use haap_core::{encrypt_request, mint_token, MintInput};
use haap_crypto::Keypair;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "stage-rsv-mint", about = "Mint a HAAP wire token + AEAD body for stage RSV testing")]
struct Cli {
    /// 64 hex chars — must equal the stage RSV's HAAP_AUDIENCE_HASH.
    #[arg(long)]
    audience_hash: String,
    /// Optional session_id (decimal u64). Default: stable sentinel high-bit
    /// pattern (0xDEAD_BEEF prefix) so the row is easy to spot in Redis.
    #[arg(long)]
    session_id: Option<u64>,
    /// Plaintext body to encrypt. Default: a small JSON-looking blob.
    #[arg(long, default_value = r#"{"tool":"query_invoices","args":{"limit":10}}"#)]
    plaintext: String,
    /// Additional-authenticated-data tag for the AEAD body.
    #[arg(long, default_value = "stage-rsv-wire-test/v1")]
    aad: String,
}

#[derive(Serialize)]
struct Output {
    session_id: u64,
    issued_at: u64,
    expires_at: u64,
    policy_epoch: u64,
    verifier_secret_hex: String,
    k_session_root_hex: String,
    sek_secret_hex: String,
    tqs_public_hex: String,
    sek_public_hex: String,
    response_key_hex: String,
    token_b64: String,
    encrypted_request_b64: String,
    request_aad_b64: String,
    plaintext_b64: String,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_aud_hash(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim()).expect("audience-hash must be 64 hex chars");
    assert_eq!(bytes.len(), 32, "audience-hash must decode to exactly 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn main() {
    let cli = Cli::parse();
    let aud_hash = parse_aud_hash(&cli.audience_hash);
    let mut rng = OsRng;

    let mut verifier_secret = [0u8; 32];
    let mut k_session = [0u8; 32];
    let mut mutual_auth = [0u8; 32];
    let mut response_key = [0u8; 32];
    let mut jti = [0u8; 16];
    rng.fill_bytes(&mut verifier_secret);
    rng.fill_bytes(&mut k_session);
    rng.fill_bytes(&mut mutual_auth);
    rng.fill_bytes(&mut response_key);
    rng.fill_bytes(&mut jti);

    let k_session_root =
        haap_core::derive_k_session_root(&k_session, &mutual_auth, &verifier_secret)
            .expect("k_session_root derivation");

    let now = now_unix();
    let session_id = cli.session_id.unwrap_or_else(|| {
        // Sentinel high-bit pattern: easy to spot in Redis, unlikely to
        // collide with real production-shaped 64-bit ids.
        0xDEAD_BEEF_0000_0000u64 | (now & 0xFFFF_FFFF)
    });
    let issued_at = now;
    let expires_at = now + 300;
    let policy_epoch: u64 = 7;

    // sek_secret is an opaque substrate scalar — cascade Step 6 reads
    // `sek_public`. We mint a fresh scalar for the row.
    let sek_secret = *Keypair::generate(&mut rng).secret();
    let mut sek_secret_bytes = [0u8; 32];
    sek_secret_bytes.copy_from_slice(&sek_secret.to_bytes());

    let input = MintInput {
        session_id,
        verifier_secret: &verifier_secret,
        k_session_root: &k_session_root,
        mutual_auth: &mutual_auth,
        jti: &jti,
        audience: b"stage-rsv-wire-test",
        client_id: b"stage-wire-test-client",
        scope: br#"{"actions":["read"]}"#,
        policy_epoch,
        response_key: &response_key,
        issued_at,
        expires_at,
        aud_hash: &aud_hash,
        tqs_instance_prefix: &[0x10, 0x20, 0x30, 0x40],
        token_iv_counter: 1,
        sek_public: &RISTRETTO_BASEPOINT_POINT,
    };
    let token = mint_token(&input, &mut rng).expect("mint_token");

    let encrypted = encrypt_request(&response_key, session_id, cli.plaintext.as_bytes(), cli.aad.as_bytes())
        .expect("encrypt_request");

    let b64 = base64::engine::general_purpose::STANDARD;
    let tqs_public_bytes = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
    let out = Output {
        session_id,
        issued_at,
        expires_at,
        policy_epoch,
        verifier_secret_hex: hex::encode(verifier_secret),
        k_session_root_hex: hex::encode(k_session_root),
        sek_secret_hex: hex::encode(sek_secret_bytes),
        tqs_public_hex: hex::encode(tqs_public_bytes),
        sek_public_hex: hex::encode(tqs_public_bytes),
        response_key_hex: hex::encode(response_key),
        token_b64: b64.encode(&token),
        encrypted_request_b64: b64.encode(&encrypted),
        request_aad_b64: b64.encode(cli.aad.as_bytes()),
        plaintext_b64: b64.encode(cli.plaintext.as_bytes()),
    };
    println!("{}", serde_json::to_string_pretty(&out).expect("serialize"));
}
