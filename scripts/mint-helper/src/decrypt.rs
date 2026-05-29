//! Stage-RSV wire-test decrypt helper.
//!
//! Companion to `stage-rsv-mint` — given a `response_key` (hex) and a
//! `session_id` (decimal u64), decrypts a base64-encoded response wire
//! produced by RSV's `/encrypt-response` endpoint via
//! `haap_core::decrypt_response`. Wire format is `header(4) ‖ tag(16) ‖
//! ciphertext`; AAD is the framing header (see
//! `hx_agent_crypto_core/crates/haap-core/src/response.rs`).
//!
//! Reads the ciphertext (base64) from stdin so the wrapper script can
//! pipe it straight from `jq -r .ciphertext_b64 …` without worrying
//! about argv escaping. Prints the decrypted plaintext (UTF-8) on
//! stdout; exit non-zero on any decode/decrypt failure with a short
//! reason on stderr.

use base64::Engine;
use clap::Parser;
use std::io::Read;

#[derive(Parser, Debug)]
#[command(
    name = "stage-rsv-decrypt",
    about = "Decrypt a stage-RSV /encrypt-response wire body using a known response_key"
)]
struct Cli {
    /// 64 hex chars — the per-session `response_key` from the matching
    /// `stage-rsv-mint` run.
    #[arg(long)]
    response_key: String,
    /// Decimal u64 — the matching `session_id`. Bound into HKDF derivation
    /// for K_resp/IV_resp.
    #[arg(long)]
    session_id: u64,
}

fn main() {
    let cli = Cli::parse();

    let key_bytes = hex::decode(cli.response_key.trim())
        .unwrap_or_else(|e| die(&format!("response_key not hex: {e}")));
    if key_bytes.len() != 32 {
        die(&format!(
            "response_key must decode to 32 bytes (got {})",
            key_bytes.len()
        ));
    }
    let mut response_key = [0u8; 32];
    response_key.copy_from_slice(&key_bytes);

    let mut wire_b64 = String::new();
    std::io::stdin()
        .read_to_string(&mut wire_b64)
        .unwrap_or_else(|e| die(&format!("read stdin: {e}")));
    let wire = base64::engine::general_purpose::STANDARD
        .decode(wire_b64.trim())
        .unwrap_or_else(|e| die(&format!("base64 decode stdin: {e}")));

    let plaintext = haap_core::decrypt_response(&response_key, cli.session_id, &wire)
        .unwrap_or_else(|e| die(&format!("decrypt_response: {e:?}")));

    // Write raw bytes so JSON containing 0x00 etc. would still survive,
    // though in practice the mock MCP only ever returns ASCII JSON.
    use std::io::Write;
    std::io::stdout()
        .write_all(&plaintext)
        .unwrap_or_else(|e| die(&format!("write stdout: {e}")));
}

fn die(msg: &str) -> ! {
    eprintln!("stage-rsv-decrypt: {msg}");
    std::process::exit(2);
}
