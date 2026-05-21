//! In-process RSV embedding for Rust MCP servers.
//!
//! Run:
//! ```bash
//! HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379 \
//! HAAP_AUDIENCE_HASH=<32-byte sha256 of audience URL in hex> \
//! cargo run --example embedded_rsv -p haap-rsv
//! ```

use haap_rsv::{Rsv, RegistrationScopeAuthorizer};
use haap_sdk_types::RsvConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = RsvConfig::from_env()?;
    // Production embedding pins `RegistrationScopeAuthorizer` (CS v6.8.0
    // §9.1.X). The constructor takes the authorizer explicitly post-C-2
    // (2026-05-20) — no silent permissive default.
    let _rsv = Rsv::new(config, Box::new(RegistrationScopeAuthorizer)).await?;

    // In production:
    //   for incoming_request in transport.requests() {
    //       let verified = rsv.verify_and_decrypt(&incoming_request.token_bytes).await?;
    //       let response = mcp_handler(verified.plaintext_body).await?;
    //       let encrypted = rsv.encrypt_response(&verified, &response)?;
    //       transport.respond(encrypted);
    //   }

    println!("RSV embedded successfully; ready for verify_and_decrypt calls.");
    Ok(())
}
