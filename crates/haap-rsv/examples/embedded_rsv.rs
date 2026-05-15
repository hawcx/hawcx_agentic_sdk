//! In-process RSV embedding for Rust MCP servers.
//!
//! Run:
//! ```bash
//! HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379 \
//! HAAP_AUDIENCE_HASH=<32-byte sha256 of audience URL in hex> \
//! cargo run --example embedded_rsv -p haap-rsv
//! ```

use haap_rsv::Rsv;
use haap_sdk_types::RsvConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = RsvConfig::from_env()?;
    let _rsv = Rsv::new(config).await?;

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
