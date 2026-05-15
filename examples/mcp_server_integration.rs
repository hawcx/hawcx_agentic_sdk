//! Full MCP server using the RSV as middleware.

use haap_rsv::{ReplayStore, Rsv};
use haap_substrate_reader::CustomerSubstrateReader;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let url = std::env::var("HAAP_CUSTOMER_REDIS_URL")?;
    let substrate = CustomerSubstrateReader::connect(&url).await?;
    let replay = ReplayStore::new(substrate.connection(), 4096);
    let audience_hash = [0u8; 32];
    let _rsv = Rsv::new(substrate, replay, audience_hash);

    // Sketch of the integration loop:
    //
    //   loop {
    //       let (token_bytes, req_meta) = receive_from_transport().await?;
    //       match rsv.verify_and_decrypt(&token_bytes).await {
    //           Ok(verified) => {
    //               let response = dispatch_mcp_handler(verified.plaintext_body).await?;
    //               let encrypted = rsv.encrypt_response(&verified, &response)?;
    //               send_to_transport(encrypted).await?;
    //           }
    //           Err(e) => {
    //               tracing::warn!(?e, "rejecting request via cascade");
    //               send_to_transport_401().await?;
    //           }
    //       }
    //   }

    println!("MCP server skeleton initialized; transport layer is application-specific.");
    Ok(())
}
