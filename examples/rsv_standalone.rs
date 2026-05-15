//! Standalone RSV listening on HTTP for verification requests.
//!
//! Run:
//! ```bash
//! HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379 \
//! cargo run --example rsv_standalone
//! ```

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

    println!("RSV initialized; HTTP listener wire-up is a follow-up step.");
    Ok(())
}
