//! End-to-end: launch the Supervisor + 3 child processes, send a
//! request, decrypt the response.
//!
//! Run:
//! ```bash
//! cargo build --workspace
//! cargo run --example full_pipeline
//! ```
//!
//! Note: the network round-trip to the MCP server is wired up in a
//! follow-up phase; this example demonstrates the supervisor lifecycle.

use haap_supervisor::{AgentRuntime, SupervisorConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = SupervisorConfig::new(
        "./target/debug/haap-authenticator".into(),
        "./target/debug/haap-tqs".into(),
        "./target/debug/haap-assembler".into(),
    );

    let mut runtime = AgentRuntime::new(config).await?;

    println!("Supervisor launched; child sockets reachable.");

    let result = runtime
        .send_request(b"hello".to_vec(), "https://mcp.example.com".to_string())
        .await;

    println!("send_request → {:?}", result);

    Ok(())
}
