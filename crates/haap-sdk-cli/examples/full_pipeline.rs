//! Customer-runtime end-to-end demo.
//!
//! Run:
//! ```bash
//! # Ensure haap-supervisor (from hx_labs) is on $PATH.
//! # Configure HAAP_* env vars (see docs/DEPLOYMENT.md).
//! cargo run --example full_pipeline -p haap-sdk-cli
//! ```

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let supervisor_bin = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join("haap-supervisor"))
                .find(|p| p.is_file())
        })
        .ok_or_else(|| anyhow::anyhow!("haap-supervisor not found on PATH"))?;

    println!("Launching haap-supervisor from: {}", supervisor_bin.display());

    let mut child = tokio::process::Command::new(&supervisor_bin)
        .spawn()?;

    let status = child.wait().await?;
    println!("haap-supervisor exited with: {status}");
    Ok(())
}
