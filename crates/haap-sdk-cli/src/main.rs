//! `haap-sdk` testing/demo CLI.
//!
//! Subcommands orchestrate hx_labs binaries (run-pipeline, run-rsv) plus
//! debug helpers (substrate-fetch, seal, unseal). No registration
//! subcommand — that's haap-auth-bin's job under Option X.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "haap-sdk",
    version,
    about = "HAAP Agentic SDK — testing/demo CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Spawn the customer-side pipeline by invoking haap-supervisor from hx_labs.
    RunPipeline {
        #[arg(long)]
        supervisor_bin: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:7443")]
        listen: String,
    },
    /// Run haap-rsv binary as MCP server sidecar.
    RunRsv {
        #[arg(long)]
        rsv_bin: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
    },
    /// Inspect customer Redis substrate for a session.
    SubstrateFetch { session_id: u64 },
    /// Seal an identity bundle via configured backend.
    Seal {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Unseal a previously-sealed file.
    Unseal {
        #[arg(long)]
        input: PathBuf,
    },
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
    match cli.command {
        Command::RunPipeline { supervisor_bin, listen } => commands::run_pipeline(supervisor_bin, listen).await,
        Command::RunRsv { rsv_bin, listen } => commands::run_rsv(rsv_bin, listen).await,
        Command::SubstrateFetch { session_id } => commands::substrate_fetch(session_id).await,
        Command::Seal { input, output } => commands::seal(&input, &output).await,
        Command::Unseal { input } => commands::unseal(&input).await,
    }
}

mod commands {
    use super::*;
    use haap_sdk_sealer::build_sealer;
    use haap_sdk_types::{sealer_config_from_env, SealedBundle};
    use haap_substrate_reader::CustomerSubstrateReader;

    pub async fn run_pipeline(supervisor_bin: Option<PathBuf>, listen: String) -> Result<()> {
        let bin = supervisor_bin
            .or_else(|| which("haap-supervisor"))
            .ok_or_else(|| anyhow!("haap-supervisor not found; pass --supervisor-bin or place on $PATH"))?;

        tracing::info!(?bin, %listen, "invoking haap-supervisor");
        let mut child = tokio::process::Command::new(&bin)
            .env("HAAP_SUPERVISOR_LISTEN", &listen)
            .spawn()
            .map_err(|e| anyhow!("spawn haap-supervisor: {e}"))?;
        let status = child.wait().await?;
        if !status.success() {
            return Err(anyhow!("haap-supervisor exited with {status}"));
        }
        Ok(())
    }

    pub async fn run_rsv(rsv_bin: Option<PathBuf>, listen: String) -> Result<()> {
        let bin = rsv_bin
            .or_else(|| which("haap-rsv"))
            .ok_or_else(|| anyhow!("haap-rsv not found; pass --rsv-bin or place on $PATH"))?;

        tracing::info!(?bin, %listen, "invoking haap-rsv");
        let mut child = tokio::process::Command::new(&bin)
            .env("HAAP_RSV_LISTEN", &listen)
            .spawn()
            .map_err(|e| anyhow!("spawn haap-rsv: {e}"))?;
        let status = child.wait().await?;
        if !status.success() {
            return Err(anyhow!("haap-rsv exited with {status}"));
        }
        Ok(())
    }

    pub async fn substrate_fetch(session_id: u64) -> Result<()> {
        let url = std::env::var("HAAP_CUSTOMER_REDIS_URL")
            .map_err(|_| anyhow!("HAAP_CUSTOMER_REDIS_URL not set"))?;
        let mut reader = CustomerSubstrateReader::connect(&url).await?;
        match reader.fetch_session(session_id).await? {
            Some(m) => {
                println!("session_id: {}", m.current_epoch);
                println!("current_epoch: {}", m.current_epoch);
                println!("status: {:?}", m.status);
                println!("audience: {:?}", m.audience);
                println!("scope_ceiling: {:?}", m.scope_ceiling);
                println!("k_session_root: [REDACTED 32 bytes]");
                println!("verifier_secret: [REDACTED 32 bytes]");
                println!("sek_valid_from..until: {}..{}", m.sek_valid_from, m.sek_valid_until);
            }
            None => println!("no session found for {session_id}"),
        }
        Ok(())
    }

    pub async fn seal(input: &PathBuf, output: &PathBuf) -> Result<()> {
        let sealer_config = sealer_config_from_env()?;
        let sealer = build_sealer(&sealer_config)?;
        let plaintext = tokio::fs::read(input).await?;
        let bundle = sealer.seal(&plaintext).await?;
        let bytes = bincode::serialize(&bundle).map_err(|e| anyhow!("serialize bundle: {e}"))?;
        tokio::fs::write(output, bytes).await?;
        println!("sealed {} bytes → {}", plaintext.len(), output.display());
        Ok(())
    }

    pub async fn unseal(input: &PathBuf) -> Result<()> {
        let sealer_config = sealer_config_from_env()?;
        let sealer = build_sealer(&sealer_config)?;
        let bytes = tokio::fs::read(input).await?;
        let bundle: SealedBundle = bincode::deserialize(&bytes).map_err(|e| anyhow!("deserialize: {e}"))?;
        let plaintext = sealer.unseal(&bundle).await?;
        // `plaintext` is Zeroizing<Vec<u8>>; the borrow keeps the
        // wipe-on-drop guarantee intact through the print.
        println!("{}", String::from_utf8_lossy(plaintext.as_slice()));
        Ok(())
    }

    fn which(bin: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(bin))
                .find(|p| p.is_file())
        })
    }
}
