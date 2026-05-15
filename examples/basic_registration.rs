//! Minimal example: read config from HAAP_* env vars and print it.
//!
//! Run:
//! ```bash
//! HAAP_AS_URL=https://as.example.com \
//! HAAP_ADMIN_CONSOLE_URL=https://admin.example.com \
//! HAAP_PINNED_IK_SP=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
//! HAAP_SEALER_BACKEND=file \
//! HAAP_SEALER_FILE_PATH=/tmp/agent.sealed \
//! HAAP_SEALER_PASSPHRASE=test-passphrase \
//! cargo run --example basic_registration
//! ```

use haap_sdk_types::AuthenticatorConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AuthenticatorConfig::from_env()?;

    println!("Loaded AuthenticatorConfig:");
    println!("  AS URL:            {}", config.as_url);
    println!("  Admin console URL: {}", config.admin_console_url);
    println!("  Pinned IK_sp:      {} (hex)", hex::encode(config.pinned_ik_sp));
    println!("  Sealer:            {:?}", config.sealer);
    println!("  Allow HTTP for dev: {}", config.allow_http_for_dev);

    // Full registration requires construction of ASClient + TqsIpc (the
    // peer TQS socket) + KeyStore + OrgToken from the admin console.
    // See docs/phase_0_helper_signatures.md for the actual signature of
    // haap_auth::v6_3_registration::perform_agent_registration.

    Ok(())
}
