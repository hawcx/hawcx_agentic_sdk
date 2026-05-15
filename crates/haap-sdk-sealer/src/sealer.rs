//! `AgentIdentitySealer` trait + factory.

use async_trait::async_trait;
use haap_sdk_types::{SealedBundle, SealerConfig, SealerError};

use crate::{FileSealer, KmsWrappedSealer, OsKeychainSealer};

#[async_trait]
pub trait AgentIdentitySealer: Send + Sync {
    /// Tag identifying the sealer backend; embedded in `SealedBundle::backend_tag`.
    fn backend_tag(&self) -> &'static str;

    async fn seal(&self, plaintext: &[u8]) -> Result<SealedBundle, SealerError>;
    async fn unseal(&self, bundle: &SealedBundle) -> Result<Vec<u8>, SealerError>;
}

pub fn build_sealer(config: &SealerConfig) -> Result<Box<dyn AgentIdentitySealer>, SealerError> {
    match config {
        SealerConfig::File { path, passphrase_env_var } => Ok(Box::new(FileSealer::new(
            path.clone(),
            passphrase_env_var.clone(),
        ))),
        SealerConfig::OsKeychain { service, account } => Ok(Box::new(OsKeychainSealer::new(
            service.clone(),
            account.clone(),
        ))),
        SealerConfig::KmsWrapped { key_id, region } => Ok(Box::new(KmsWrappedSealer::new(
            key_id.clone(),
            region.clone(),
        ))),
    }
}
