//! `AgentIdentitySealer` trait + factory.

use async_trait::async_trait;
use haap_sdk_types::{SealedBundle, SealerConfig, SealerError};
use zeroize::Zeroizing;

use crate::{FileSealer, KmsWrappedSealer, OsKeychainSealer};

#[async_trait]
pub trait AgentIdentitySealer: Send + Sync {
    /// Tag identifying the sealer backend; embedded in `SealedBundle::backend_tag`.
    fn backend_tag(&self) -> &'static str;

    async fn seal(&self, plaintext: &[u8]) -> Result<SealedBundle, SealerError>;

    /// Unseal `bundle` and return the recovered plaintext wrapped in
    /// [`Zeroizing`] so the buffer is wiped on drop.
    ///
    /// The previous `Vec<u8>` return left identity-bundle bytes
    /// lingering in the heap until the allocator chose to reuse the
    /// page — a long-lived agent that unsealed once at boot could be
    /// core-dumped or `/proc/<pid>/mem`-scraped minutes later and the
    /// bytes were still recoverable (L-4 hardening 2026-05-20). Callers
    /// that genuinely need a plain `Vec<u8>` can pull it out with
    /// `Zeroizing::into_inner`, but should think hard before doing so.
    async fn unseal(&self, bundle: &SealedBundle) -> Result<Zeroizing<Vec<u8>>, SealerError>;
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
