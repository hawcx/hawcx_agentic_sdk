//! KmsWrappedSealer: stub. AWS/GCP KMS integration is post-alpha.

use async_trait::async_trait;
use haap_sdk_types::{SealedBundle, SealerError};
use zeroize::Zeroizing;

use crate::sealer::AgentIdentitySealer;

pub struct KmsWrappedSealer {
    pub key_id: String,
    pub region: String,
}

impl KmsWrappedSealer {
    pub fn new(key_id: String, region: String) -> Self {
        Self { key_id, region }
    }
}

#[async_trait]
impl AgentIdentitySealer for KmsWrappedSealer {
    fn backend_tag(&self) -> &'static str {
        "kms-wrapped-v1"
    }

    async fn seal(&self, _plaintext: &[u8]) -> Result<SealedBundle, SealerError> {
        Err(SealerError::NotImplemented("kms-wrapped seal"))
    }

    async fn unseal(&self, _bundle: &SealedBundle) -> Result<Zeroizing<Vec<u8>>, SealerError> {
        Err(SealerError::NotImplemented("kms-wrapped unseal"))
    }
}
