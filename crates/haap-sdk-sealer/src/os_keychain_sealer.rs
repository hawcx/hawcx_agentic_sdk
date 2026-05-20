//! OsKeychainSealer: 32-byte AES-256-GCM key stored in the OS keychain
//! via keyring-rs v3; ciphertext is portable.
//!
//! Wire layout inside `SealedBundle::ciphertext`:
//! ```text
//! [0:12]   nonce (random per seal)
//! [12:..]  AES-256-GCM ciphertext (includes 16-byte tag)
//! ```
//! AAD: `b"haap-authenticator-os-keychain-v1"`.
//!
//! Cross-platform: macOS Keychain Services, Windows Credential Manager,
//! Linux Secret Service. Linux requires `libsecret-1-dev`.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
use haap_sdk_types::{SealedBundle, SealerError};
use zeroize::Zeroizing;

use crate::sealer::AgentIdentitySealer;

const AAD: &[u8] = b"haap-authenticator-os-keychain-v1";
const BACKEND_TAG: &str = "os-keychain-v1";

pub struct OsKeychainSealer {
    service: String,
    account: String,
}

impl OsKeychainSealer {
    pub fn new(service: String, account: String) -> Self {
        Self { service, account }
    }

    fn entry(&self) -> Result<keyring::Entry, SealerError> {
        keyring::Entry::new(&self.service, &self.account)
            .map_err(|e| SealerError::Keyring(e.to_string()))
    }

    fn load_or_create_key(&self) -> Result<[u8; 32], SealerError> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(hex_string) => decode_key(&hex_string),
            Err(keyring::Error::NoEntry) => {
                let mut key = [0u8; 32];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut key);
                entry
                    .set_password(&hex::encode(key))
                    .map_err(|e| SealerError::Keyring(e.to_string()))?;
                Ok(key)
            }
            Err(e) => Err(SealerError::Keyring(e.to_string())),
        }
    }

    fn load_key(&self) -> Result<[u8; 32], SealerError> {
        let entry = self.entry()?;
        let hex_string = entry
            .get_password()
            .map_err(|e| SealerError::Keyring(e.to_string()))?;
        decode_key(&hex_string)
    }
}

fn decode_key(s: &str) -> Result<[u8; 32], SealerError> {
    let bytes = hex::decode(s.trim()).map_err(|e| SealerError::Keyring(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(SealerError::InvalidFormat(
            "keychain-stored key not 32 bytes",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[async_trait]
impl AgentIdentitySealer for OsKeychainSealer {
    fn backend_tag(&self) -> &'static str {
        BACKEND_TAG
    }

    async fn seal(&self, plaintext: &[u8]) -> Result<SealedBundle, SealerError> {
        let key = self.load_or_create_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: AAD,
                },
            )
            .map_err(|e| SealerError::AeadEncrypt(e.to_string()))?;

        let mut wire = Vec::with_capacity(12 + ct.len());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ct);

        Ok(SealedBundle {
            backend_tag: BACKEND_TAG.to_string(),
            ciphertext: wire,
        })
    }

    async fn unseal(&self, bundle: &SealedBundle) -> Result<Zeroizing<Vec<u8>>, SealerError> {
        if bundle.backend_tag != BACKEND_TAG {
            return Err(SealerError::BackendTagMismatch(
                bundle.backend_tag.clone(),
                BACKEND_TAG.to_string(),
            ));
        }
        if bundle.ciphertext.len() < 12 + 16 {
            return Err(SealerError::InvalidFormat("ciphertext shorter than nonce+tag"));
        }

        let key = self.load_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce_bytes = &bundle.ciphertext[..12];
        let ct = &bundle.ciphertext[12..];
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: AAD,
                },
            )
            .map_err(|e| SealerError::AeadDecrypt(e.to_string()))?;

        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(all(test, feature = "os-keychain-tests"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn os_keychain_round_trip() {
        let sealer = OsKeychainSealer::new(
            "haap-agentic-sdk-test".to_string(),
            format!("test-{}", std::process::id()),
        );
        let plaintext = b"sample".to_vec();
        let bundle = sealer.seal(&plaintext).await.unwrap();
        let recovered = sealer.unseal(&bundle).await.unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }
}
