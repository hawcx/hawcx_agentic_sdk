//! FileSealer: passphrase + Argon2id → AES-256-GCM AEAD over arbitrary
//! plaintext.
//!
//! Wire layout inside `SealedBundle::ciphertext`:
//! ```text
//! [0:16]   salt (random per seal)
//! [16:28]  nonce (random per seal)
//! [28:..]  AES-256-GCM ciphertext (includes 16-byte tag)
//! ```
//! AAD: `b"haap-authenticator-file-sealer-v1"`.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use async_trait::async_trait;
use haap_sdk_types::{SealedBundle, SealerError};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::sealer::AgentIdentitySealer;

const AAD: &[u8] = b"haap-authenticator-file-sealer-v1";
const BACKEND_TAG: &str = "file-sealer-v1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub struct FileSealer {
    path: PathBuf,
    passphrase_env_var: String,
}

impl FileSealer {
    pub fn new(path: PathBuf, passphrase_env_var: String) -> Self {
        Self {
            path,
            passphrase_env_var,
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Read the passphrase from configured sources, in priority order:
    ///
    /// 1. `${passphrase_env_var}_FILE` — path to a file whose contents
    ///    are the passphrase. Preferred because the value never lives
    ///    in the process's `environ`, which is world-readable on Linux
    ///    via `/proc/<pid>/environ` for the same UID and is included
    ///    verbatim in `ps -E` output / crash dumps. Trailing newline is
    ///    stripped (a `printf "secret" > /run/secrets/sealer` is
    ///    equivalent to the file containing `secret`).
    /// 2. `${passphrase_env_var}` — direct env var. Emits a warn log on
    ///    every read so operators see the drift in their logs and can
    ///    migrate to the `_FILE` variant.
    ///
    /// Both sources are mutually exclusive in practice; if both are
    /// set the `_FILE` form wins and the env var is ignored.
    fn read_passphrase(&self) -> Result<Zeroizing<String>, SealerError> {
        let file_var = format!("{}_FILE", self.passphrase_env_var);
        if let Ok(path) = std::env::var(&file_var) {
            let bytes = std::fs::read(&path).map_err(|e| {
                SealerError::MissingPassphrase(format!(
                    "{file_var}={path}: read failed: {e}"
                ))
            })?;
            let s = String::from_utf8(bytes).map_err(|_| {
                SealerError::MissingPassphrase(format!(
                    "{file_var}={path}: contents not UTF-8"
                ))
            })?;
            // Strip a single trailing newline (`printf %s\\n` is the
            // canonical way to write a secret to a tmpfs file).
            let trimmed = s.strip_suffix('\n').unwrap_or(&s).to_string();
            if trimmed.is_empty() {
                return Err(SealerError::MissingPassphrase(format!(
                    "{file_var}={path}: empty passphrase file"
                )));
            }
            return Ok(Zeroizing::new(trimmed));
        }

        match std::env::var(&self.passphrase_env_var) {
            Ok(v) => {
                tracing::warn!(
                    env_var = %self.passphrase_env_var,
                    "FileSealer reading passphrase from env var; prefer \
                     {}_FILE (path to a tmpfs/secret-mount file) to keep \
                     the value out of /proc/<pid>/environ and crash dumps",
                    self.passphrase_env_var
                );
                Ok(Zeroizing::new(v))
            }
            Err(_) => Err(SealerError::MissingPassphrase(
                self.passphrase_env_var.clone(),
            )),
        }
    }

    fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealerError> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(64 * 1024, 3, 4, Some(32))
            .map_err(|e| SealerError::Argon2(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(passphrase, salt, out.as_mut())
            .map_err(|e| SealerError::Argon2(e.to_string()))?;
        Ok(out)
    }
}

#[async_trait]
impl AgentIdentitySealer for FileSealer {
    fn backend_tag(&self) -> &'static str {
        BACKEND_TAG
    }

    async fn seal(&self, plaintext: &[u8]) -> Result<SealedBundle, SealerError> {
        let passphrase = self.read_passphrase()?;

        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let key = Self::derive_key(passphrase.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
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

        let mut wire = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
        wire.extend_from_slice(&salt);
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
        if bundle.ciphertext.len() < SALT_LEN + NONCE_LEN + 16 {
            return Err(SealerError::InvalidFormat(
                "ciphertext shorter than salt+nonce+tag prefix",
            ));
        }

        let salt = &bundle.ciphertext[..SALT_LEN];
        let nonce_bytes = &bundle.ciphertext[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ct = &bundle.ciphertext[SALT_LEN + NONCE_LEN..];

        let passphrase = self.read_passphrase()?;
        let key = Self::derive_key(passphrase.as_bytes(), salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn seal_unseal_round_trip() {
        let dir = TempDir::new().unwrap();
        std::env::set_var("HAAP_TEST_PASSPHRASE_F1", "correct horse battery staple");
        let sealer = FileSealer::new(
            dir.path().join("sealed.bin"),
            "HAAP_TEST_PASSPHRASE_F1".into(),
        );
        let plaintext = b"sample identity bundle bytes".to_vec();
        let bundle = sealer.seal(&plaintext).await.unwrap();
        let recovered = sealer.unseal(&bundle).await.unwrap();
        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let dir = TempDir::new().unwrap();
        std::env::set_var("HAAP_TEST_PASSPHRASE_F2", "another phrase");
        let sealer = FileSealer::new(
            dir.path().join("sealed.bin"),
            "HAAP_TEST_PASSPHRASE_F2".into(),
        );
        let mut bundle = sealer.seal(b"plaintext").await.unwrap();
        let last = bundle.ciphertext.len() - 1;
        bundle.ciphertext[last] ^= 0xFF;
        let result = sealer.unseal(&bundle).await;
        assert!(matches!(result, Err(SealerError::AeadDecrypt(_))));
    }

    #[tokio::test]
    async fn passphrase_file_takes_precedence_over_env() {
        let dir = TempDir::new().unwrap();
        let pp_path = dir.path().join("pp");
        std::fs::write(&pp_path, b"file-mode-secret\n").unwrap();
        std::env::set_var("HAAP_TEST_PASSPHRASE_F4", "env-mode-secret");
        std::env::set_var(
            "HAAP_TEST_PASSPHRASE_F4_FILE",
            pp_path.to_str().unwrap(),
        );
        let sealer = FileSealer::new(
            dir.path().join("sealed.bin"),
            "HAAP_TEST_PASSPHRASE_F4".into(),
        );
        let bundle = sealer.seal(b"plaintext").await.unwrap();

        // Now flip the env to a wrong value — the _FILE form should
        // still drive the derivation and unseal should succeed.
        std::env::set_var("HAAP_TEST_PASSPHRASE_F4", "different-env-value");
        let recovered = sealer.unseal(&bundle).await.unwrap();
        assert_eq!(recovered.as_slice(), b"plaintext");

        std::env::remove_var("HAAP_TEST_PASSPHRASE_F4_FILE");
        std::env::remove_var("HAAP_TEST_PASSPHRASE_F4");
    }

    #[tokio::test]
    async fn empty_passphrase_file_is_rejected() {
        let dir = TempDir::new().unwrap();
        let pp_path = dir.path().join("pp");
        std::fs::write(&pp_path, b"").unwrap();
        std::env::set_var(
            "HAAP_TEST_PASSPHRASE_F5_FILE",
            pp_path.to_str().unwrap(),
        );
        let sealer = FileSealer::new(
            dir.path().join("sealed.bin"),
            "HAAP_TEST_PASSPHRASE_F5".into(),
        );
        let err = sealer.seal(b"plaintext").await.unwrap_err();
        assert!(matches!(err, SealerError::MissingPassphrase(_)));
        std::env::remove_var("HAAP_TEST_PASSPHRASE_F5_FILE");
    }

    #[tokio::test]
    async fn wrong_passphrase_is_rejected() {
        let dir = TempDir::new().unwrap();
        std::env::set_var("HAAP_TEST_PASSPHRASE_F3", "right phrase");
        let sealer = FileSealer::new(
            dir.path().join("sealed.bin"),
            "HAAP_TEST_PASSPHRASE_F3".into(),
        );
        let bundle = sealer.seal(b"plaintext").await.unwrap();
        std::env::set_var("HAAP_TEST_PASSPHRASE_F3", "wrong phrase");
        let result = sealer.unseal(&bundle).await;
        assert!(matches!(result, Err(SealerError::AeadDecrypt(_))));
    }
}
