//! `RsvConfig` and supporting types.

use crate::errors::ConfigError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SealerConfig {
    File {
        path: PathBuf,
        passphrase_env_var: String,
    },
    OsKeychain {
        service: String,
        account: String,
    },
    KmsWrapped {
        key_id: String,
        region: String,
    },
}

/// Configuration consumed by the RSV library and binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsvConfig {
    /// Customer Redis connection URL (e.g., redis://customer-redis:6379).
    pub customer_redis_url: String,
    /// SHA-256 of the audience URL (UTF-8 bytes). Tokens must carry
    /// this aud_hash to be accepted.
    pub audience_hash: [u8; 32],
    /// LRU capacity for the in-process replay-check fast path.
    pub replay_lru_capacity: usize,
}

impl RsvConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let customer_redis_url = std::env::var("HAAP_CUSTOMER_REDIS_URL")
            .map_err(|_| ConfigError::MissingEnv("HAAP_CUSTOMER_REDIS_URL"))?;

        let audience_hash_hex = std::env::var("HAAP_AUDIENCE_HASH")
            .map_err(|_| ConfigError::MissingEnv("HAAP_AUDIENCE_HASH"))?;
        let audience_hash_vec = hex::decode(&audience_hash_hex)
            .map_err(|e| ConfigError::InvalidEnv("HAAP_AUDIENCE_HASH", e.to_string()))?;
        if audience_hash_vec.len() != 32 {
            return Err(ConfigError::InvalidEnv(
                "HAAP_AUDIENCE_HASH",
                format!("expected 32 bytes, got {}", audience_hash_vec.len()),
            ));
        }
        let mut audience_hash = [0u8; 32];
        audience_hash.copy_from_slice(&audience_hash_vec);

        let replay_lru_capacity = std::env::var("HAAP_REPLAY_LRU_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4096);

        Ok(Self {
            customer_redis_url,
            audience_hash,
            replay_lru_capacity,
        })
    }
}

/// Default sealer backend when `HAAP_SEALER_BACKEND` is unset.
///
/// On macOS, Windows, and Linux we default to the OS-native keychain
/// (Keychain Services / Credential Manager / Secret Service). The
/// `file` backend is still supported but must be opted into explicitly
/// — defaulting to a passphrase-on-disk store is a footgun (M-1
/// hardening 2026-05-20): the typical operator who never sets
/// `HAAP_SEALER_BACKEND` should end up with the keychain-backed sealer,
/// not a file the wrong process can grep.
const fn default_sealer_backend() -> &'static str {
    if cfg!(any(target_os = "macos", target_os = "windows", target_os = "linux")) {
        "os-keychain"
    } else {
        // Other Unix flavours (FreeBSD, illumos, …) have no first-party
        // keyring-rs backend yet. Force operators to pick explicitly
        // rather than silently falling back to file mode.
        ""
    }
}

/// Parse SealerConfig from env vars (used by haap-sdk-cli seal/unseal).
pub fn sealer_config_from_env() -> Result<SealerConfig, ConfigError> {
    let backend = std::env::var("HAAP_SEALER_BACKEND")
        .unwrap_or_else(|_| default_sealer_backend().to_string());
    if backend.is_empty() {
        return Err(ConfigError::UnknownSealerBackend(
            "HAAP_SEALER_BACKEND unset and no OS-keychain backend available on this platform; \
             set HAAP_SEALER_BACKEND to one of: os-keychain, file, kms"
                .to_string(),
        ));
    }
    match backend.as_str() {
        "file" => {
            let path = std::env::var("HAAP_SEALER_FILE_PATH")
                .map_err(|_| ConfigError::MissingEnv("HAAP_SEALER_FILE_PATH"))?;
            let passphrase_env_var = std::env::var("HAAP_SEALER_PASSPHRASE_ENV")
                .unwrap_or_else(|_| "HAAP_SEALER_PASSPHRASE".to_string());
            Ok(SealerConfig::File {
                path: PathBuf::from(path),
                passphrase_env_var,
            })
        }
        "os-keychain" => {
            let service = std::env::var("HAAP_SEALER_KEYCHAIN_SERVICE")
                .unwrap_or_else(|_| "haap-agentic-sdk".to_string());
            let account = std::env::var("HAAP_SEALER_KEYCHAIN_ACCOUNT")
                .unwrap_or_else(|_| "default".to_string());
            Ok(SealerConfig::OsKeychain { service, account })
        }
        "kms" => {
            let key_id = std::env::var("HAAP_SEALER_KMS_KEY_ID")
                .map_err(|_| ConfigError::MissingEnv("HAAP_SEALER_KMS_KEY_ID"))?;
            let region = std::env::var("HAAP_SEALER_KMS_REGION")
                .unwrap_or_else(|_| "us-east-1".to_string());
            Ok(SealerConfig::KmsWrapped { key_id, region })
        }
        other => Err(ConfigError::UnknownSealerBackend(other.to_string())),
    }
}
