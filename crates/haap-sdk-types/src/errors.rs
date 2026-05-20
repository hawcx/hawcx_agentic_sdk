use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    MissingEnv(&'static str),
    #[error("invalid value for env var {0}: {1}")]
    InvalidEnv(&'static str, String),
    #[error("unknown sealer backend: {0}")]
    UnknownSealerBackend(String),
}

#[derive(Debug, Error)]
pub enum SealerError {
    #[error("sealer backend not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("argon2 key derivation failed: {0}")]
    Argon2(String),
    #[error("AEAD encryption failed: {0}")]
    AeadEncrypt(String),
    #[error("AEAD decryption failed: {0}")]
    AeadDecrypt(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("missing passphrase env var: {0}")]
    MissingPassphrase(String),
    #[error("ciphertext format invalid: {0}")]
    InvalidFormat(&'static str),
    #[error("backend tag mismatch: bundle was sealed with {0}, this sealer is {1}")]
    BackendTagMismatch(String, String),
}

#[derive(Debug, Error)]
pub enum SubstrateReaderError {
    #[error("redis transport: {0}")]
    Redis(String),
    #[error("deserialization error: {0}")]
    Bincode(#[from] bincode::Error),
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("wire framing invalid: {0}")]
    Framing(String),
    #[error("session not found in substrate")]
    SessionNotFound,
    #[error("substrate reader: {0}")]
    Substrate(#[from] SubstrateReaderError),
    #[error("token rejected by cascade: {0}")]
    CascadeRejected(String),
    #[error("replay detected")]
    Replay,
    /// H-1 (2026-05-20): the token's wire-level `aud_hash` (CS §7.1
    /// bytes 48–79) did not match the operator-configured
    /// `RsvConfig::audience_hash`. Distinct from the cascade's Step 3b
    /// `AudHashMismatch` (which compares against `session.audience`
    /// in substrate) because the SDK-level check is the front-line
    /// gate before substrate is even queried — it catches tokens
    /// minted for a different audience without consuming a substrate
    /// round-trip.
    #[error("token aud_hash does not match RsvConfig::audience_hash")]
    AudienceMismatch,
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum RsvError {
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    #[error("substrate: {0}")]
    Substrate(#[from] SubstrateReaderError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
