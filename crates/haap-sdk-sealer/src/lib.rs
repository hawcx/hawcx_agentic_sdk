//! Identity bundle sealer (AES-256-GCM AEAD).
//!
//! Three implementations:
//! - [`FileSealer`]: Argon2id-derived passphrase key + AES-256-GCM.
//! - [`OsKeychainSealer`]: AES-256-GCM key in OS keychain via keyring-rs v3.
//! - [`KmsWrappedSealer`]: stub returning NotImplemented (post-alpha).
//!
//! AES-256-GCM is chosen to match hx_labs cryptographic conventions —
//! one AEAD stack workspace-wide.

pub mod file_sealer;
pub mod kms_sealer;
pub mod os_keychain_sealer;
pub mod sealer;

pub use file_sealer::FileSealer;
pub use kms_sealer::KmsWrappedSealer;
pub use os_keychain_sealer::OsKeychainSealer;
pub use sealer::{build_sealer, AgentIdentitySealer};
