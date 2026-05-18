//! Hawcx HAAP Verifier.
//!
//! Wraps `haap_core::cascade::verify_and_decrypt_request` with substrate
//! access + replay enforcement. The 16-step cascade implementation
//! lives in hx_labs; this crate is a thin orchestration layer.
//!
//! Target latency: < 400 μs per spec.

pub mod authorizer;
pub mod replay;
pub mod rsv;

pub use authorizer::{PermissiveAuthorizer, RegistrationScopeAuthorizer};
pub use replay::{InMemReplayCheck, RedisReplayCheck, ReplayError};
pub use rsv::Rsv;
