//! Shared types for the HAAP agentic SDK (Option X distribution model).
//!
//! Intentionally dependency-light: types that flow between sealer,
//! substrate reader, RSV library/binary, and the CLI. The five
//! customer-side process binaries (Authenticator, TQS-precompute,
//! TQS-JIT, Assembler, Supervisor) come from hx_labs directly and
//! do NOT consume this crate.

pub mod config;
pub mod errors;
pub mod material;
pub mod sealed;
pub mod verified;

pub use config::{sealer_config_from_env, RsvConfig, SealerConfig};
pub use errors::{ConfigError, RsvError, SealerError, SubstrateReaderError, VerifyError};
pub use material::SubstrateMaterial;
pub use sealed::SealedBundle;
pub use verified::VerifiedRequest;
