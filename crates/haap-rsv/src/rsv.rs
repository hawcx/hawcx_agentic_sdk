//! `Rsv` — top-level HAAP Verifier facade.

use haap_sdk_types::{RsvConfig, RsvError, VerifiedRequest, VerifyError};
use haap_substrate_reader::CustomerSubstrateReader;

use crate::replay::ReplayStore;

/// Hawcx HAAP Verifier.
///
/// The 16-step cascade lives in `haap_core::cascade::verify_and_decrypt_request`.
/// This struct adds the two orchestration concerns specific to MCP
/// server deployments: customer Redis substrate access for `SessionRecord`
/// lookup, and two-tier replay enforcement.
pub struct Rsv {
    pub substrate: CustomerSubstrateReader,
    pub replay: ReplayStore,
    pub config: RsvConfig,
}

impl Rsv {
    pub async fn new(config: RsvConfig) -> Result<Self, RsvError> {
        let substrate = CustomerSubstrateReader::connect(&config.customer_redis_url).await?;
        let replay = ReplayStore::new(substrate.connection(), config.replay_lru_capacity);
        Ok(Self {
            substrate,
            replay,
            config,
        })
    }

    /// Run the 16-step verification cascade over `token_bytes`, decrypt
    /// the body, and return the verified plaintext.
    ///
    /// Adapter responsibility (per `/tmp/sdk_salvage/hx_labs_signatures_2026-06-01.md`):
    /// 1. Decode wire bytes to `ParsedToken` via `haap_wire::decode_token`.
    /// 2. Look up `SessionRecord` via the substrate reader.
    /// 3. Construct `CascadeContext` from `self.config`.
    /// 4. Pass an `&mut ReplayCheck` impl backed by `self.replay`.
    /// 5. Pass an `Authorizer` impl (permissive for alpha; haap_cedar
    ///    for production).
    /// 6. Call `verify_and_decrypt_request`, package the result.
    ///
    /// The full adapter wire-up sits behind this function: it requires
    /// constructing the `CascadeContext` and impl-ing `ReplayCheck`
    /// + `Authorizer` traits against the hx_labs surface, which is a
    /// careful piece of glue best landed in a focused follow-up PR
    /// once the alpha integration test scaffolding is in place.
    pub async fn verify_and_decrypt(
        &mut self,
        _token_bytes: &[u8],
    ) -> Result<VerifiedRequest, VerifyError> {
        Err(VerifyError::Internal(
            "RSV cascade adapter wire-up lands in a focused follow-up PR — see crates/haap-rsv/src/rsv.rs comment for the 6-step adapter blueprint".to_string(),
        ))
    }

    /// Encrypt a response body for return to the agent.
    ///
    /// Delegates to `haap_core::response::encrypt_response` with the
    /// per-request response_key recovered during `verify_and_decrypt`.
    pub fn encrypt_response(
        &self,
        _verified: &VerifiedRequest,
        _response_body: &[u8],
    ) -> Result<Vec<u8>, VerifyError> {
        Err(VerifyError::Internal(
            "encrypt_response adapter wire-up lands alongside verify_and_decrypt".to_string(),
        ))
    }
}
