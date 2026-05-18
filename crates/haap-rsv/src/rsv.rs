//! `Rsv` — top-level HAAP Verifier facade.
//!
//! Wraps `haap_core::cascade::verify_and_decrypt_request` with
//! substrate-access + replay enforcement orchestration. The 16-step
//! cascade lives in hx_labs; this crate is a thin orchestration layer.

use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use haap_core::cascade::verify_and_decrypt_request;
use haap_core::types::{Authorizer, CascadeContext, SessionRecord};
use haap_core::error::CascadeRejectReason;
use haap_sdk_types::{RsvConfig, RsvError, VerifiedRequest, VerifyError};
use haap_substrate_reader::CustomerSubstrateReader;
use haap_wire::decode_token;
use zeroize::Zeroizing;

use crate::authorizer::PermissiveAuthorizer;
use crate::replay::{InMemReplayCheck, RedisReplayCheck};

/// Trait-object wrapper for the runtime-chosen [`Authorizer`].
///
/// The cascade accepts `&impl Authorizer`, and a blanket
/// `impl<A: Authorizer> Authorizer for &A` lives in haap-core, but
/// `Box<dyn Authorizer + Send + Sync>` doesn't gain an `Authorizer` impl
/// for free (no orphan-rule-compliant way to add one from outside
/// haap-core). This newtype wraps the boxed trait object and forwards
/// the trait method so the cascade can consume it via `&self.authorizer`.
pub(crate) struct DynAuthorizer(pub Box<dyn Authorizer + Send + Sync>);

impl Authorizer for DynAuthorizer {
    fn authorize(
        &self,
        claimed_scope: &[u8],
        operation: &str,
        resource: &str,
        session: &SessionRecord,
    ) -> bool {
        self.0.authorize(claimed_scope, operation, resource, session)
    }
}

/// Hawcx HAAP Verifier.
///
/// Holds two Redis clients:
/// - `CustomerSubstrateReader` (async ConnectionManager) for session lookup
/// - `redis::Client` (sync) for cascade-internal replay enforcement
///
/// The dual-client setup is required because the cascade's
/// `ReplayCheck` trait is synchronous (it runs inside a sync cascade
/// function), while substrate fetch is async around it.
///
/// v6.8.0 (W4 2026-05-18): also holds an operator-chosen
/// [`Authorizer`] (defaults to [`PermissiveAuthorizer`]). Operators
/// that want registration-scope binding construct the verifier with
/// [`Rsv::new_with_authorizer`] and [`RegistrationScopeAuthorizer`]
/// (or any custom impl).
pub struct Rsv {
    substrate: CustomerSubstrateReader,
    redis_client: redis::Client,
    config: RsvConfig,
    authorizer: DynAuthorizer,
}

impl Rsv {
    /// Construct an `Rsv` with [`PermissiveAuthorizer`]. Suitable for
    /// alpha deployments that do not yet enforce registration-scope
    /// binding; the cascade's Step 10 ceiling check remains the floor.
    pub async fn new(config: RsvConfig) -> Result<Self, RsvError> {
        Self::new_with_authorizer(config, Box::new(PermissiveAuthorizer)).await
    }

    /// Construct an `Rsv` with an operator-chosen [`Authorizer`].
    ///
    /// Production deployments that opt in to registration-scope
    /// binding pass `Box::new(RegistrationScopeAuthorizer)` per
    /// CS v6.8.0 §9.1.X (W4). Custom authorizers (Cedar-backed,
    /// composite, etc.) work the same way.
    pub async fn new_with_authorizer(
        config: RsvConfig,
        authorizer: Box<dyn Authorizer + Send + Sync>,
    ) -> Result<Self, RsvError> {
        let substrate = CustomerSubstrateReader::connect(&config.customer_redis_url).await?;
        let redis_client = redis::Client::open(config.customer_redis_url.clone())
            .map_err(|e| RsvError::Io(std::io::Error::other(e.to_string())))?;
        Ok(Self {
            substrate,
            redis_client,
            config,
            authorizer: DynAuthorizer(authorizer),
        })
    }

    /// Verify a wire-format token and (optionally) decrypt an
    /// accompanying encrypted request body.
    ///
    /// For alpha v0.1.0-alpha.2 the SDK exposes the token-only path
    /// (no encrypted request body). The request-body path lands
    /// alongside the haap-rsv HTTP API extension in a follow-up PR.
    pub async fn verify_and_decrypt(
        &mut self,
        token_bytes: &[u8],
    ) -> Result<VerifiedRequest, VerifyError> {
        self.verify_and_decrypt_with_body(token_bytes, None, b"").await
    }

    /// Token + encrypted-request-body variant of `verify_and_decrypt`.
    pub async fn verify_and_decrypt_with_body(
        &mut self,
        token_bytes: &[u8],
        encrypted_request: Option<&[u8]>,
        request_aad: &[u8],
    ) -> Result<VerifiedRequest, VerifyError> {
        // 1. Decode wire bytes → ParsedToken
        let parsed = decode_token(token_bytes)
            .map_err(|e| VerifyError::Framing(format!("{e:?}")))?;

        // 2. Substrate fetch → RawSessionRecord
        let raw = self
            .substrate
            .fetch_session(parsed.session_id)
            .await?
            .ok_or(VerifyError::SessionNotFound)?;

        // 3. RawSessionRecord → SessionRecord (Ristretto decompression)
        let session = SessionRecord::try_from(raw)
            .map_err(map_cascade_reject)?;

        // 4. CascadeContext (alpha: empty operation/resource —
        //    PermissiveAuthorizer ignores both)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let ctx = CascadeContext {
            now,
            token_ttl_secs: 60,
            operation: "",
            resource: "",
            max_confirmation_ttl_secs: 300,
            pop_sig: None,
            tool_arguments: None,
        };

        // 5. ReplayCheck impl — sync Redis-backed
        let conn = self.redis_client.get_connection().map_err(|e| {
            VerifyError::Internal(format!("redis sync connect for replay: {e}"))
        })?;
        let mut replay = RedisReplayCheck::new(conn);

        // 6. Authorizer impl — operator-chosen at construction time.
        //    v6.8.0 (W4) lets operators select RegistrationScopeAuthorizer
        //    or any custom impl via Rsv::new_with_authorizer.
        // 7. Cascade call
        let (token_body, body_plaintext) = verify_and_decrypt_request(
            &parsed,
            Some(&session),
            &ctx,
            &mut replay,
            &self.authorizer,
            encrypted_request,
            request_aad,
        )
        .map_err(map_cascade_reject)?;

        Ok(VerifiedRequest {
            session_id: parsed.session_id,
            jti: token_body.jti,
            plaintext_body: body_plaintext.unwrap_or_default(),
            response_key: Zeroizing::new(token_body.response_key),
        })
    }

    /// In-memory variant of `verify_and_decrypt` for unit tests.
    ///
    /// Replaces the Redis-backed replay check with an in-process
    /// HashSet held in `replay` so unit tests don't need Redis.
    pub async fn verify_and_decrypt_with_in_mem_replay(
        &mut self,
        token_bytes: &[u8],
        replay: &mut InMemReplayCheck,
        encrypted_request: Option<&[u8]>,
        request_aad: &[u8],
    ) -> Result<VerifiedRequest, VerifyError> {
        let parsed = decode_token(token_bytes)
            .map_err(|e| VerifyError::Framing(format!("{e:?}")))?;

        let raw = self
            .substrate
            .fetch_session(parsed.session_id)
            .await?
            .ok_or(VerifyError::SessionNotFound)?;

        let session = SessionRecord::try_from(raw).map_err(map_cascade_reject)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let ctx = CascadeContext {
            now,
            token_ttl_secs: 60,
            operation: "",
            resource: "",
            max_confirmation_ttl_secs: 300,
            pop_sig: None,
            tool_arguments: None,
        };

        let (token_body, body_plaintext) = verify_and_decrypt_request(
            &parsed,
            Some(&session),
            &ctx,
            replay,
            &self.authorizer,
            encrypted_request,
            request_aad,
        )
        .map_err(map_cascade_reject)?;

        Ok(VerifiedRequest {
            session_id: parsed.session_id,
            jti: token_body.jti,
            plaintext_body: body_plaintext.unwrap_or_default(),
            response_key: Zeroizing::new(token_body.response_key),
        })
    }

    /// Encrypt a response body for return to the agent.
    ///
    /// Delegates to `haap_core::response::encrypt_response` with the
    /// per-request `response_key` recovered during `verify_and_decrypt`.
    pub fn encrypt_response(
        &self,
        verified: &VerifiedRequest,
        response_body: &[u8],
    ) -> Result<Vec<u8>, VerifyError> {
        haap_core::response::encrypt_response(
            &verified.response_key,
            verified.session_id,
            response_body,
        )
        .map_err(|e| VerifyError::Internal(format!("response encryption failed: {e:?}")))
    }

    /// Access the inner config (read-only) — useful for diagnostics
    /// and tests.
    pub fn config(&self) -> &RsvConfig {
        &self.config
    }
}

/// Map a `CascadeRejectReason` to a `VerifyError` variant.
///
/// Every cascade rejection variant gets a stable SDK-side mapping so
/// callers can branch on `VerifyError` without depending on the
/// hx_labs error enum directly.
fn map_cascade_reject(reject: CascadeRejectReason) -> VerifyError {
    use CascadeRejectReason::*;
    match reject {
        InvalidFraming => VerifyError::CascadeRejected("InvalidFraming (step 1)".into()),
        SessionNotFound => VerifyError::SessionNotFound,
        SessionSuspended => VerifyError::CascadeRejected("SessionSuspended (step 2)".into()),
        SessionRevoked => VerifyError::CascadeRejected("SessionRevoked (step 2)".into()),
        TemporalInvalid => VerifyError::CascadeRejected("TemporalInvalid (step 3)".into()),
        AudHashMismatch => VerifyError::CascadeRejected("AudHashMismatch (step 3b)".into()),
        SekExpired => VerifyError::CascadeRejected("SekExpired (step 4)".into()),
        KeyDerivation => VerifyError::CascadeRejected("KeyDerivation (step 5)".into()),
        SessionRootDerivation => VerifyError::CascadeRejected("SessionRootDerivation".into()),
        SignatureInvalid => VerifyError::CascadeRejected("SignatureInvalid (step 6)".into()),
        AeadDecryptFailed => VerifyError::CascadeRejected("AeadDecryptFailed (step 7)".into()),
        BodyDeserialize => VerifyError::CascadeRejected("BodyDeserialize (step 7)".into()),
        VerifierSecretMismatch => VerifyError::CascadeRejected("VerifierSecretMismatch (step 8)".into()),
        ReplayDetected => VerifyError::Replay,
        ReplayCheckError => VerifyError::CascadeRejected("ReplayCheckError (step 9)".into()),
        PolicyEpochStale => VerifyError::CascadeRejected("PolicyEpochStale (step 10)".into()),
        StalePolicy => VerifyError::CascadeRejected("StalePolicy (step 10)".into()),
        PrivKeyDerivation => VerifyError::CascadeRejected("PrivKeyDerivation (step 11)".into()),
        PrivSigInvalid => VerifyError::CascadeRejected("PrivSigInvalid (step 11)".into()),
        AuthorizationDenied => VerifyError::CascadeRejected("AuthorizationDenied (step 13)".into()),
        ConfirmationRequired => VerifyError::CascadeRejected("ConfirmationRequired (step 13)".into()),
        ConfirmationExpired => VerifyError::CascadeRejected("ConfirmationExpired (step 13)".into()),
        ConfirmationTtlExceeded => VerifyError::CascadeRejected("ConfirmationTtlExceeded (step 13)".into()),
        PurposeMissing => VerifyError::CascadeRejected("PurposeMissing (step 13)".into()),
        ApprovalDigestInvalid => VerifyError::CascadeRejected("ApprovalDigestInvalid (step 13)".into()),
        MissingHumanConfirmation => VerifyError::CascadeRejected("MissingHumanConfirmation (step 13)".into()),
        CibaExpired => VerifyError::CascadeRejected("CibaExpired (step 13)".into()),
        MissingApprovalDigest => VerifyError::CascadeRejected("MissingApprovalDigest (step 13)".into()),
        MalformedApprovalDigest => VerifyError::CascadeRejected("MalformedApprovalDigest (step 13)".into()),
        ApprovalDigestMismatch => VerifyError::CascadeRejected("ApprovalDigestMismatch (step 13)".into()),
        ScopeCeilingExceeded => VerifyError::CascadeRejected("ScopeCeilingExceeded (step 13)".into()),
        HaapiBillingInvalid => VerifyError::CascadeRejected("HaapiBillingInvalid (step 13.5)".into()),
        IntentVerificationFailed => VerifyError::CascadeRejected("IntentVerificationFailed (step 13.7)".into()),
        PopSigMissing => VerifyError::CascadeRejected("PopSigMissing (step 14)".into()),
        PopSigInvalid => VerifyError::CascadeRejected("PopSigInvalid (step 14)".into()),
        PopPubMissing => VerifyError::CascadeRejected("PopPubMissing (step 14)".into()),
        ConcurrentConsume => VerifyError::Replay,
    }
}
