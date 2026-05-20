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

use crate::authorizer::{PermissiveAuthorizer, RegistrationScopeAuthorizer};
use crate::replay::{InMemReplayCheck, RedisReplayCheck};

/// Environment variable selecting the operator's [`Authorizer`].
///
/// Set to `permissive` (default) or `strict`. Read by
/// [`Rsv::new_from_env`].
pub const ENV_RSV_AUTHORIZER: &str = "HAWCX_RSV_AUTHORIZER";

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
    /// Construct an `Rsv` with an operator-chosen [`Authorizer`].
    ///
    /// This is the only constructor that takes the authorizer as a
    /// direct parameter. Operators MUST pass an authorizer explicitly
    /// — the previous `Rsv::new(config)` form silently defaulted to
    /// [`PermissiveAuthorizer`], which was the right choice for
    /// in-process tests but the wrong choice for the customer-facing
    /// SDK surface (C-2 hardening 2026-05-20). Removing the default
    /// makes "what authorizer is this verifier enforcing?" a typed
    /// question at every call site rather than something the reader
    /// has to remember.
    ///
    /// For production deployments, pass
    /// `Box::new(RegistrationScopeAuthorizer)` (CS v6.8.0 §9.1.X).
    /// For dev / unit-test deployments that explicitly want the
    /// permissive behaviour, use [`Rsv::new_alpha_permissive`] —
    /// which logs a startup warning naming the caller crate so
    /// "permissive snuck into prod" failures show up in the log
    /// stream rather than only on review.
    pub async fn new(
        config: RsvConfig,
        authorizer: Box<dyn Authorizer + Send + Sync>,
    ) -> Result<Self, RsvError> {
        Self::new_with_authorizer(config, authorizer).await
    }

    /// Construct an `Rsv` with [`PermissiveAuthorizer`], explicitly
    /// opting into the dev-only permissive path.
    ///
    /// This constructor exists so callers that genuinely want the
    /// dev/test behaviour (unit-test harnesses, the local crewai-demo
    /// flow, anything where you control all token issuance) can do so
    /// without reaching for the env-var dispatch. It logs a
    /// `tracing::warn!` with the caller's crate name at construction
    /// time — that warning is the audit trail for "why is this
    /// verifier permissive?" so a future reader doesn't have to grep
    /// the codebase.
    ///
    /// Hard rule: do not call this from production binaries. The
    /// `haap-rsv-bin` sidecar uses [`Rsv::new_from_env`], which
    /// defaults to `strict` and forces the operator to opt into
    /// `permissive` via `HAWCX_RSV_AUTHORIZER=permissive`.
    pub async fn new_alpha_permissive(config: RsvConfig) -> Result<Self, RsvError> {
        tracing::warn!(
            caller = env!("CARGO_PKG_NAME"),
            "Rsv::new_alpha_permissive: constructing an RSV with PermissiveAuthorizer; \
             this is the dev-only opt-in path. Production callers must pass \
             RegistrationScopeAuthorizer to Rsv::new explicitly, or rely on \
             Rsv::new_from_env (which defaults to 'strict')."
        );
        Self::new_with_authorizer(config, Box::new(PermissiveAuthorizer)).await
    }

    /// Construct an `Rsv` with the authorizer selected by the
    /// [`ENV_RSV_AUTHORIZER`] environment variable.
    ///
    /// | Value         | Authorizer                          |
    /// |---------------|-------------------------------------|
    /// | (unset)       | [`RegistrationScopeAuthorizer`]     |
    /// | `permissive`  | [`PermissiveAuthorizer`]            |
    /// | `strict`      | [`RegistrationScopeAuthorizer`]     |
    ///
    /// Matching is ASCII case-insensitive. Any other value is rejected
    /// fail-fast (`RsvError::Io` with an explanatory message) to avoid
    /// the silent-permissive-fallback foot-gun.
    ///
    /// Default flipped to `strict` 2026-05-20 (C-2 hardening). The
    /// previous default was `permissive`, which was load-bearingly
    /// wrong for production: a customer who deployed `haap-rsv-bin`
    /// with default env config got a verifier that accepted any
    /// claimed scope, regardless of what the agent registered. The
    /// `Rsv::new` constructor used the same default. The new behaviour
    /// is "strict unless you ask for permissive" and emits a
    /// `tracing::warn!` when the env var is unset so the implicit
    /// choice still shows up in logs.
    ///
    /// Switching to `strict` requires that all enrolled agents have
    /// `registered_scope_json` written into substrate (per the AS-side
    /// W4 work). Pre-v6.9.0 sessions without it fall through to
    /// permissive semantics at the per-session level via
    /// [`RegistrationScopeAuthorizer`]'s `None` branch (see
    /// `authorizer.rs:71`) — this is the documented graceful fallback,
    /// not a global toggle.
    pub async fn new_from_env(config: RsvConfig) -> Result<Self, RsvError> {
        let raw = std::env::var(ENV_RSV_AUTHORIZER).ok();
        if raw.is_none() {
            tracing::warn!(
                env_var = ENV_RSV_AUTHORIZER,
                "HAWCX_RSV_AUTHORIZER unset; defaulting to 'strict' \
                 (RegistrationScopeAuthorizer). Set HAWCX_RSV_AUTHORIZER=permissive \
                 to opt into the dev/alpha permissive path."
            );
        }
        let authorizer = authorizer_from_env_value(raw.as_deref())?;
        Self::new_with_authorizer(config, authorizer).await
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
            // The SDK's alpha cascade path doesn't carry PoP-v2 envelopes
            // (the HTTP API doesn't surface them). Sessions whose active
            // policy requires PoP-v2 reject at Step 14 with
            // `PopRequestEnvelopeMissing`, which `map_cascade_reject`
            // surfaces unchanged.
            pop_envelope: None,
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
            pop_envelope: None,
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

/// Pure parser for the [`ENV_RSV_AUTHORIZER`] value. Extracted so unit
/// tests can exercise the dispatch table without touching the process
/// environment (which is global, race-prone, and hard to clean up).
///
/// `None`, `Some("")`, `Some("strict")` → [`RegistrationScopeAuthorizer`].
/// `Some("permissive")` → [`PermissiveAuthorizer`].
/// Any other value → `RsvError::Io` (fail-fast, no silent fallback).
///
/// Default flipped from `permissive` to `strict` 2026-05-20 (C-2). A
/// caller who has not yet thought about authorizer choice now gets the
/// safer answer; opting into `permissive` requires typing the word out
/// loud in the operator's env config.
///
/// Matching is ASCII case-insensitive with surrounding whitespace
/// trimmed.
pub(crate) fn authorizer_from_env_value(
    raw: Option<&str>,
) -> Result<Box<dyn Authorizer + Send + Sync>, RsvError> {
    let normalized = raw.map(|s| s.trim().to_ascii_lowercase());
    match normalized.as_deref() {
        None | Some("") | Some("strict") => Ok(Box::new(RegistrationScopeAuthorizer)),
        Some("permissive") => Ok(Box::new(PermissiveAuthorizer)),
        Some(other) => Err(RsvError::Io(std::io::Error::other(format!(
            "{ENV_RSV_AUTHORIZER}={other:?} is not a recognized value; expected 'permissive' or 'strict'"
        )))),
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
        PopTranscriptVersionUnknown => {
            VerifyError::CascadeRejected("PopTranscriptVersionUnknown (step 14)".into())
        }
        PopRequestEnvelopeMissing => {
            VerifyError::CascadeRejected("PopRequestEnvelopeMissing (step 14)".into())
        }
        // §43 delegation chain (CS v7.0.0). The SDK passes these through
        // verbatim; the consumer is the customer's gateway, not the SDK
        // process. Keep messages stable so existing log greps continue
        // to work.
        DelegationSigInvalid => VerifyError::CascadeRejected("DelegationSigInvalid (step 13.2)".into()),
        DelegationExpired => VerifyError::CascadeRejected("DelegationExpired (step 13.2)".into()),
        DelegationNotYetValid => {
            VerifyError::CascadeRejected("DelegationNotYetValid (step 13.2)".into())
        }
        DelegationChainBroken => VerifyError::CascadeRejected("DelegationChainBroken (step 13.2)".into()),
        DelegationScopeEscalation => {
            VerifyError::CascadeRejected("DelegationScopeEscalation (step 13.2)".into())
        }
        DelegationPubkeyMismatch => {
            VerifyError::CascadeRejected("DelegationPubkeyMismatch (step 13.2)".into())
        }
        DelegationLeafMismatch => VerifyError::CascadeRejected("DelegationLeafMismatch (step 13.2)".into()),
        DelegationScopeExceedsCeiling => {
            VerifyError::CascadeRejected("DelegationScopeExceedsCeiling (step 13.2)".into())
        }
        DelegationDepthExceeded => {
            VerifyError::CascadeRejected("DelegationDepthExceeded (step 13.2)".into())
        }
        DelegationRevoked => VerifyError::CascadeRejected("DelegationRevoked (step 13.2)".into()),
        DelegationGrantTooLong => {
            VerifyError::CascadeRejected("DelegationGrantTooLong (step 13.2)".into())
        }
        DelegationRevocationStale => {
            VerifyError::CascadeRejected("DelegationRevocationStale (step 13.2)".into())
        }
        DelegationRevocationUnavailable => {
            VerifyError::CascadeRejected("DelegationRevocationUnavailable (step 13.2)".into())
        }
        DelegationDirectoryUnavailable => {
            VerifyError::CascadeRejected("DelegationDirectoryUnavailable (step 13.2)".into())
        }
        // §16 user/admin policy signature (v7.1.0).
        UserPolicySigRequired => {
            VerifyError::CascadeRejected("UserPolicySigRequired (step 15)".into())
        }
        UserPolicySigInvalid => {
            VerifyError::CascadeRejected("UserPolicySigInvalid (step 15)".into())
        }
        SignerRoleMismatch => VerifyError::CascadeRejected("SignerRoleMismatch (step 15)".into()),
        ConcurrentConsume => VerifyError::Replay,
    }
}

#[cfg(test)]
mod env_authorizer_tests {
    //! Env-var dispatch tests for `HAWCX_RSV_AUTHORIZER`.
    //!
    //! These exercise the pure parser `authorizer_from_env_value` rather
    //! than `Rsv::new_from_env` directly, so the suite doesn't need a
    //! live Redis and doesn't mutate the process environment (which is
    //! global state and unsafe under cargo's parallel test runner).
    //!
    //! Behavior is asserted by inspecting the returned trait object's
    //! `Authorizer::authorize` decision on synthetic SessionRecords —
    //! Permissive always returns true; RegistrationScope rejects on
    //! mismatch.
    use super::authorizer_from_env_value;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use haap_core::types::{SessionRecord, SessionStatus};
    use haap_sdk_types::RsvError;

    fn session_with_scope(registered_scope_json: Option<Vec<u8>>) -> SessionRecord {
        SessionRecord {
            tqs_public: RistrettoPoint::default(),
            sek_secret: Scalar::ZERO,
            sek_public: RistrettoPoint::default(),
            sek_valid_from: 0,
            sek_valid_until: 0,
            verifier_secret: [0u8; 32],
            k_session_root: [0u8; 32],
            current_epoch: 0,
            scope_ceiling: None,
            pop_pub: None,
            status: SessionStatus::Active,
            org_id: None,
            audience: None,
            profile: None,
            registered_scope_json,
            pop_transcript_version: None,
        }
    }

    fn unwrap_auth(
        r: Result<Box<dyn haap_core::types::Authorizer + Send + Sync>, RsvError>,
    ) -> Box<dyn haap_core::types::Authorizer + Send + Sync> {
        // Box<dyn Trait> doesn't impl Debug, so `.expect(...)` is not
        // available. Match directly.
        match r {
            Ok(a) => a,
            Err(e) => panic!("authorizer_from_env_value rejected unexpectedly: {e}"),
        }
    }

    #[test]
    fn env_unset_selects_strict() {
        // C-2 2026-05-20: default flipped from permissive to strict.
        // An operator who has not configured HAWCX_RSV_AUTHORIZER gets
        // the registration-scope-binding authorizer; a mismatched
        // claimed_scope is rejected at this layer rather than relying
        // on the cascade's Step 10 ceiling as the only floor.
        let auth = unwrap_auth(authorizer_from_env_value(None));
        let session = session_with_scope(Some(b"registered".to_vec()));
        assert!(
            !auth.authorize(b"different", "read", "x", &session),
            "unset env should resolve to strict and reject mismatched claimed_scope"
        );
        // Matching scope still accepted.
        assert!(auth.authorize(b"registered", "read", "x", &session));
    }

    #[test]
    fn env_empty_string_selects_strict() {
        // Common ops mistake: HAWCX_RSV_AUTHORIZER= (export with no
        // value). Treat as unset, not as a parse error — refusing to
        // start the verifier over a whitespace-only env value would be
        // an annoying ops trap with no security upside. Post-C-2 this
        // also resolves to strict (was: permissive).
        let auth = unwrap_auth(authorizer_from_env_value(Some("")));
        let session = session_with_scope(Some(b"registered".to_vec()));
        assert!(!auth.authorize(b"different", "read", "x", &session));
    }

    #[test]
    fn env_permissive_explicit_selects_permissive() {
        // Permissive remains explicitly opt-in for the dev/alpha path.
        let auth = unwrap_auth(authorizer_from_env_value(Some("permissive")));
        let session = session_with_scope(Some(b"registered".to_vec()));
        assert!(auth.authorize(b"different", "read", "x", &session));
    }

    #[test]
    fn env_strict_selects_registration_scope_authorizer() {
        let auth = unwrap_auth(authorizer_from_env_value(Some("strict")));
        let session = session_with_scope(Some(b"registered".to_vec()));
        // Strict rejects mismatched claimed-vs-registered.
        assert!(!auth.authorize(b"different", "read", "x", &session));
        // Strict accepts matching scope.
        assert!(auth.authorize(b"registered", "read", "x", &session));
    }

    #[test]
    fn env_strict_legacy_substrate_defers_permissive() {
        // Strict mode with a pre-W4 session (no registered_scope_json
        // in substrate) MUST NOT brick verification — it falls through
        // to permissive at the per-session level via the
        // RegistrationScopeAuthorizer::None branch. This is the
        // documented graceful-fallback contract.
        let auth = unwrap_auth(authorizer_from_env_value(Some("strict")));
        let session = session_with_scope(None);
        assert!(auth.authorize(b"any:scope", "any", "any", &session));
    }

    #[test]
    fn env_case_insensitive_with_whitespace() {
        // Operators commonly hit case-sensitivity gotchas (`Strict`,
        // ` strict `, `STRICT`). Normalize.
        for v in ["Strict", " strict ", "STRICT", "\tstrict\n"] {
            let auth = unwrap_auth(authorizer_from_env_value(Some(v)));
            let session = session_with_scope(Some(b"reg".to_vec()));
            assert!(
                !auth.authorize(b"mismatch", "read", "x", &session),
                "{v:?} should resolve to strict semantics"
            );
        }
    }

    #[test]
    fn env_unknown_value_fails_fast() {
        // Silent fallback on unknown values is the classic "I thought I
        // was running strict but it's actually permissive" foot-gun.
        // Reject loudly.
        let err = match authorizer_from_env_value(Some("paranoid")) {
            Ok(_) => panic!("unknown value must fail fast, not silently fall back"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("HAWCX_RSV_AUTHORIZER") && msg.contains("paranoid"),
            "error must name both env var and rejected value, got: {msg}"
        );
    }
}
