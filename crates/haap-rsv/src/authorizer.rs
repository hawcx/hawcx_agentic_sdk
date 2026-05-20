//! Authorizer adapters for the RSV cascade.
//!
//! v6.8.0 (W4 2026-05-18) closes the two prerequisites that previously
//! made `RegistrationScopeAuthorizer` impossible to ship from the SDK
//! (see commit history + docs/rsv_adapter_helper_signatures.md Phase 0.4):
//!
//! 1. The substrate now carries `registered_scope_json` on
//!    `RawSessionRecord` / `SessionRecord` (hx_labs W4 / haap-core).
//! 2. The `Authorizer` trait signature accepts `&SessionRecord`, so
//!    impls can inspect the registration-time field at decision time
//!    (hx_labs W4 / haap-core).
//!
//! This module exposes:
//!
//! - [`PermissiveAuthorizer`] — alpha default; always returns true and
//!   defers to the cascade's Step 10 ceiling check.
//! - [`RegistrationScopeAuthorizer`] — strict-equality reference impl
//!   that mirrors the haap-core impl byte-for-byte. The RSV operator
//!   selects it via [`crate::Rsv::builder`].
//!
//! Strict-equality semantics (not subset) is v6.8.0's default per memo
//! §2.4 + CS §9.1.X. Subset semantics is a future enhancement that
//! requires no further trait shape changes — only the comparison logic.

use haap_core::types::{Authorizer, SessionRecord};

/// Permissive authorizer: always returns `true`.
///
/// Cascade-internal checks (scope_ceiling at step 10, PoP at step 14,
/// confirmation requirements, etc.) remain active. This authorizer
/// only short-circuits the operation+resource policy evaluation that
/// belongs to a future Cedar layer.
pub struct PermissiveAuthorizer;

impl Authorizer for PermissiveAuthorizer {
    fn authorize(
        &self,
        _claimed_scope: &[u8],
        _operation: &str,
        _resource: &str,
        _session: &SessionRecord,
    ) -> bool {
        true
    }
}

/// Strict-equality registration-scope authorizer per CS v6.8.0 §9.1.X.
///
/// The token's `claimed_scope` MUST equal
/// `session.registered_scope_json` byte-for-byte (CanonicalJSON). When
/// `registered_scope_json` is `None` (legacy substrates that did not
/// opt in to registration-scope binding), this authorizer defers
/// permissive — the cascade's Step 10 ceiling check remains the
/// protection floor.
///
/// Mirrors `haap_core::authorizer::RegistrationScopeAuthorizer`. The
/// SDK ships an independent type so RSV operators do not need to take
/// a direct `haap-core::authorizer` import.
pub struct RegistrationScopeAuthorizer;

impl Authorizer for RegistrationScopeAuthorizer {
    fn authorize(
        &self,
        claimed_scope: &[u8],
        _operation: &str,
        _resource: &str,
        session: &SessionRecord,
    ) -> bool {
        match &session.registered_scope_json {
            Some(registered) => claimed_scope == registered.as_slice(),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use haap_core::types::SessionStatus;

    fn fake_session(registered_scope_json: Option<Vec<u8>>) -> SessionRecord {
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

    #[test]
    fn permissive_authorizer_allows_anything() {
        let auth = PermissiveAuthorizer;
        let session = fake_session(None);
        assert!(auth.authorize(b"any:scope", "read", "any:resource", &session));
        assert!(auth.authorize(b"", "", "", &session));
        assert!(auth.authorize(b"write", "DELETE", "/admin", &session));
    }

    #[test]
    fn registration_scope_match_accepts() {
        let auth = RegistrationScopeAuthorizer;
        let scope = br#"["read:notes"]"#.to_vec();
        let session = fake_session(Some(scope.clone()));
        assert!(auth.authorize(&scope, "read", "notes", &session));
    }

    #[test]
    fn registration_scope_mismatch_rejects() {
        let auth = RegistrationScopeAuthorizer;
        let session = fake_session(Some(br#"["read:notes"]"#.to_vec()));
        assert!(!auth.authorize(br#"["write:notes"]"#, "write", "notes", &session));
    }

    #[test]
    fn registration_scope_absent_defers_permissive() {
        // Legacy substrate (None) defers to permissive; the cascade's
        // Step 10 ceiling check is the protection floor.
        let auth = RegistrationScopeAuthorizer;
        let session = fake_session(None);
        assert!(auth.authorize(br#"["any:thing"]"#, "any", "any", &session));
    }

    #[test]
    fn registration_scope_empty_registered_rejects_nonempty_claimed() {
        // `Some(vec![])` means the AS explicitly registered an empty
        // scope. Strict equality means *any* non-empty claimed_scope
        // must fail. This is distinct from `None` (legacy substrate)
        // which defers permissive — we don't conflate the two.
        let auth = RegistrationScopeAuthorizer;
        let session = fake_session(Some(Vec::new()));
        assert!(!auth.authorize(br#"["read:notes"]"#, "read", "notes", &session));
        // ...and equally, an empty claimed_scope against empty registered
        // is a vacuous match (the cascade's Step 10 ceiling check is the
        // load-bearing gate for empty-scope cases — see authorizer.rs:69).
        assert!(auth.authorize(b"", "", "", &session));
    }
}
