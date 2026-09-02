# RSV Cascade Adapter — the ancestor monorepo Helper Signatures

**Date:** 2026-05-15
**the ancestor monorepo HEAD verified:** `17da98a` (Merge pull request #62 from
hawcx/feature/mode-c-provision-session-material-dispatch-2026-05-27)

## verify_and_decrypt_request

`crates/haap-core/src/cascade.rs:165`

```rust
pub fn verify_and_decrypt_request(
    token: &ParsedToken,
    session: Option<&SessionRecord>,
    ctx: &CascadeContext<'_>,
    replay: &mut impl ReplayCheck,
    authorizer: &impl Authorizer,
    encrypted_request: Option<&[u8]>,
    request_aad: &[u8],
) -> Result<(TokenBody, Option<Vec<u8>>), CascadeRejectReason>
```

Sync (not async). The cascade calls `verify_token` then optionally
decrypts a request body via `crate::request::decrypt_request` if
`encrypted_request` starts with `REQUEST_HEADER`.

## CascadeContext

`crates/haap-core/src/types.rs:133`

```rust
pub struct CascadeContext<'a> {
    pub now: u64,
    pub token_ttl_secs: u64,
    pub operation: &'a str,
    pub resource: &'a str,
    pub max_confirmation_ttl_secs: u64,
    pub pop_sig: Option<&'a [u8; 64]>,
    pub tool_arguments: Option<&'a [u8]>,
}
```

**No `audience_hash` field.** Audience binding is enforced at step 3b
via the token's `aud_hash` matching `SessionRecord.audience` (the
cascade computes SHA-256(audience) and compares).

## ReplayCheck

`crates/haap-core/src/types.rs:209` — **synchronous** trait:

```rust
pub trait ReplayCheck {
    fn replay_precheck(&mut self, session_id: u64, jti: &[u8; 16]) -> Result<bool, String>;
    fn replay_consume(&mut self, session_id: u64, jti: &[u8; 16], ttl_secs: u64) -> Result<bool, String>;
}
```

**JTI is `[u8; 16]`** — the raw CSPRNG bytes from `TokenBody.jti`, NOT
the 22-byte base64url wire encoding. The SDK's existing
`ReplayStore<[u8; 22]>` and `VerifiedRequest.jti: [u8; 22]` must
change to `[u8; 16]` for cascade compatibility.

## Authorizer

`crates/haap-core/src/types.rs:226` — **synchronous** trait:

```rust
pub trait Authorizer {
    fn authorize(&self, scope: &[u8], operation: &str, resource: &str) -> bool;
}
```

**Returns `bool` directly** — true if scope authorizes operation on
resource, false otherwise. No error context; the cascade maps
`false` to `CascadeRejectReason::AuthorizationDenied`.

## SessionRecord

`crates/haap-core/src/types.rs:20` — substantially **richer** than
the SDK's current `SubstrateMaterial`:

```rust
pub struct SessionRecord {
    pub tqs_public: RistrettoPoint,         // 32-byte compressed point decompressed
    pub sek_secret: Scalar,                 // 32-byte canonical scalar
    pub sek_public: RistrettoPoint,         // 32-byte compressed point decompressed
    pub sek_valid_from: u64,
    pub sek_valid_until: u64,
    pub verifier_secret: [u8; 32],
    pub k_session_root: [u8; 32],
    pub current_epoch: u64,
    pub scope_ceiling: Option<serde_json::Value>,
    pub pop_pub: Option<[u8; 32]>,
    pub status: SessionStatus,              // Active|Suspended|Revoked
    pub org_id: Option<String>,
    pub audience: Option<Vec<u8>>,
    pub profile: Option<Profile>,           // Enterprise|Standard
}
```

## RawSessionRecord (substrate format)

`crates/haap-redis/src/key_table.rs:75` — what the CAA writes to
Redis. Cryptographic points stored as raw bytes (no decompression):

```rust
pub struct RawSessionRecord {
    pub tqs_public: [u8; 32],
    pub sek_secret: [u8; 32],
    pub sek_public: [u8; 32],
    pub sek_valid_from: u64,
    pub sek_valid_until: u64,
    pub verifier_secret: [u8; 32],
    pub k_session_root: [u8; 32],
    pub current_epoch: u64,
    pub pop_pub: Option<[u8; 32]>,
    pub agent_instance_id: Option<String>,
    pub status: SessionStatus,
    pub client_id: Option<String>,
    pub pk_c: Option<[u8; 32]>,
    pub audience: Option<String>,
    pub scope_ceiling: Option<String>,  // JSON-serialized
    pub session_created_at: Option<u64>,
    pub session_expires_at: Option<u64>,
    pub profile: Option<String>,
    pub trust_level: Option<u8>,
    pub org_id: Option<String>,
    pub max_calls: Option<u32>,
    pub require_attestation: Option<bool>,
    // ... additional v6.0.0 §8.1 fields
}
```

A `TryFrom<RawSessionRecord> for SessionRecord` impl exists at
`types.rs:155` (feature-gated on `redis-backend`).

## TokenBody (cascade return type)

`crates/haap-core/src/types.rs:102`:

```rust
pub struct TokenBody {
    pub mutual_auth: [u8; 32],
    pub verifier_secret: [u8; 32],
    pub jti: [u8; 16],
    pub audience: Vec<u8>,
    pub client_id: Vec<u8>,
    pub scope: Vec<u8>,
    pub priv_sig: [u8; 32],
    pub policy_epoch: u64,
    pub response_key: [u8; 32],
}
```

`response_key` is the per-token 32-byte secret the MCP server uses to
encrypt its response (via `haap_core::response::encrypt_response`).

## CascadeRejectReason variants (mapping target)

`crates/haap-core/src/error.rs:10` — full enum:

| Variant | Step |
|---|---|
| `InvalidFraming` | 1 |
| `SessionNotFound` / `SessionSuspended` / `SessionRevoked` | 2 |
| `TemporalInvalid` | 3 |
| `AudHashMismatch` | 3b |
| `SekExpired` | 4 |
| `KeyDerivation` / `SessionRootDerivation` | 5 |
| `SignatureInvalid` | 6 |
| `AeadDecryptFailed` / `BodyDeserialize` | 7 |
| `VerifierSecretMismatch` | 8 |
| `ReplayDetected` / `ReplayCheckError` | 9 |
| `PolicyEpochStale` / `StalePolicy` | 10 |
| `PrivKeyDerivation` / `PrivSigInvalid` | 11 |
| `AuthorizationDenied` / `ConfirmationRequired` / `ConfirmationExpired` / `ConfirmationTtlExceeded` / `PurposeMissing` / `ApprovalDigestInvalid` / `MissingHumanConfirmation` / `CibaExpired` / `MissingApprovalDigest` / `MalformedApprovalDigest` / `ApprovalDigestMismatch` / `ScopeCeilingExceeded` | 13 |
| `HaapiBillingInvalid` | 13.5 |
| `IntentVerificationFailed` | 13.7 |
| `PopSigMissing` / `PopSigInvalid` / `PopPubMissing` | 14 |
| `ConcurrentConsume` | 15 |

Plus consumer-feature variants (`UserPolicySigInvalid`,
`TsaTokenMissing`, etc.) — feature-gated on `consumer`.

## decode_token

`crates/haap-wire/src/token.rs:108`:

```rust
pub fn decode_token(data: &[u8]) -> Result<ParsedToken, WireError>
```

Structural validation only — length check, R_tok point decompression,
σ_tok canonical scalar check, jti_pad zero check. Semantic
validation (version, temporal, Schnorr) is deferred to the cascade.

## ParsedToken

`crates/haap-wire/src/token.rs:68` — the **wire-format** decoded
fields (not the cascade-verified body):

```rust
pub struct ParsedToken {
    pub version: u8,
    pub alg_id: u8,
    pub msg_type: u8,
    pub session_id: u64,
    pub token_iv: [u8; 12],
    pub issued_at: u64,
    pub expires_at: u64,
    pub policy_epoch: u64,
    pub aud_hash: [u8; 32],
    pub jti: [u8; 22],          // 22-byte base64url ASCII wire form
    pub r_tok: RistrettoPoint,
    pub sigma_tok: Scalar,
    pub aad: Vec<u8>,
    pub ct_body: Vec<u8>,
    pub tag: [u8; 16],
}
```

**JTI on ParsedToken is 22 bytes** (wire form). After cascade
verification, the decrypted `TokenBody.jti` is 16 bytes (raw CSPRNG).
The SDK's `VerifiedRequest.jti` should expose the 16-byte form
(matching the post-cascade representation).

## encrypt_response

`crates/haap-core/src/response.rs:70`:

```rust
pub fn encrypt_response(
    response_key: &[u8; 32],
    session_id: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, ResponseError>
```

## Phase 0.4 investigation: registration-scope semantics

**Verdict: the Authorizer trait does NOT support comparing token
scope against a registration-time scope.** The trait signature
`authorize(scope, operation, resource) -> bool` only knows about:

- The token's claimed scope (already in `body.scope` after the
  cascade decrypts it).
- The operation/resource the request is attempting.

It does NOT receive a `SessionRecord`, `RawSessionRecord`, or any
other substrate-derived data. There is no "registered scope" or
"granted scope" field anywhere in `SessionRecord` (the closest
field is `scope_ceiling`, which is the **policy-set** ceiling, not
the **registration-time** scope).

**Conclusion C-prime**: The prompt's `RegistrationScopeAuthorizer`
design — strict equality between claimed scope and registration
scope — cannot be implemented against the current Authorizer trait
without one of:

1. **Stateful Authorizer**: hold the registration scope as state
   (`RegistrationScopeAuthorizer { registered_scope: Vec<u8> }`).
   Construct per-request after substrate lookup. Requires
   `SubstrateMaterial` (or `RawSessionRecord`) to carry a
   `registered_scope` field, which the CAA must write.
   *Today: neither field exists.*
2. **Trait extension**: change the Authorizer trait to take
   `&SessionRecord` so it can compare against any session-stored
   value. Requires an ancestor-monorepo PR + cascade-wide signature update.
   *Today: not feasible in PR A scope.*
3. **Permissive alpha + future Cedar**: ship alpha with a
   permissive `Authorizer` (always returns true) that defers all
   scope/operation/resource authorization to the cascade's existing
   internal checks (scope_ceiling at step 13, confirmation
   requirements, PoP, etc.). RegistrationScopeAuthorizer becomes a
   post-alpha workstream once the substrate carries
   registered_scope.
   *Today: feasible, intentionally narrow.*

**Decision applied: option 3 for alpha.** The PR A implementation
uses a `PermissiveAuthorizer`. The Phase 3 commit and the closure
report document this clearly. RegistrationScopeAuthorizer is added
to the open-follow-ups list with a precise gating condition
(substrate schema extension).

## Substrate gap (Phase 1 implication)

The SDK's current `SubstrateMaterial`:

```rust
pub struct SubstrateMaterial {
    pub session_id: u64,
    pub k_session_root: [u8; 32],
    pub verifier_secret: [u8; 32],
    pub scope: String,
    pub policy_epoch: u64,
}
```

is **substantially incomplete** versus what `SessionRecord` requires.
Missing critical fields:

- `tqs_public: [u8; 32]` — required for Schnorr signature
  verification at step 6
- `sek_secret`, `sek_public` — required for AEAD key derivation at
  step 5
- `sek_valid_from`/`sek_valid_until` — required for temporal check
  at step 4
- `status: SessionStatus` — required for step 2 active/suspended/revoked check
- `pop_pub`, `org_id`, `audience` — optional but consumed by cascade
  steps 3b/13/14

**Decision applied**: Phase 1 replaces `SubstrateMaterial` with a
re-export of `haap_redis::RawSessionRecord` (path-dep'd from
the ancestor monorepo). The SDK already path-deps `haap-redis` indirectly via
`haap-core`'s `redis-backend` feature; adding it directly as a
dependency of `haap-substrate-reader` lets us re-use the CAA's
substrate schema verbatim.

The `haap-sdk-types::SubstrateMaterial` type is retained as a
backwards-compatibility alias (`type SubstrateMaterial =
RawSessionRecord`) so existing call sites keep building. The
field set expands; existing code that only reads
`session_id`/`k_session_root`/etc. continues to work.

## Adapter responsibilities (after Phase 0 reality check)

1. Decode wire bytes via `haap_wire::decode_token` → `ParsedToken`.
2. Substrate fetch: `CustomerSubstrateReader::fetch_session(session_id)`
   returns `Option<RawSessionRecord>`.
3. Convert `RawSessionRecord` → `SessionRecord` via the existing
   `TryFrom` impl (gated on `redis-backend` feature).
4. Construct `CascadeContext` from `RsvConfig` + per-request inputs
   (operation, resource — currently empty defaults for alpha,
   plumbed through future API).
5. Provide `ReplayCheck` impl (RsvReplayCheck wrapping the SDK's
   ReplayStore, with `[u8; 16]` JTI keys after the schema fix).
6. Provide `Authorizer` impl (`PermissiveAuthorizer` for alpha).
7. Call `verify_and_decrypt_request`, package the result into
   `VerifiedRequest`.

## Key divergences from prompt's blueprint

| Prompt assumption | Phase 0 reality |
|---|---|
| `SubstrateMaterial → SessionRecord` is a field-rename mapping | Substrate is dramatically incomplete; path-dep `RawSessionRecord` and reuse the existing TryFrom |
| `ReplayCheck` is async with `[u8; 22]` JTI | Sync, `[u8; 16]` JTI |
| `Authorizer` can hold registration-scope state | Trait signature precludes session-level state without extension |
| `CascadeContext.audience_hash` field | No such field; audience is enforced via `SessionRecord.audience` |
| `RegistrationScopeAuthorizer` enforces registration-time scope | Use `PermissiveAuthorizer` for alpha; registration-scope requires substrate schema + trait extension |

Each subsequent phase adapts to actual signatures.
