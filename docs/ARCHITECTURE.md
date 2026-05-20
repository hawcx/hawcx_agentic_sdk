# Architecture

## Option X distribution model

The SDK is a **distribution source**, not a wrapper layer. Customer
binaries come from `hx_labs` directly. The SDK contributes:

1. The publishable `haap-rsv` library (in-process embed for Rust MCP servers).
2. The `haap-rsv` HTTP sidecar binary (cross-language MCP servers).
3. The `haap-sdk` testing/demo CLI.
4. Mechanism 2 release CI that bundles everything into per-platform
   tarballs and a multi-arch Docker image.

## 6-process customer-side pipeline

Per HAAP Canonical Specification v7.2.0 §45.2 (Pattern Z), the per-agent
runtime extends from four protected child processes to five with the
addition of the External Identity Broker (EIB) for OAuth bearer-token
isolation. Together with the Supervisor, the customer-side pipeline is
six processes.

```
┌── haap-supervisor (zero crypto; manages lifecycle) ──┐
│                                                       │
│  ┌── haap-auth-bin ───────┐                          │
│  │  (Authenticator)        │                          │
│  │  Holds IK_i             │                          │
│  │  Performs X3DH          │                          │
│  └─────────────┬───────────┘                          │
│                │                                       │
│  ┌─────────────▼───────────┐                          │
│  │ haap-tqs-precompute-bin │                          │
│  │ Pre-mints Schnorr       │                          │
│  │ commitments             │                          │
│  └─────────────┬───────────┘                          │
│                │                                       │
│  ┌─────────────▼───────────┐                          │
│  │  haap-tqs-jit-bin       │                          │
│  │  Completes tokens at    │                          │
│  │  request time           │                          │
│  └─────────────┬───────────┘                          │
│                │                                       │
│  ┌─────────────▼───────────┐                          │
│  │ haap-assembler-bin      │   ◀── Agent / LLM via   │
│  │ K_req encrypt           │      Assembler API      │
│  │ K_resp decrypt          │                          │
│  │ Single-flight           │                          │
│  └─────────────┬───────────┘                          │
│                │ bearer-attach IPC (§45.4)             │
│  ┌─────────────▼───────────┐                          │
│  │ haap-eib-bin            │                          │
│  │ External Identity       │                          │
│  │ Broker — holds OAuth    │                          │
│  │ bearer tokens (§45)     │                          │
│  └─────────────────────────┘                          │
│                                                       │
└───────────────────────────────────────────────────────┘
```

Each customer-side process holds only the keys relevant to its role.
The Supervisor itself holds zero key material.

## MCP server side

Two integration paths:

### Path A: Rust MCP server with `haap-rsv` library embed

```rust
use haap_rsv::Rsv;
use haap_sdk_types::RsvConfig;

let mut rsv = Rsv::new(RsvConfig::from_env()?).await?;
let verified = rsv.verify_and_decrypt(&token_bytes).await?;
// handle MCP call with verified.plaintext_body
let encrypted = rsv.encrypt_response(&verified, &response_bytes)?;
```

### Path B: Cross-language MCP server with `haap-rsv` HTTP sidecar

```bash
HAAP_CUSTOMER_REDIS_URL=redis://... \
HAAP_AUDIENCE_HASH=<sha256 hex> \
haap-rsv --listen 127.0.0.1:8443
```

The MCP server (in Python, Go, Node, whatever) calls the sidecar:

```
POST /verify         {token_b64}              → {plaintext_b64, session_id, jti_hex, verification_handle}
POST /encrypt-response {handle, plaintext_b64} → {ciphertext_b64}
GET  /healthz                                  → "ok"
```

Verification handles are cached in-memory with 30s TTL so the server
doesn't need to re-decode the token to encrypt the response.

## Cryptographic boundaries

**SDK-owned:**
- Identity bundle sealing (AES-256-GCM via FileSealer or OsKeychainSealer)
- Customer Redis SessionMaterial substrate access
- RSV orchestration (substrate access + replay + cascade delegation)

**hx_labs-owned (consumed via path-dep):**
- X3DH ceremony (`haap_auth::v6_3_registration::perform_agent_registration`)
- Token wire format (`haap_wire::ParsedToken`, encode/decode)
- HKDF v3 derivation (`haap_crypto::zkp`)
- Schnorr signing/verification (`haap_crypto::schnorr_sig`)
- Token minting (`haap_core::mint::mint_token`)
- The 16-step verification cascade (`haap_core::cascade::verify_and_decrypt_request`)
- All AEAD constructions on the wire (AES-256-GCM via `haap_core::request::encrypt_request`, etc.)

**Decision test for any new SDK code**: "Does this line compute or
verify a value the HAAP spec defines?" If yes, it belongs in
`hx_labs` — the SDK calls into the library. If no (it's transport,
persistence, lifecycle, distribution packaging), the SDK owns it.

## IPC

The five customer-side processes (Authenticator, TQS-precompute,
TQS-JIT, Assembler, External Identity Broker) communicate over IPC
managed by `hx_labs`'s `haap-supervisor`. The SDK does NOT define
their IPC envelope — that lives in `hx_labs::haap-ipc`.

The SDK's own `haap-sdk-ipc` crate is a generic UDS framing + SO_PEERCRED
primitive for SDK-internal use (CLI ↔ helpers, future bin-to-bin
coordination). It is not on the protocol surface.

## Threat model

- **Same-host attacker**: SO_PEERCRED on the customer-side IPC sockets
  prevents non-Hawcx processes from connecting. Filesystem permissions
  (mode 0600) provide defense in depth.
- **Token theft + replay**: tokens have short TTLs (60s) and unique
  jti values enforced by the RSV's two-tier replay store (LRU + Redis
  SETNX with per-token TTL).
- **Sealed-at-rest material**: Argon2id-derived passphrase key +
  AES-256-GCM protects identity bundles on disk.
- **Network observer**: all on-wire encryption uses AES-256-GCM via
  `hx_labs` primitives; the SDK never constructs AEADs on the protocol
  surface.

Not protected against:
- Compromise of the customer host operating system (root attacker).
- Compromise of customer Redis (`SubstrateMaterial` is sensitive).
- Compromise of the AS or its signing keys (trust root).
- Side-channel attacks on the underlying crypto primitives.

## Post-alpha roadmap

1. RSV cascade adapter wire-up (Phase 7 follow-up PR).
2. KMS-wrapped sealer (AWS KMS + GCP KMS).
3. Mobile FFI via UniFFI (alpha+1).
4. System packages (.deb, .rpm, Homebrew, scoop).
5. Native TLS feature for environments that mandate it.
