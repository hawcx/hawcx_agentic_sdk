# Architecture

Per the HAAP Canonical Specification v6.7.4 + v6.6.0 MCP topology, the
SDK ships six components across two sides:

## MCP host side (customer-deployed, one set per agent instance)

```
                         ┌─── Supervisor ───┐
                         │  (zero crypto)   │
                         └──────────────────┘
                          spawns + watches
                                 │
              ┌──────────────────┼───────────────────┐
              │                  │                   │
         ┌─────────┐         ┌───────┐          ┌──────────┐
         │  Auth   │ ◀──────▶│  TQS  │ ◀───────▶│ Assembler│ ◀─── MCP Client (Agent/LLM)
         │ (IK_i)  │  UDS    │       │   UDS    │          │      via assembler.sock
         └─────────┘         └───────┘          └──────────┘
                                                      │
                                                      │ encrypted bytes
                                                      ▼
                                              HTTPS to MCP server
```

### Authenticator (`haap-authenticator`)

- Holds the per-agent identity key IK_i.
- Performs X3DH against the AS via `haap_auth::v6_3_registration::perform_agent_registration`.
- Exposes K_session to TQS over `authenticator.sock`.
- Optionally unseals an existing `RegisteredAgent` from disk on startup
  (via the configured `AgentIdentitySealer`) rather than re-registering.

### TQS (`haap-tqs`) — Token Queue Service

- Connects to `authenticator.sock` at startup to fetch K_session.
- Pre-mints batches of access tokens (RECOMMENDED 10/batch, 10K hard
  cap, 60s TTL). Minting delegates to `haap_core::mint::mint_token`.
- Each token has a 16-byte CSPRNG `jti`. Per-token keys derive from
  K_session + jti via the HKDF chains internal to `mint_token` —
  the SDK never reimplements these.
- Exposes the mint-gate over `tqs.sock` to the Assembler.

### Assembler (`haap-assembler`)

- Single-flight per spec: max ONE in-flight `response_key` at any
  instant. Pipelining is PROHIBITED and rejected with
  `AssemblerError::AlreadyInFlight`.
- Encrypts outgoing request bodies under K_req (derived from the token's
  `response_key` via `haap_core::request::derive_request_key`).
- Decrypts incoming response bodies under K_resp (via
  `haap_core::response::decrypt_response`).
- Exposes a zero-crypto interface to the agent application over
  `assembler.sock`.

### Supervisor (`haap-supervisor`)

- Spawns Authenticator, TQS, Assembler as child processes via
  `tokio::process::Command`.
- Waits for each child's UDS to become reachable (timeout 30s) before
  spawning the next, then registers a health-watch task per child.
- Holds zero crypto material itself — it is purely a process orchestrator.

## MCP server side (third-party tool services)

### RSV (`haap-rsv`) — HAAP Verifier / Resource Server Verifier

- 16-step verification cascade per §9. The cascade itself lives in
  `haap_core::cascade::verify_and_decrypt_request`; the SDK wires that
  function to the customer Redis substrate reader and the two-tier
  replay store.
- Target latency: < 400 μs.
- Negative paths fail closed: any check failing aborts the cascade
  without revealing intermediate state to the caller.

### Customer Redis substrate reader (`haap-substrate-reader`)

- Reads `SubstrateMaterial` (K_session_root + verifier_secret + scope +
  billing_context + epoch_id + aud_hash) keyed by `haap:session:{u64:016x}`.
- The customer-side substrate **writer** lives in `hx_agent_client_admin_service`
  (the CAA); only the **reader** lives here. The substrate is
  customer-deployed Redis, separate from Hawcx's own Redis.

## IPC architecture

All four host-side processes communicate over Unix domain sockets in:

- **Linux**: `$XDG_RUNTIME_DIR/hawcx/` (or `$TMPDIR/hawcx/` if unset)
- **macOS**: `$TMPDIR/hawcx/`

Sockets are mode `0600` (only the owning user can open). On top of
filesystem permissions, SO_PEERCRED is enforced by the kernel: the
`IpcServer::accept` call checks the peer process's UID matches the
expected UID at connection time and rejects mismatches.

- Linux: `nix::sys::socket::sockopt::PeerCredentials` populates a
  `struct ucred` (pid, uid, gid).
- macOS: raw `libc::getsockopt(SOL_LOCAL, LOCAL_PEERPID/LOCAL_PEEREUID)`
  + `getpeereid` for gid.

Wire format: `u32_be(payload_len) || bincode_payload`. Max frame size
is 16 MiB (configurable, but the IPC traffic on these sockets is
small).

## Wire format references (cross-ref to `hx_labs` and v6.7.4 spec)

| Concern | Where it lives |
|---|---|
| Token wire format (§7.1) | `haap-wire::token::ParsedToken` + `encode_token`/`decode_token` |
| Request body AEAD | `haap_core::request::encrypt_request` / `decrypt_request` |
| Response body AEAD | `haap_core::response::encrypt_response` / `decrypt_response` |
| Token minting | `haap_core::mint::mint_token` |
| Cascade verification (§9) | `haap_core::cascade::verify_and_decrypt_request` |
| X3DH registration ceremony (§4.2.1) | `haap_auth::v6_3_registration::perform_agent_registration` |
| HKDF v3 inputs | `haap_crypto::zkp::compute_v3_salt` + `compute_v3_info` |
| Schnorr sig/verify | `haap_crypto::schnorr_sig::{schnorr_sign, schnorr_verify}` |
| Session ID allocator | `haap_redis::allocate_session_id` (returns `u64`) |

The SDK **never reimplements these**. Any line of SDK code that
appears to compute or verify a spec-defined cryptographic value is a
bug — that work belongs in `hx_labs`. The SDK calls into the library
crates listed above.

## Sealer plugin model

`AgentIdentitySealer` is an async trait with three concrete impls:

- **FileSealer**: passphrase + Argon2id (m=64MiB, t=3, p=4) →
  ChaCha20Poly1305. Wire `[salt(16) || nonce(12) || ct_with_tag]`.
  AAD: `b"haap-authenticator-file-sealer-v1"`.
- **OsKeychainSealer**: keyring-rs v3 stores a 32-byte ChaCha20Poly1305
  key in the OS keychain at (service, account); ciphertext is
  `[nonce(12) || ct_with_tag]`. AAD: `b"haap-authenticator-os-keychain-v1"`.
- **KmsWrappedSealer**: stub returning `NotImplemented`. AWS/GCP KMS
  integration is a post-alpha workstream.

SDK-internal sealing may use ChaCha20Poly1305 because it's storage
protection, not a protocol surface. **Protocol-level** AEAD (token body
encryption, request/response body encryption) MUST use AES-256-GCM per
§7 — and the SDK gets that automatically because it calls into
`haap_core` rather than rolling its own.

## Threat model — what the SDK protects against

- **Token theft and replay**: tokens are short-lived (60s) and have
  unique jti enforced by the two-tier replay store (LRU + Redis SETNX).
- **Cross-process key leakage**: Authenticator never gives K_session to
  Agent/LLM or MCP Client; only TQS (matched UID over SO_PEERCRED).
- **Cross-tenant access**: per-token keys derive from K_session and jti,
  so leaking one token doesn't compromise the others.
- **Sealed-at-rest material**: `RegisteredAgent` on disk goes through
  Argon2id + AEAD; raw bytes never touch the filesystem.
- **Pipelining bugs**: Assembler enforces single-flight; a pipelined
  request returns `AlreadyInFlight` rather than mixing response keys.

## What the SDK does NOT protect against

- A compromise of the customer host operating system — SO_PEERCRED is a
  sufficient barrier against non-Hawcx processes on the same host, not
  against a privileged attacker with root access.
- A compromise of the customer Redis — `SubstrateMaterial` written by
  the CAA is sensitive; treat customer Redis as security-relevant.
- A compromise of the AS or its signing keys — that is the trust root.
- Side-channel attacks on the underlying crypto primitives (the SDK
  uses standard `aes-gcm` and `chacha20poly1305` crates; if those are
  vulnerable, the SDK inherits the vulnerability).

## Post-alpha roadmap

1. KMS-wrapped sealer (AWS KMS + GCP KMS SDK integration).
2. Python bindings via `pyo3`.
3. TypeScript bindings via `napi-rs`.
4. Real CI workflow (clippy --all-targets, cargo-deny, cargo-audit).
5. Post-quantum sealer variants (ML-KEM hybrid).
6. Bench harness for the RSV cascade (< 400 μs target).
