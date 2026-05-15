# RSV HTTP API

The `haap-rsv` binary exposes a small HTTP API for cross-language MCP
servers (Python, Go, Node, etc.) to integrate the HAAP verification
cascade as a sidecar.

## Endpoints

### `POST /verify`

Verify a token and optionally decrypt the request body.

**Request:**

```json
{
  "token_b64": "<base64 of wire-format token bytes>",
  "encrypted_request_b64": "<optional base64 of encrypted body>",
  "request_aad_b64": "<optional base64 of AAD>"
}
```

Field rules:

- `token_b64` is required.
- `encrypted_request_b64` and `request_aad_b64` are optional but
  must be paired — both present together, or both omitted.
  Asymmetric presence is a client error.

Field naming conventions (see `crates/haap-rsv-bin/src/lib.rs`):
`*_b64` = base64 STANDARD (RFC 4648 §4); `*_hex` = lowercase hex.

**Response (200):**

```json
{
  "plaintext_b64": "<base64 of decrypted body, empty if no body was supplied>",
  "session_id": 1234567890,
  "jti_hex": "<32-char hex of raw 16-byte JTI>",
  "verification_handle": "<UUID v4>"
}
```

**Response (400):**

Returned for malformed JSON, invalid base64 in any `*_b64` field, or
asymmetric presence of `encrypted_request_b64` / `request_aad_b64`.

```json
{
  "error": "encrypted_request_b64 and request_aad_b64 must be provided together or both omitted"
}
```

**Response (401):**

Returned when the cascade rejects the token (any `CascadeRejectReason`).

```json
{
  "error": "<cascade reject reason>"
}
```

The `verification_handle` is cached in-memory for 30 seconds and is
required to call `/encrypt-response`.

**Example — token-only verification:**

```bash
curl -X POST http://127.0.0.1:8443/verify \
  -H 'Content-Type: application/json' \
  -d '{"token_b64": "AAEC...truncated"}'
```

**Example — token plus encrypted body:**

```bash
curl -X POST http://127.0.0.1:8443/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "token_b64": "AAEC...truncated",
    "encrypted_request_b64": "X4z...truncated",
    "request_aad_b64": "YWQ..."
  }'
```

Schema evolution: new optional fields may be added without breaking
existing clients; existing field names and types are stable contract
for alpha-2 and beyond. Removed fields will be marked deprecated for
at least one alpha cycle before removal.

### `POST /encrypt-response`

Encrypt a response body using the per-request response_key recovered
during `/verify`.

**Request:**

```json
{
  "verification_handle": "<UUID from /verify>",
  "plaintext_b64": "<base64 of response body>"
}
```

**Response (200):**

```json
{
  "ciphertext_b64": "<base64 of encrypted response>"
}
```

**Response (404):**

If the handle has expired (older than 30s) or never existed:

```json
{
  "error": "verification handle not found (expired or never created)"
}
```

### `GET /healthz`

Health-check endpoint. Returns `200 "ok"` if the RSV is ready to
serve verify requests.

## Operation

The binary listens on `HAAP_RSV_LISTEN` (default `127.0.0.1:8443`).
Use a reverse proxy + TLS termination in production; the binary
itself does not terminate TLS. See the threat-model section below
for the supported deployment patterns.

Concurrent verification requests are serialized at the `Rsv` mutex —
internal redesign for finer-grained concurrency lands in a follow-up
PR.

## Threat model and transport security

`haap-rsv` listens for HTTP connections at the configured `HAAP_RSV_LISTEN`
address. By default this is `127.0.0.1:8443` (loopback only). The default
is intentional and reflects the supported alpha deployment pattern.

### Sidecar deployment (recommended)

The supported alpha pattern co-locates `haap-rsv` with the MCP server
process on the same host:

```
[MCP server process]  <-HTTP->  [haap-rsv on 127.0.0.1:8443]
        (same host)
```

The TCP traffic between these two processes never leaves the host. Loopback
HTTP is sufficient because:

1. **The HAAP-layer cryptography is the protective surface.** The agent's
   request body reaches `haap-rsv` already AES-256-GCM-encrypted with K_req.
   `haap-rsv` decrypts via the cascade (using K_session_root-derived keys)
   and returns plaintext to the local MCP server. The MCP server encrypts
   its response with K_resp before sending it back. HTTP-vs-HTTPS at the
   transport layer is a defense-in-depth question for the metadata around
   those encrypted payloads, not for the protective surface itself.

2. **Loopback traffic does not leave the host.** An attacker would need
   local code execution on the same host to intercept, at which point they
   have more direct attack paths (process memory, debugger attach, etc.).

3. **TLS cert management adds operational complexity for marginal protection
   on loopback.** The supported pattern uses reverse proxies (nginx, Caddy,
   Envoy) for TLS termination when cross-host traffic is involved (see
   below). Loopback deployments skip the cert lifecycle burden.

### Cross-host deployment

If `haap-rsv` runs on a different host than the MCP server (network traffic
between them), HTTPS becomes essential. The supported pattern places a
TLS-terminating reverse proxy in front of `haap-rsv`:

```
[MCP server]  --TLS->  [reverse proxy]  <-HTTP->  [haap-rsv on 127.0.0.1:8443]
                      (TLS termination)              (loopback only)
```

The reverse proxy:

- Terminates TLS with a certificate the MCP server trusts
- Forwards plaintext HTTP to `haap-rsv` on loopback within its own host
- Optionally adds rate limiting, request logging, and access control

This deployment pattern is the standard "production" deployment shape.
Customers handle cert lifecycle through their existing TLS infrastructure
(Let's Encrypt, internal PKI, cert-manager in Kubernetes, etc.) — the
same infrastructure they use for everything else.

### Why `haap-rsv` does not have native TLS

Adding native TLS to `haap-rsv-bin` would require:

- Cert lifecycle management (rotation before expiry, renewal alerts)
- Cert provisioning during deployment
- Operator-side configuration (cert path, key path, CA chain, OCSP stapling)

For an alpha release, this is operational complexity that doesn't unlock
new threat model protection beyond what HAAP-layer crypto already provides.
Native TLS support is a documented post-alpha workstream.

### Direct network exposure (NOT supported)

Configurations like `HAAP_RSV_LISTEN=0.0.0.0:8443` (binding all interfaces
without a reverse proxy) are not supported. `haap-rsv` will emit a
startup warning if it detects non-loopback binding. The warning is
informational; the binary will still serve traffic, but the deployment
is operating outside the supported pattern.

If a customer needs to expose `haap-rsv` on a network address, the correct
solution is to put it behind a TLS-terminating reverse proxy.

### What the HAAP protocol protects

For clarity, the following are protected by HAAP at the application
cryptographic layer regardless of transport:

- **Token authenticity**: Schnorr signature over R_tok, sigma_tok, and the
  encrypted body's GCM tag. Forged tokens fail verification.
- **Request body confidentiality and integrity**: AES-256-GCM with K_req
  derived per-token from K_session_root + jti. Tampered or replayed
  ciphertext fails decryption.
- **Response body confidentiality and integrity**: AES-256-GCM with
  K_resp derived per-token. Same protection on the response path.
- **Replay protection**: jti tracked in Redis with TTL; second use of
  the same jti rejected.
- **Scope enforcement**: cascade step 13 enforces `scope_ceiling` from
  substrate. The Authorizer trait adds policy gating on top.

The following are protected by HAAP at the application layer ONLY when
transport TLS is also in use:

- **Metadata confidentiality**: HTTP headers (e.g., Content-Length, custom
  headers added by intermediaries) are visible to a network attacker
  without TLS. The encrypted body's structure may reveal patterns even
  if the contents are protected.
- **Timing analysis**: response time correlations can reveal request
  patterns even when contents are encrypted. TLS does not fully mitigate
  this but obscures the network-layer view.

For high-sensitivity deployments where metadata protection matters,
deploy `haap-rsv` behind a TLS-terminating reverse proxy regardless of
whether the deployment is single-host or multi-host.
