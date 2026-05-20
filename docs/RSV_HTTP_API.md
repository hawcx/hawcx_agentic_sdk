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

`haap-rsv` runs in one of two transport modes (selected via `--transport`
or `HAAP_RSV_TRANSPORT`):

- **`unix` (default)**: bind a Unix Domain Socket at
  `$XDG_RUNTIME_DIR/hawcx/rsv.sock` (overridable via `HAAP_RSV_UDS_PATH`).
  Authentication is performed at accept time via `SO_PEERCRED`
  (Linux) / `LOCAL_PEEREUID` (macOS). The peer's effective UID must
  equal `HAAP_RSV_EXPECTED_PEER_UID` (default: the `haap-rsv` process's
  own UID). Mismatched peers are dropped without a response.
- **`tcp` (opt-in)**: bind a TCP listener at `HAAP_RSV_LISTEN`
  (default `127.0.0.1:8443`). Every authenticated route requires
  `Authorization: Bearer <token>` where the token equals
  `HAAP_RSV_AUTH_TOKEN`. `HAAP_RSV_AUTH_TOKEN` MUST be at least
  32 bytes; shorter values cause `haap-rsv` to refuse to start. The
  comparison is constant-time (`subtle::ConstantTimeEq`).

`GET /healthz` is exempt from both authentication paths (it is a
liveness probe and exposes no secrets).

Use a TLS-terminating reverse proxy in front of the TCP listener for
any deployment that crosses a host boundary; the binary itself does
not terminate TLS.

Concurrent verification requests are serialized at the `Rsv` mutex —
internal redesign for finer-grained concurrency lands in a follow-up
PR.

## Threat model and transport security

`haap-rsv` defaults to UDS (`$XDG_RUNTIME_DIR/hawcx/rsv.sock`) so that
"any process on the host can hit the verifier and decrypt request
bodies" is not the out-of-the-box reality. The previous "loopback is
fine" reasoning has been retired: loopback TCP authenticates _nothing_
about its caller — any local process (including unrelated daemons,
container neighbours, and SSRF-reachable services) could call
`/verify` and learn plaintext request bodies.

### Sidecar deployment (recommended)

The supported pattern co-locates `haap-rsv` with the MCP server process
on the same host and uses UDS for the wire between them:

```
[MCP server process]  <-UDS->  [haap-rsv on $XDG_RUNTIME_DIR/hawcx/rsv.sock]
        (same host, same UID)
```

The UDS is `chmod 600` and the parent directory is `chmod 700`. The
`haap-rsv` accept loop validates `SO_PEERCRED` on every connection and
drops peers whose UID doesn't match `HAAP_RSV_EXPECTED_PEER_UID`. An
attacker who lands code execution under a different UID on the same
host cannot reach the verifier even though the socket file is on the
local filesystem.

### Cross-host deployment

If `haap-rsv` runs on a different host than the MCP server (network traffic
between them), use TCP transport, the bearer-token authenticator, and a
TLS-terminating reverse proxy:

```
[MCP server]  --TLS->  [reverse proxy]  <--HTTP+Bearer-->  [haap-rsv on 127.0.0.1:8443]
                      (TLS termination)                       (--transport tcp)
```

The reverse proxy:

- Terminates TLS with a certificate the MCP server trusts
- Forwards HTTP to `haap-rsv` on loopback within its own host, including
  the `Authorization: Bearer <HAAP_RSV_AUTH_TOKEN>` header
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

Configurations like `--transport tcp` + `HAAP_RSV_LISTEN=0.0.0.0:8443`
(binding all interfaces without a reverse proxy) are not supported.
The bearer-token middleware authenticates every request but does not
encrypt the wire — HTTP headers, response bodies that the MCP server
re-encrypts, and timing information are all visible to a network
attacker. `haap-rsv` will emit a startup warning if it detects
non-loopback binding even in TCP mode.

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
