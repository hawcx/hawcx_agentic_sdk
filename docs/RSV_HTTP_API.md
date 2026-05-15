# RSV HTTP API

The `haap-rsv` binary exposes a small HTTP API for cross-language MCP
servers (Python, Go, Node, etc.) to integrate the HAAP verification
cascade as a sidecar.

## Endpoints

### `POST /verify`

Verify a token + decrypt the request body.

**Request:**

```json
{
  "token_b64": "<base64 of wire-format token bytes>"
}
```

**Response (200):**

```json
{
  "plaintext_b64": "<base64 of decrypted body>",
  "session_id": 1234567890,
  "jti_hex": "<22-byte base64url JTI as hex string>",
  "verification_handle": "<UUID v4>"
}
```

**Response (401):**

```json
{
  "error": "<cascade reject reason>"
}
```

The `verification_handle` is cached in-memory for 30 seconds and is
required to call `/encrypt-response`.

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
itself does not terminate TLS.

Concurrent verification requests are serialized at the `Rsv` mutex —
internal redesign for finer-grained concurrency lands in a follow-up
PR.

## Status

The cascade adapter (calling
`haap_core::cascade::verify_and_decrypt_request`) is wired up in a
focused follow-up PR. Today `/verify` returns 401 with the message
`"RSV cascade adapter wire-up lands in a focused follow-up PR"`;
the endpoint shape, handle caching, error contract, and TTL
mechanics are in place and stable.
