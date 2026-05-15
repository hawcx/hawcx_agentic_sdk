# Deployment

## Customer-side host

```bash
# 1. Install tarball or pull Docker image (see README).
# 2. Configure env vars:
export HAAP_AS_URL=https://as.example.com
export HAAP_ADMIN_CONSOLE_URL=https://admin.example.com
export HAAP_PINNED_IK_SP=<64 hex chars>
export HAAP_SEALER_BACKEND=os-keychain
export HAAP_SEALER_KEYCHAIN_SERVICE=haap-agentic-sdk
export HAAP_SEALER_KEYCHAIN_ACCOUNT=prod
export HAAP_CUSTOMER_REDIS_URL=redis://customer-redis:6379

# 3. Launch the pipeline (uses haap-supervisor from hx_labs):
haap-sdk run-pipeline
# or directly:
haap-supervisor
```

## MCP server host

```bash
# Sidecar deployment (cross-language MCP servers):
export HAAP_CUSTOMER_REDIS_URL=redis://customer-redis:6379
export HAAP_AUDIENCE_HASH=<sha256 hex of audience URL>
haap-sdk run-rsv --listen 0.0.0.0:8443

# Or run haap-rsv directly with the same env vars.
```

For Rust MCP servers, embed the `haap-rsv` library instead — see
[`INTEGRATION.md`](INTEGRATION.md).

## Production env vars

| Var | Required for | Description |
|---|---|---|
| `HAAP_AS_URL` | Authenticator | AS endpoint (HTTPS only) |
| `HAAP_ADMIN_CONSOLE_URL` | Authenticator | OrgToken fetch endpoint |
| `HAAP_PINNED_IK_SP` | Authenticator | 32-byte hex AS identity key for SPK_sig pinning |
| `HAAP_SEALER_BACKEND` | Authenticator | `file` / `os-keychain` / `kms` (default: `file`) |
| `HAAP_SEALER_FILE_PATH` | `file` backend | Where to read/write sealed bundle |
| `HAAP_SEALER_PASSPHRASE` | `file` backend | (env var name configurable via `_ENV` suffix) |
| `HAAP_SEALER_KEYCHAIN_SERVICE` | `os-keychain` | Default: `haap-agentic-sdk` |
| `HAAP_SEALER_KEYCHAIN_ACCOUNT` | `os-keychain` | Default: `default` |
| `HAAP_CUSTOMER_REDIS_URL` | RSV, CLI | Customer Redis URL |
| `HAAP_AUDIENCE_HASH` | RSV | SHA-256 of audience URL (UTF-8 bytes) hex |
| `HAAP_REPLAY_LRU_CAPACITY` | RSV | Default: 4096 |
| `HAAP_RSV_LISTEN` | RSV bin | HTTP listen addr (default: `127.0.0.1:8443`) |
| `HAAP_SUPERVISOR_LISTEN` | Supervisor | (consumed by hx_labs binary) |

## Pre-flight checklist

- [ ] `HAAP_PINNED_IK_SP` matches the current AS IK_sp.
- [ ] AS and admin console URLs are HTTPS.
- [ ] Customer Redis is reachable; AUTH/TLS configured for production.
- [ ] Sealer backend initialized:
  - File backend: the path is writable, the passphrase env var is set
    via secret manager (Kubernetes Secret, AWS Secrets Manager, etc.)
  - OS keychain: tested by an initial seal+unseal cycle.
- [ ] Five hx_labs binaries on `$PATH` of the Supervisor (or use
    `--supervisor-bin` to point at a tarball install dir).
- [ ] Customer Redis sized: ~1 KB per active session, plus replay-store
    entries (~50 bytes each, TTL-expiring).
- [ ] RSV's `HAAP_AUDIENCE_HASH` matches the MCP server's audience URL.

## Cross-references

- Customer Redis setup: [`REDIS_SETUP.md`](REDIS_SETUP.md).
- HTTP API reference: [`RSV_HTTP_API.md`](RSV_HTTP_API.md).
- Supervisor operations: [`SUPERVISOR_OPS.md`](SUPERVISOR_OPS.md).
- Release process: [`RELEASE.md`](RELEASE.md).
