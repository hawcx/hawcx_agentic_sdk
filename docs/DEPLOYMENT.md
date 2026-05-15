# Deployment

## Customer-side (MCP host) topology

For each agent instance, deploy:

1. The three Hawcx binaries (`haap-authenticator`, `haap-tqs`,
   `haap-assembler`) on the same host as the agent runtime, owned by
   the same OS user.
2. A `haap-supervisor` (or an embedded `AgentRuntime`) that spawns them.
3. A customer Redis instance reachable from the agent host (the same
   Redis that the CAA writes SessionMaterial to). See
   [`REDIS_SETUP.md`](REDIS_SETUP.md).

The four processes communicate over Unix domain sockets in
`$XDG_RUNTIME_DIR/hawcx/` (Linux) or `$TMPDIR/hawcx/` (macOS). The
directory is created with mode 0700 on first launch.

## MCP server-side topology

For each MCP server that integrates with HAAP, deploy:

1. The `haap-rsv` library embedded into the server's request handler
   (or `haap-sdk run-rsv` as a standalone HTTP fronting service).
2. Read access to the same customer Redis that the agent's CAA writes to.

## Env vars

See the README for the full list. The minimum set for production:

```bash
HAAP_AS_URL=https://as.example.com
HAAP_ADMIN_CONSOLE_URL=https://admin.example.com
HAAP_PINNED_IK_SP=<64 hex chars>
HAAP_SEALER_BACKEND=os-keychain   # or "file" for non-interactive prod
HAAP_SEALER_KEYCHAIN_SERVICE=haap-agentic-sdk
HAAP_SEALER_KEYCHAIN_ACCOUNT=prod
HAAP_CUSTOMER_REDIS_URL=redis://customer-redis:6379
HAAP_SEALED_AGENT_PATH=/var/lib/hawcx/agent.sealed
```

`HAAP_ALLOW_HTTP_FOR_DEV` must NOT be set in production.

## Sealer backend selection

| Backend | Best for | Cons |
|---|---|---|
| `file` | Containerized deployments with secret-mounted passphrase | Passphrase rotation requires re-sealing |
| `os-keychain` | Desktop / single-user workstations, macOS hosts | Headless Linux requires libsecret-1-dev |
| `kms` | Cloud production with KMS already in use | **Post-alpha; not yet implemented** |

For headless Linux deployments today, use `file` with the passphrase
mounted from a secret manager (Kubernetes Secret, AWS Secrets Manager,
HashiCorp Vault).

## Production pre-flight checklist

- [ ] `HAAP_PINNED_IK_SP` matches the AS's current IK_sp identity.
- [ ] `HAAP_AS_URL` and `HAAP_ADMIN_CONSOLE_URL` are HTTPS.
- [ ] `HAAP_ALLOW_HTTP_FOR_DEV` is unset (or `false`).
- [ ] Customer Redis is reachable and AUTH/TLS is configured.
- [ ] Sealer file path or OS keychain entry is initialized.
- [ ] Socket directory `$XDG_RUNTIME_DIR/hawcx/` has mode 0700.
- [ ] The three child binaries are on `$PATH` of the Supervisor process.
- [ ] Customer Redis is sized (~1 KB/active session) and configured
      with `allkeys-lru` eviction + AOF persistence (see REDIS_SETUP.md).
- [ ] CAA has writeable network path to the same Redis.

## Cross-references

- The CAA (customer admin agent) writer half lives in
  [`hx_agent_client_admin_service`](https://github.com/hawcx/hx_agent_client_admin_service)
  (separate repo).
- The AS lives in [`hx_labs`](https://github.com/hawcx/hx_labs) as
  `haap-server` (along with the rest of the protocol stack).
- Admin and user consoles are at
  [`hx_admin_console`](https://github.com/hawcx/hx_admin_console) and
  [`hx_user_console`](https://github.com/hawcx/hx_user_console).
- Operator-facing hx_labs deployment guide:
  `~/Projects/hx_labs/DEPLOYMENT.md`.
