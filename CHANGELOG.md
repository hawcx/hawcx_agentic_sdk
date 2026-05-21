# Changelog

All notable changes to the Hawcx Agentic SDK are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track each language surface independently (Rust crate
versions in `Cargo.toml`, Node version in `node/package.json`, Python
version in `python/pyproject.toml`).

## [v0.1.0-alpha.7] - 2026-05-21

### Security

- **C-1**: `haap-rsv` HTTP API now requires authentication on every
  endpoint except `GET /healthz`. Default transport is a Unix Domain
  Socket at `$XDG_RUNTIME_DIR/hawcx/rsv.sock` with `SO_PEERCRED` peer
  validation. TCP transport requires `--transport tcp` plus
  `HAAP_RSV_AUTH_TOKEN` (>= 32 bytes); the binary refuses to start
  with a missing or too-short token. See `docs/RSV_HTTP_API.md` for
  the rewritten threat model.
- **C-2**: `Rsv::new(config)` is replaced by `Rsv::new(config, authorizer)`
  — the authorizer is now a required parameter. `Rsv::new_alpha_permissive`
  is the explicitly-named opt-in for dev/test. `Rsv::new_from_env`
  defaults to `strict` (was: `permissive`) when `HAWCX_RSV_AUTHORIZER`
  is unset. **Breaking change** for external embedders.
- **H-1**: `HAAP_AUDIENCE_HASH` is now enforced. `Rsv::verify_and_decrypt*`
  constant-time compares the token's wire `aud_hash` against
  `RsvConfig::audience_hash` before any substrate fetch. New
  `VerifyError::AudienceMismatch` variant.
- **H-2**: `/verify` 401 bodies collapsed to a generic
  `{"error":"unauthorized"}` to close the cascade-step oracle. Full
  rejection reasons logged server-side at `debug` level. Verbose mode
  available via `HAAP_RSV_VERBOSE_ERRORS=1` (forced off under
  `HAAP_PRODUCTION_MODE=true`).
- **H-3 (BREAKING)**: `HawcxAgent.connect()` and `connect_by_agent_id()`
  now require a `principalAllowlist` (Node) / `principal_allowlist`
  (Python) parameter. The SDK validates every `actingForUser` /
  `acting_for_user` against the construction-time allowlist before
  any IPC bytes are written; out-of-list principals throw. Pass `[]`
  to forbid runtime principal switching entirely. See README "Threat
  model — runtime principal" for the full guidance.
- **H-4**: IPC client now verifies peer UID and refuses unsafe socket
  paths. `HAAP_SDK_EXPECTED_PEER_UID` pins the expected peer; the
  default is the file owner of the socket path. The Node and Python
  clients `stat` the socket parent dir and refuse to use it if
  owner-UID or mode-bits are unsafe. `/tmp/hawcx/` fallback now
  requires `HAAP_SDK_ALLOW_TMP_IPC=1` to opt in.

### Migration — H-3 breaking change

Before:

```ts
const agent = await HawcxAgent.connect(endpoint);
await agent.invoke({ actingForUser: someUser, ... });
```

After:

```ts
const agent = await HawcxAgent.connect(endpoint, {
  principalAllowlist: ["alice", "bob"], // closed set from operator config
});
await agent.invoke({ actingForUser: "alice", ... });
```

Python:

```python
with HawcxAgent.connect(endpoint, principal_allowlist=["alice", "bob"]) as agent:
    agent.invoke(target_rs_url=..., acting_for_user="alice")
```

If your deployment does not use runtime principal switching, pass
`principalAllowlist: []` / `principal_allowlist=[]` — any
`actingForUser` then raises.
