# Changelog

All notable changes to the Hawcx Agentic SDK are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track each language surface independently (Rust crate
versions in `Cargo.toml`, Node version in `node/package.json`, Python
version in `python/pyproject.toml`).

## [0.1.6] - unreleased (Python surface only)

`python/pyproject.toml` is bumped to `0.1.6`; nothing is published until a
`python-v0.1.6` tag is pushed.

- **BREAKING (#84, Ask 2): `acting_for_user` is now a required keyword-only
  argument** on `HawcxAgent.invoke`. The silent `= None` default is removed —
  omitting it raises `TypeError`. Pass an explicit `None` for an unprincipled
  call; that reproduces the pre-field wire bytes (no `acting_for_user` key), so
  wire compatibility is preserved. The silent default was the wrong-human
  default when one agent instance is shared across employees; the generator's
  constructor binding (the root defect) moves to per-call via `invoke_for`,
  paired with P0-45.

- **New subcommand `hawcx init`** (#88) — scaffolds both halves of a customer
  agent from one `hawcx/agent-template/v1`: the `@generated`
  `hawcx_tools.py` that `hawcx wrap` already emitted, plus a
  **customer-owned `config.py`** carrying the deployment values the Lane A
  core consumes (`McpTool` per tool, `PROVIDER`, `PRINCIPAL_ALLOWLIST`). With
  the Lane A core in the SDK since 0.1.5, that config was the last thing every
  customer still hand-wrote, and hand-writing it is how a fleet ends up with N
  subtly different shapes of the same file.

  **Why `init` and not `wrap --config`.** The issue left the choice open. The
  two outputs have opposite ownership — the tool module is regenerated freely,
  the config is hand-edited and must never be clobbered — and one `--force`
  cannot serve both. Here `--force` regenerates `hawcx_tools.py` only; the
  config is written when absent and **kept** otherwise, with no flag to
  overwrite it. A single flag governing both would eventually eat a config
  while someone was doing the routine thing to the module.

  **Placeholders that cannot look configured.** Every deployment-specific value
  is emitted as `FILL_ME` and the file ends in a `require_filled()` call, so an
  untouched config raises at **import** and names every unfilled path at once
  (`TOOLS['o365.mail.read'].url`, …) rather than one per traceback. A commented
  `# TODO: your RS URL` would have survived review and reached the Assembler as
  a real target. `FILL_ME` and `require_filled` are new exports on
  `hawcx_haap`, so the check is tested library code rather than a copy inlined
  into every customer's config.

  **`PRINCIPAL_ALLOWLIST` is emitted with no default**, and pinned that way by
  a test. It is the fail-closed gate on `acting_for_user`; `[]` is a real
  answer ("forbid runtime principal switching entirely") and must be a human's
  choice, not the scaffolder's. Not scaffolded on purpose: HTTP method (MCP
  `tools/call` is POST and `Caller.invoke_kwargs` sets it) and per-tool
  provider (a `Caller` carries one provider; two providers means two
  `Caller`s). The generated config imports only `hawcx_haap`, so an agent
  carrying it still bundles with `hawcx bundle`.

- **`hawcx bundle` is now reproducible on Windows** (#92). `pip install
  --target` materialises a console-script launcher per entry point under
  `bin/`. On Windows that launcher is a stub `.exe` with a zip appended, and
  the appended member is stamped with **wall-clock time** — two builds
  seconds apart produced different bytes, so the digest moved for unchanged
  input. `_normalize_mtimes` fixes filesystem mtimes and cannot reach inside
  the bytes of a generated file.

  The launchers are now dropped from the staged tree instead. Nothing is
  lost: a zipapp's exec target is the archive itself and its entry point is
  the staged `__main__.py`, so a launcher inside the archive could never
  have been executed. An agent that ships its own `bin/` keeps it — the tree
  is snapshotted before pip runs and only pip's additions are removed.

  **The bug report understated the problem, and deleting the launcher alone
  would not have fixed it.** The installing distribution's `RECORD` carries
  `sha256=` of the launcher pip generated, so the drift lived in a second
  file too. Measured here on Windows: two builds differed in **58 bytes**
  across `bin/hawcx.exe` *and*
  `hawcx_haap-0.1.5.dist-info/RECORD` — not the two bytes originally
  reported. The matching `RECORD` rows are now dropped with the launcher.

  Verified by rebuilding the same input twice on Windows: identical digest,
  zero differing bytes, and the artifact 108,627 bytes smaller.

- **Digests move with this release.** Dropping the launchers changes the
  archive on every platform, not only Windows — the POSIX text launcher goes
  too. Any bundle digest measured with 0.1.5 must be re-measured, and any
  class manifest naming one re-signed. No digest is pinned in this
  repository; `agent-bundle.yml` recomputes.
## [0.1.5] - unreleased (Python surface only)

`python/pyproject.toml` is bumped to `0.1.5`; nothing is published until a
`python-v0.1.5` tag is pushed. The bundled `hawcx-manager` version is
unchanged at `0.8.8`.

- **New module `hawcx_haap.mcp_caller`** — the Lane A integration core, lifted
  out of a customer agent (`hx_ukg_poc` PR #73) where it had no business being
  per-customer. `Caller`, `McpTool`, `Decision`, `get_agent`, `close_agent`,
  `env_principal_allowlist`, all exported from `hawcx_haap`. It builds the MCP
  JSON-RPC `tools/call` document, routes every call through `agent.invoke()`,
  and classifies the answer as an allow or a deny. Pure-Python, no new
  dependency — a consumer built on it still bundles with `hawcx bundle`.
- **Fixed on the way in: an SSE-framed denial was classified as an ALLOW.**
  Streamable HTTP may answer with an event stream, and the extracted code
  detected one by testing whether the body starts with `data:`. A real frame
  opens with `event: message`, so the check said "not a stream", no JSON-RPC
  error was found, and an HTTP 200 carrying a §45.7.5 rejection came back as a
  successful call. `_json_documents()` now tries the whole body as JSON and
  then scans every `data:` line unconditionally; `test_mcp_caller.py` pins the
  `event: message` case specifically. Written once here so no customer agent
  has to rediscover it.
- **Unclassifiable responses now deny.** A body that yields no JSON-RPC
  document — empty, truncated, HTML error page, non-UTF-8, a top-level array —
  is a `Decision(allowed=False)` rather than an allow. A denial nobody could
  parse must not read as a success. A JSON-RPC error outside the HAAP
  `-32005…-32000` range is still an allow: it is a downstream fault, and
  calling it a policy denial would manufacture a decision nobody made.

## [0.1.5] - unreleased (Node surface only)

`node/package.json` is bumped to `0.1.5`; nothing is published until a
`node-v0.1.5` tag is pushed. (Ravi's Ask-2 answer named `0.1.4`, but the
CHANGELOG dates `0.1.4` as released 2026-06-11, so the breaking change takes a
new version — revert to `0.1.4` if that tag never actually shipped.)

- **BREAKING (#84, Ask 2): `actingForUser` is now a required key** on
  `HawcxAgent.invoke`. The `?` optional is dropped (`actingForUser: string |
  null`) and a missing key throws (`actingForUser is required`). Pass `null` for
  an explicit unprincipled call — that omits the wire field (pre-field bytes),
  so wire compatibility is preserved. Removes the wrong-human default when one
  instance is shared across employees.

## [0.1.4] - 2026-06-11

Bundles **`hawcx-manager` 0.8.8**, a renewal-cadence hardening release on top of
the daemon-first model from 0.1.3 — no surprises across long-running sessions.

- **ASS-23:** root-fixed the autonomous session-renewal cadence. The periodic
  `RenewalTrigger` was anchored to the full session interval, so `since_last`
  landed just under the period on alternate ticks and the loop renewed at half
  the intended rate — long sessions could let a session lapse mid-tool-call.
  The periodic trigger now fires at `4/5` of the interval, so renewal always
  beats the session TTL with margin.
- **ASS-29:** the TQS-JIT child's upstream connect budget is now configurable
  (`HAAP_TQS_UPSTREAM_TIMEOUT_SECS`, falling back to
  `HAAP_ASSEMBLER_UPSTREAM_TIMEOUT_SECS`, default 600s) instead of a hardcoded
  30s — it waits through the JIT precompute warm-up instead of dying before the
  token pool fills.

`HAWCX_MANAGER_VERSION` bumped `0.8.7 → 0.8.8` in lockstep across all three release
workflows.

## [0.1.3] - 2026-06-10

Bundles **`hawcx-manager` 0.8.7**, which makes the **daemon-first** model work:
bring the agent-host up first (`hawcx-manager daemon start` / `haap-supervisor
run`), then `hawcx-manager enroll standard-agent` once — the rest wires itself.

- **ASS-28:** `enroll` now delivers the minted org_token straight to the running
  daemon's control socket (`MSG_REGISTER_REQ`), so the daemon registers itself and
  background renewal takes over — no external delivery script, no manual restart.
- **ASS-29:** the Assembler's upstream (TQS) connect budget is configurable
  (`HAAP_ASSEMBLER_UPSTREAM_TIMEOUT_SECS`, default 600s) instead of a hardcoded
  30s, so it waits through the human-paced device-flow enrollment instead of dying
  before the agent registers.
- **ASS-29:** `HAAP_MANAGER_TOKEN_STORE=file|keyring|auto` override — unattended /
  daemon-first enroll can force the encrypted-file token store, skipping the macOS
  keychain prompt and its duplicate-item collision on repeat enrollments.

- **ASS-29 (0.8.7):** `cfg`-gate the control-socket delivery to Unix + add a Windows
  stub — 0.8.6 used `tokio::net::UnixStream` unconditionally and failed the Windows
  build, so 0.8.6 never shipped through the SDK; 0.8.7 builds on every platform.

`HAWCX_MANAGER_VERSION` bumped `0.8.5 → 0.8.7` in lockstep across all three release
workflows.

## [0.1.1] - 2026-06-09

Bundles **`hawcx-manager` 0.8.5**, which adds the **`daemon`** subcommand
(`install | uninstall | start | stop | status | logs`) — run the agent-host as a
background OS service (launchd/systemd) instead of by hand (ASS-19) — and fixes
a **Windows-only build break** in `haap-assembler-bin` (the `#[cfg(windows)]`
`handle_agent_message` call site was missing the `rs_proxy_url` /
`rs_proxy_auth_token` args added in ASS-15, so the Windows wheels failed to
compile). `HAWCX_MANAGER_VERSION` bumped `0.8.2 → 0.8.5` in lockstep across all
three release workflows. Final (non-prerelease) version, so `pip install
hawcx-haap` / `npm install @hawcx/hawcx-haap` resolve to it without `--pre` or a
version pin.

## [v0.1.0-alpha.10] - 2026-05-22

Re-tag of the alpha.9 content on top of #18's smoke-test fix.

The `v0.1.0-alpha.9` tag was pushed early (at commit `9c3f557`, the
merge of #17) **before** #18 was merged. The resulting release run
succeeded and published 5 tarballs, but those artifacts pre-date the
smoke-test self-skip fix from #18, so the alpha.9 run still showed
the bundle smoke test as red (with the old "denied" error). Rather
than retarget the immutable alpha.9 tag and create an artifact/tag
mismatch, this release supersedes alpha.9 cleanly.

Contents are identical to what alpha.9 intended to ship: PRs #17 +
#18. No protocol, SDK API, or runtime behavior changes vs. alpha.8.

### Build / Release / CI

- **Language-binding test portability** (#17): the `release-node` and
  `release-python` workflows now go green on Windows and Linux.
  - Python (`python/tests/conftest.py`): the `short_sock_path`
    fixture now skips on Windows, matching the existing
    `mock_assembler` precedent. Closes the
    `AttributeError: module 'socket' has no attribute 'AF_UNIX'`
    failures on Windows py3.10–3.13.
  - Node (`node/tests/ipc.test.ts`, `node/tests/agent.test.ts`):
    the UDS-using `describe` blocks are wrapped with
    `describe.skipIf(process.platform === "win32")`, closing the
    Windows `EACCES` failures. The two `AssemblerClient handshake
    validation` tests now create their own per-user temp dirs via
    `fs.mkdtempSync(..., { mode: 0o700 })` instead of dropping
    sockets into `/tmp`, closing the Linux regression introduced by
    the H-3 / M-3 parent-dir hardening in alpha.7.
- **Bundle smoke test signal** (#18): the `bundle_smoke_test` job
  no longer goes red on every release tag. `docker/bundle/smoke-test.sh`
  pre-checks `docker manifest inspect ghcr.io/hawcx/hx-caa:${HAAP_VERSION}`
  before `docker compose pull`. If the matching CAA tag isn't
  published yet, the script exits 0 with a clear explanation. The
  workflow drops `continue-on-error: true`, so any OTHER smoke
  failure (compose syntax, entrypoint break, env validation crash,
  port collision) now correctly blocks the release.

Behavioral matrix for the smoke job after alpha.10:

| Condition | Smoke job |
|---|---|
| SDK tagged; matching `hx-caa` tag not yet published | ✓ (skip message in logs) |
| SDK + `hx-caa` tagged at same version | runs end-to-end; ✓ on success, ✗ on real failure |
| Real structural break at any time | ✗ (blocks the release) |

The next time `hx_agent_client_admin_service` publishes a matching
`hx-caa:v0.1.0-alpha.X` tag and an SDK tag is pushed at the same
version, the smoke job will exercise the bundle end-to-end.

## [v0.1.0-alpha.8] - 2026-05-21

Release-pipeline fixes only. No protocol, SDK API, or runtime
behavior changes vs. alpha.7.

### Build / Release

- **Linux runners** (#15): install `libdbus-1-dev` + `pkg-config`
  before `cargo build`. Closes the alpha.7 build failure where the
  `keyring` crate (used by `haap-keystore`'s `KeyringUakStore` per
  CS v7.2.5 §35.8 — UAK in OS credential storage) transitively
  pulled `libdbus-sys` without the apt package being present.
- **Windows targets** (#16): restored `x86_64-pc-windows-msvc` and
  `aarch64-pc-windows-msvc` to the release matrix. The agent-side
  runtime (supervisor + the 5 protected children: authenticator,
  tqs-precompute, tqs-jit, assembler, eib) now ships Windows
  binaries alongside Linux and macOS. Per-platform IPC trust model:
  - Linux / macOS: UDS + `SO_PEERCRED` / `LOCAL_PEERCRED`
    (CS v7.2.5 §39.12.1).
  - Windows: Named Pipes with DACL restricting to current user SID
    + SYSTEM, `FILE_FLAG_FIRST_PIPE_INSTANCE`,
    `reject_remote_clients(true)` — implementation in
    `hx_labs::haap_ipc::win_dacl` (CS v7.2.5 §39.12.2).
- **`haap-rsv` stays Unix-only** (#16): the MCP server-side
  verifier sidecar continues to ship Linux + macOS only. It uses
  UDS + peer-credential checks for the local-sidecar trust model
  collocated with the MCP server. Windows agents do not need it;
  server operators deploy it as a Linux container.
- **`haap-sdk-ipc` portability** (#16): UDS listener / peer-cred
  modules gated behind `#[cfg(unix)]`. The crate is SDK-internal
  (CLI ↔ helpers, not on the protocol surface per
  `docs/ARCHITECTURE.md` §IPC); on Windows it builds as a stub
  exposing `error` / `framing` / `paths` only. Named-pipe parity
  via `hx_labs::haap_ipc::win_dacl` is a follow-up.

### Per-platform binary set

| Target | Agent-side runtime (supervisor + 5) | `haap-sdk` CLI | `haap-rsv` (MCP sidecar) |
|---|:-:|:-:|:-:|
| x86_64-unknown-linux-gnu | ✓ | ✓ | ✓ |
| aarch64-unknown-linux-gnu | ✓ | ✓ | ✓ |
| aarch64-apple-darwin | ✓ | ✓ | ✓ |
| x86_64-pc-windows-msvc | ✓ | ✓ | ✗ |
| aarch64-pc-windows-msvc | ✓ | ✓ | ✗ |

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
