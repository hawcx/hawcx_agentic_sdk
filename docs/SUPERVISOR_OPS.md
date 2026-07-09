# Operating the agent-host (`hawcx-manager` supervisor)

The Supervisor is the `supervisor` role of the `hawcx-manager`
multicall binary (`hawcx-manager supervisor`, invoked via the
`haap-supervisor` legacy-name symlink), built from
`hx_agent_client_auth_service`, not the SDK. This doc captures the
operational surface customers care about. For internals see the
`hx_agent_client_auth_service` Supervisor source
(`crates/haap-supervisor/`).

## Running it

The recommended way to run the agent-host is as a background OS
service via the `daemon` subcommand (SDK 0.1.1+, ASS-19):

```bash
hawcx-manager daemon install    # install + start (idempotent)
hawcx-manager daemon status     # installed/running + socket paths
hawcx-manager daemon logs -f    # tail the daemon log
hawcx-manager daemon stop       # stop, leave installed
hawcx-manager daemon uninstall  # stop + remove
```

- **macOS:** launchd user agent (`com.hawcx.agent`, `KeepAlive` —
  restarts on crash, starts on login).
- **Linux:** `systemd --user` unit (`Restart=on-failure`).
- **Windows:** the `daemon` subcommand is not available yet; use the
  supervisor's own SCM integration instead
  (`haap-supervisor install | uninstall | run`).

The service execs `haap-supervisor run`, sources operator env vars
from `~/.hawcx/agent.env`, and writes its log to
`~/.hawcx/logs/agent.log`.

For foreground development runs, invoke the supervisor role
directly:

```bash
haap-supervisor run     # or: hawcx-manager supervisor run
```

### Ordering: daemon first, then enroll

Since SDK 0.1.3 (ASS-28) the model is **daemon-first**: bring the
agent-host up, then enroll once —

```bash
hawcx-manager daemon install
hawcx-manager enroll <agent-class>     # e.g. standard-agent
```

`enroll` delivers the minted org_token straight to the running
daemon's control socket (`MSG_REGISTER_REQ`), the daemon registers
itself, and background session renewal takes over — no external
delivery script, no manual restart. If no daemon is running, `enroll`
falls back to printing the bundle for manual delivery.

## Configuration

The Supervisor reads a TOML config file. Path resolution:

1. `$HAWCX_CONFIG` env var, if set;
2. otherwise the platform default — `/etc/hawcx/haap/config.toml`
   (Unix) or `C:\ProgramData\Hawcx\HAAP\config.toml` (Windows);
3. otherwise it fails with an error naming the attempted path.

The config carries the org identity, IPC directory, orchestrator
block, optional registration block, and an `[[agents]]` roster — one
entry per agent the Supervisor hosts:

```toml
employee_id = "emp-1"
org_id = "org-1"
ipc_dir = "/tmp/hawcx"

[orchestrator]
socket_dir = "/tmp/haap-orch"
idp_endpoint = "https://localhost:8443"
mtls_cert_path = "/etc/haap/orch.crt"
mtls_key_path = "/etc/haap/orch.key"
zeroize_timer_secs = 28800

[[agents]]
agent_id = "research-u1"
auth_uuid = "00000000000000000000000000000001"
subject_user_id = "00000000-0000-0000-0000-000000000001"
agent_class = "research"
pool_size = 1
max_assemblers = 4
auth_bin = "haap-authenticator"
tqs_precompute_bin = "haap-tqs-precompute"
tqs_jit_bin = "haap-tqs-jit"
assembler_bin = "haap-assembler"
agent_bin = "agent-llm"
```

Child binary paths are per-agent config fields (`auth_bin`,
`tqs_precompute_bin`, `tqs_jit_bin`, `assembler_bin`, `agent_bin`),
not a `$PATH` convention — set them to the legacy-name symlinks (as
above) or to absolute paths. Optional per-agent blocks:

- `[agents.eib]` — spawn an External Identity Broker for this agent
  (Pattern Z, HAAP CS §45). No block → no EIB process.
- `[agents.nim_provider]` — spawn the NVIDIA NIM provider sidecar
  (Pattern Y, HAAP CS §47). No block → no sidecar.

An optional top-level `[registration]` block (AS URL, admin
Authenticator URL, pinned `IK_sp` values, policy bundle path) is
injected into child Authenticator environments as `HAAP_*` env vars.

## Lifecycle

For each `[[agents]]` roster entry the Supervisor spawns, in order:

1. `hawcx-manager authenticator` (`haap-authenticator`)
2. `hawcx-manager tqs-precompute` (`haap-tqs-precompute`)
3. `hawcx-manager tqs-jit` (`haap-tqs-jit`)
4. `hawcx-manager assembler` (`haap-assembler`) — a pool of
   `pool_size` (capped at `max_assemblers`)
5. `hawcx-manager eib` (`haap-eib`) — only when `[agents.eib]` is
   configured (Pattern Z, §45.2)
6. `haap-nim-provider` — only when `[agents.nim_provider]` is
   configured (Pattern Y, §47)

Each child is the same `hawcx-manager` binary invoked with a
different role subcommand (or its legacy-name symlink). Each child
must bring up its UDS before the next is spawned. If any child fails
to start within the configured timeout (default 30s), the Supervisor
SIGTERMs the already-running children and exits with a non-zero
status.

## Health

- `hawcx-manager daemon status` reports whether the service is
  installed/running and lists its socket paths.
- Each child exits with status 0 on graceful shutdown and non-zero
  otherwise. The Supervisor watches each child via `wait()` and
  re-raises an exit status if any child dies unexpectedly.
- Restart-on-crash comes from the OS service manager (launchd
  `KeepAlive` / systemd `Restart=on-failure`) when running under
  `daemon install`; a foreground `haap-supervisor run` does not
  restart itself.

## Shutdown

`hawcx-manager daemon stop` (or SIGTERM to a foreground run) shuts
down gracefully: the Supervisor SIGTERMs its children in reverse
dependency order (agent → nim-provider → eib → assemblers → tqs-jit
→ tqs-precompute → authenticator, then the orchestrator), waits a
grace period (default 5s), SIGKILLs any stragglers, and cleans up
the sockets.

`kill -9` (SIGKILL) bypasses this; use only when graceful shutdown
hangs.

## Logs

All child processes write structured logs (JSON) to stderr. Under
`daemon install` these land in `~/.hawcx/logs/agent.log`
(`hawcx-manager daemon logs -f` to follow); standard log collectors
(Fluent Bit, Vector, Datadog Agent, etc.) can consume them. Set
`RUST_LOG=info` (or `debug` / `trace` for finer detail).

## Common operations

### Verify the pipeline is alive

```bash
hawcx-manager daemon status   # installed/running + socket paths
ls <ipc_dir>/<agent_id>/      # per-agent Assembler sockets
```

### Rotate the identity bundle

```bash
# Stop the daemon:
hawcx-manager daemon stop

# Update the sealed bundle (dev/testing only — use the `haap-sdk seal`
# debug helper; production deployments have their secret-management
# system push a new sealed file):
haap-sdk seal --input new-identity.json --output /var/lib/hawcx/agent.sealed

# Restart:
hawcx-manager daemon start
```

### Inspect the substrate (dev/debug helper)

```bash
HAAP_CUSTOMER_REDIS_URL=redis://... \
    haap-sdk substrate-fetch 1234567890
```

## Reference

For the full Supervisor process graph, pool semantics, and
`SetSessionContext` IPC details, see the
`hx_agent_client_auth_service::haap-supervisor` crate source.
