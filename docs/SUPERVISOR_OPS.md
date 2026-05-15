# Operating `haap-supervisor`

The Supervisor is part of `hx_labs`, not the SDK. This doc captures
the operational surface customers care about. For internals see the
`hx_labs` Supervisor source.

## Lifecycle

The Supervisor spawns four child processes in order:

1. `haap-auth-bin` (Authenticator)
2. `haap-tqs-precompute-bin`
3. `haap-tqs-jit-bin`
4. `haap-assembler-bin`

Each child must bring up its UDS before the next is spawned. If any
child fails to start within the configured timeout (default 30s),
the Supervisor SIGTERMs the already-running children and exits with
a non-zero status.

## Configuration

The Supervisor reads its child-binary paths from `$PATH`. To use
binaries from a non-standard location, prepend that directory to
`$PATH` or symlink them into `/usr/local/bin`.

Env vars passed to children: the Supervisor forwards all `HAAP_*`
env vars unchanged. Children read what they need.

## Health

- Each child exits with status 0 on graceful shutdown and non-zero
  otherwise.
- The Supervisor watches each child via `wait()` and re-raises an
  exit status if any child dies unexpectedly.
- Restart-on-crash is opt-in (per `hx_labs` Supervisor config).

## Shutdown

`haap-supervisor` handles SIGTERM gracefully:

1. Stop accepting new requests at the Assembler.
2. Drain in-flight requests (max one — single-flight is enforced).
3. SIGTERM each child in reverse order.
4. Exit when all children have exited.

`kill -9` (SIGKILL) bypasses this; use only when graceful shutdown
hangs.

## Logs

All child processes write structured logs (JSON) to stderr. Standard
log collectors (Fluent Bit, Vector, Datadog Agent, etc.) consume
them. Set `RUST_LOG=info` (or `debug` / `trace` for finer detail).

## Common operations

### Verify the pipeline is alive

```bash
# The Assembler exposes a health endpoint (hx_labs detail):
curl http://127.0.0.1:7443/healthz  # adjust port per HAAP_SUPERVISOR_LISTEN
```

### Rotate the identity bundle

```bash
# Stop the supervisor:
kill -TERM <pid>

# Update the sealed bundle (use the SDK's `haap-sdk seal` for testing,
# or have your secret-management system push a new sealed file):
haap-sdk seal --input new-identity.json --output /var/lib/hawcx/agent.sealed

# Restart:
haap-supervisor
```

### Inspect the substrate

```bash
HAAP_CUSTOMER_REDIS_URL=redis://... \
    haap-sdk substrate-fetch 1234567890
```

## Reference

For the full Supervisor process graph, pool semantics, and
`SetSessionContext` IPC details, see the `hx_labs::haap-supervisor`
crate source.
