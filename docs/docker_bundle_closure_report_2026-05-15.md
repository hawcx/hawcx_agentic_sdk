# Docker Bundle Closure Report

**Date:** 2026-05-17
**Branch:** feature/docker-bundle-2026-05-15
**PR:** see GitHub PR for hx_agentic_sdk feature/docker-bundle-2026-05-15

## What landed

### docker/bundle/

- **docker-compose.yml** — four services: `caa-admin-auth`, `caa`, `rsv`, `redis`,
  on a bridge network with named volumes for IPC and CAA state
- **.env.example** — documented configuration; required values are blank
  placeholders so customers see what they need to provide
- **README.md** — quickstart, architecture explanation (two-process CAA,
  distroless basis, no Postgres), troubleshooting, scope disclaimers
- **smoke-test.sh** — brings the bundle up, polls `/healthz` on RSV and
  `PING` on Redis, soft-probes CAA gRPC; auto-teardown under `CI=1`

### Release workflow integration

- `.github/workflows/release.yml` release notes now mention `docker/bundle/`
- New job `bundle_smoke_test` runs on tag push, depends on `docker_manifest`,
  runs `smoke-test.sh` with `CI=1`, marked `continue-on-error: true`

## How customers use this

1. Clone the SDK repo at the release tag
2. `cp docker/bundle/.env.example docker/bundle/.env`
3. Fill in tenant credentials in `.env` (`HAWCX_ORG_ID`, `HAWCX_IK_C`,
   `HAAP_BOOTSTRAP_OTRC`, `HAAP_AUDIENCE_HASH`)
4. `docker compose -f docker/bundle/docker-compose.yml up`
5. CAA gRPC reachable on `localhost:9443`, RSV HTTP on `localhost:8443`

## Deviations from the original prompt template

The Phase 0 preflight against actual binaries surfaced several mismatches
between the prompt's docker-compose template and reality. Documented here
because the bundle architecture diverged enough to be worth flagging.

| Prompt template | Reality | Resolution |
|---|---|---|
| `HAAP_CAA_REDIS_URL` env var | CAA doesn't use Redis in alpha-1 | Dropped from compose |
| `HAAP_CAA_POSTGRES_URL` env var | CAA uses file-based state dir | Dropped Postgres service entirely |
| `HAAP_RSV_LISTEN_ADDR` | Actual var is `HAAP_RSV_LISTEN` | Corrected |
| `HAAP_RSV_AUDIENCE_ID` | Actual var is `HAAP_AUDIENCE_HASH` (64-hex bytes) | Corrected |
| `HAAP_RSV_REDIS_URL` | Actual var is `HAAP_CUSTOMER_REDIS_URL` | Corrected |
| `HAAP_RSV_AS_ENDPOINT` | RSV verifies tokens locally; no AS endpoint var | Dropped |
| `HAAP_CAA_ADMIN_AUTH_LISTEN_ADDR` | admin-auth communicates over Unix socket, not TCP | Dropped |
| Single `caa` container | orchestrator does NOT spawn admin-auth — `main.rs:90` reads "ensure haap-admin-auth-bin is running at {ipc_path}" | Split into `caa-admin-auth` + `caa`, sharing `/var/run/hawcx` via `caa_ipc` volume |
| Healthchecks invoking `--health-check` flag | Neither binary supports the flag; distroless base has no shell | Healthchecks disabled on CAA/RSV; smoke test verifies from host via `/healthz` + Redis `PING` |
| Sealer config in RSV compose | `Rsv::new` only opens Redis; sealer wired elsewhere | Removed `HAAP_SEALER_*` from compose, env, and README |

These were judgment calls made during Phase 1 — none required halting per the
prompt's failure-handling criteria (images verified, env vars expressible, no
healthcheck blocker that couldn't be worked around).

## Scope clarifications

- **Evaluation only**: bundle is not production-ready. No TLS termination, no
  HA, no Helm. Production deployment guide deferred to v0.2.
- **No AS included**: bundle points to Hawcx's AS by default (`HAAP_AS_URL`).
  Customers running their own AS override the env var.
- **No agent runtime**: customers run their own agents. The Python SDK for
  CrewAI integration ships with Priority 2.
- **Smoke test is soft on CAA**: with throwaway placeholders for IK_c, the
  admin-auth process can't decode the key and exits, leaving the orchestrator
  unable to bind its gRPC port. The smoke test reports this as a soft probe
  and only fails hard on RSV `/healthz` + Redis `PING`. Real CAA functional
  validation requires customer-provisioned tenant credentials.

## What this enables

- Customers can evaluate HAAP without Kubernetes setup
- CrewAI examples (Priority 2) can `docker compose up` for their backend
- Sales demos run on a laptop
- The release workflow's bundle smoke test catches structural regressions
  (image manifest, entrypoint, env-var contract) on every tag push

## Known follow-ups

- Smoke test currently uses throwaway IK_c. A future improvement is to wire
  test tenant credentials into the CI environment so the CAA gRPC probe
  becomes a hard pass.
- Production deployment guide and Helm charts (post-v0.2)
- TLS termination via a reverse proxy in the bundle (post-v0.2, optional)
