#!/usr/bin/env bash
#
# Wire-level e2e smoke test against the local bundle's deployed
# haap-rsv image. Drives real HTTP traffic, injects a SessionRecord
# into the bundle's Redis, mints a token + AEAD body, hits /verify,
# asserts the cascade round-trips and the tamper cases all 401.
#
# Operator wrapper around the Rust engine:
#   hx_agent_authorizer/crates/haap-rsv-bin/tests/wire_e2e_against_deployed_bundle.rs
#
# Re-runnable without cleanup — each run generates a clock-derived
# session_id; the engine's RAII guard DELs its substrate row on drop.
#
# Exit codes: 0 pass; 1 setup error; 2 test failure.
#
# Usage:
#   ./wire-e2e-test.sh
#   HAAP_RSV_URL=http://localhost:8443 ./wire-e2e-test.sh
#   AUTHORIZER_REPO=/path/to/hx_agent_authorizer ./wire-e2e-test.sh

set -euo pipefail

# ── Locate paths ────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${SCRIPT_DIR}"

# Default to sibling-checkout layout (workspace/hx_agent_authorizer).
# Override via AUTHORIZER_REPO for non-standard layouts.
AUTHORIZER_REPO_DEFAULT="$(cd "${BUNDLE_DIR}/../../.." && pwd)/hx_agent_authorizer"
AUTHORIZER_REPO="${AUTHORIZER_REPO:-${AUTHORIZER_REPO_DEFAULT}}"

ENV_FILE="${BUNDLE_DIR}/.env"

# ── Output helpers ──────────────────────────────────────────────────

GREEN=$(printf '\033[0;32m')
RED=$(printf '\033[0;31m')
YELLOW=$(printf '\033[0;33m')
BOLD=$(printf '\033[1m')
RESET=$(printf '\033[0m')

ok()   { printf "%s[ OK ]%s %s\n"   "${GREEN}" "${RESET}" "$*"; }
warn() { printf "%s[WARN]%s %s\n"   "${YELLOW}" "${RESET}" "$*" >&2; }
fail() { printf "%s[FAIL]%s %s\n"   "${RED}"   "${RESET}" "$*" >&2; }
hdr()  { printf "\n%s== %s ==%s\n"  "${BOLD}"   "$*"   "${RESET}"; }

# ── Preflight ───────────────────────────────────────────────────────

hdr "Preflight"

if ! command -v docker >/dev/null 2>&1; then
    fail "docker not on PATH"; exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
    if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
        export PATH="${HOME}/.cargo/bin:${PATH}"
    else
        fail "cargo not on PATH; install Rust or set PATH"; exit 1
    fi
fi
ok "docker + cargo on PATH"

if [[ ! -f "${ENV_FILE}" ]]; then
    fail "bundle .env not found at ${ENV_FILE}"
    fail "copy .env.example to .env and edit, or run smoke-test.sh first"
    exit 1
fi
ok ".env present at ${ENV_FILE}"

if [[ ! -d "${AUTHORIZER_REPO}/crates/haap-rsv-bin" ]]; then
    fail "haap-rsv-bin not found at ${AUTHORIZER_REPO}/crates/haap-rsv-bin"
    fail "set AUTHORIZER_REPO to the hx_agent_authorizer checkout"
    exit 1
fi
ok "authorizer repo at ${AUTHORIZER_REPO}"

# Pull env values from .env without sourcing (operator-edited; may
# contain `export` / comments we don't want to evaluate).
extract_env() {
    local key="$1"
    grep -E "^${key}=" "${ENV_FILE}" \
        | head -1 \
        | sed -E "s/^${key}=//; s/^['\"]//; s/['\"]$//"
}

RSV_TOKEN="${HAAP_RSV_AUTH_TOKEN:-$(extract_env HAAP_RSV_AUTH_TOKEN)}"
AUD_HASH="${HAAP_AUDIENCE_HASH:-$(extract_env HAAP_AUDIENCE_HASH)}"
RSV_URL="${HAAP_RSV_URL:-http://localhost:8443}"

if [[ -z "${RSV_TOKEN}" ]]; then
    fail "HAAP_RSV_AUTH_TOKEN missing from .env or environment"; exit 1
fi
if [[ -z "${AUD_HASH}" || "${#AUD_HASH}" -ne 64 ]]; then
    fail "HAAP_AUDIENCE_HASH must be 64 hex chars (got ${#AUD_HASH})"; exit 1
fi
ok "bearer token (${#RSV_TOKEN} bytes) + audience hash present"

if ! (cd "${BUNDLE_DIR}" && docker compose ps --status running 2>/dev/null | grep -q hawcx-rsv); then
    warn "RSV container not running — attempting docker compose up -d"
    (cd "${BUNDLE_DIR}" && docker compose up -d) || {
        fail "docker compose up failed; bring the bundle up manually"; exit 1
    }
fi

for attempt in 1 2 3 4 5; do
    if curl -sS -o /dev/null -m 2 -w "" "${RSV_URL}/healthz" 2>/dev/null; then
        ok "RSV /healthz reachable at ${RSV_URL}"
        break
    fi
    if [[ "${attempt}" == 5 ]]; then
        fail "RSV /healthz unreachable at ${RSV_URL} after 5 tries"; exit 1
    fi
    sleep 1
done

# ── Run the engine ──────────────────────────────────────────────────

hdr "Running wire-e2e cases via cargo test"

LOG_FILE="$(mktemp -t wire-e2e-test.XXXXXX.log)"
trap 'rm -f "${LOG_FILE}"' EXIT

set +e
(cd "${AUTHORIZER_REPO}" && \
    HAAP_RSV_URL="${RSV_URL}" \
    HAAP_RSV_AUTH_TOKEN="${RSV_TOKEN}" \
    HAAP_AUDIENCE_HASH="${AUD_HASH}" \
    HAAP_RSV_REDIS_COMPOSE_DIR="${BUNDLE_DIR}" \
    cargo test \
        -p haap-rsv-bin \
        --test wire_e2e_against_deployed_bundle \
        -- --ignored --nocapture --test-threads=1 \
        > "${LOG_FILE}" 2>&1)
TEST_EXIT=$?
set -e

# Echo cargo output so operators see per-case `[wire-e2e]` markers.
cat "${LOG_FILE}"

hdr "Result"

RESULT_LINE="$(grep -E '^test result:' "${LOG_FILE}" | tail -1 || true)"

if [[ "${TEST_EXIT}" == 0 ]] && [[ "${RESULT_LINE}" == *"ok."* ]]; then
    ok "${RESULT_LINE}"
    ok "wire-e2e: PASS"
    exit 0
fi

fail "${RESULT_LINE:-<no cargo result line; build may have failed>}"
fail "wire-e2e: FAIL — see cargo output above"
# TEST_EXIT==0 with no pass line = build broke; distinguish from runtime fail.
if [[ "${TEST_EXIT}" == 0 ]]; then exit 1; fi
exit 2
