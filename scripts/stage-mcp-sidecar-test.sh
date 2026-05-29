#!/usr/bin/env bash
# stage-mcp-sidecar-test.sh — full §45 MCP-sidecar lifecycle vs stage RSV.
# Extends `stage-rsv-wire-test.sh` (which only hits `/verify`) by spinning
# up a local mock MCP server that talks to BOTH `/verify` AND
# `/encrypt-response`, then drives the round trip with a Rust-built client.
# See the matching CHANGELOG entry for the full step sequence.

set -u
set -o pipefail

STAGE_PROJECT="${STAGE_PROJECT:-hawcx-stage-client}"
STAGE_CLUSTER="${STAGE_CLUSTER:-hx-stage-client-gke}"
STAGE_REGION="${STAGE_REGION:-us-east1}"
STAGE_NS="${STAGE_NS:-hx-agent-authorizer}"
STAGE_SECRET="${STAGE_SECRET:-haap-rsv-secrets}"
STAGE_RSV_URL="${STAGE_RSV_URL:-https://stage-authorizer.haapidemo.com}"
REDIS_HOST="${REDIS_HOST:-10.30.0.3}"
REDIS_PORT="${REDIS_PORT:-6379}"
HELPER_POD="${HELPER_POD:-mcp-sidecar-test-redis-$$}"
MOCK_PORT="${MOCK_PORT:-9999}"
# Fresh sentinel — distinct from §1 wire test's 0xDEADBEEF.
SENTINEL_HIGH="0xCAFEBABE"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINT_BIN="${SCRIPT_DIR}/mint-helper/target/release/stage-rsv-mint"
DECRYPT_BIN="${SCRIPT_DIR}/mint-helper/target/release/stage-rsv-decrypt"
MOCK_LOG="$(mktemp -t mock-mcp.XXXXXX.log)"
export PATH="${HOME}/.cargo/bin:${PATH}"

OVERALL=0
log()  { printf '\033[1;34m[mcp-sidecar]\033[0m %s\n' "$*" >&2; }
pass() { printf '\033[1;32mPASS\033[0m: %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m: %s\n' "$*"; OVERALL=1; }

SESSION_KEY=""; MOCK_PID=""
cleanup() {
    local rc=$?
    log "cleanup: mock_pid=${MOCK_PID:-none} session_key=${SESSION_KEY:-none} (exit=${rc})"
    [[ -n "${MOCK_PID}" ]] && { kill "${MOCK_PID}" 2>/dev/null || true; wait "${MOCK_PID}" 2>/dev/null || true; }
    [[ -n "${SESSION_KEY}" ]] && kubectl exec "${HELPER_POD}" -n "${STAGE_NS}" -- \
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" DEL "${SESSION_KEY}" >/dev/null 2>&1 || true
    kubectl delete pod "${HELPER_POD}" -n "${STAGE_NS}" --wait=false >/dev/null 2>&1 || true
    [[ -f "${MOCK_LOG}" && ${rc} -ne 0 ]] && { echo "--- mock-mcp log tail ---" >&2; tail -40 "${MOCK_LOG}" >&2 || true; }
    rm -f "${MOCK_LOG}"
    exit "${rc}"
}
trap cleanup EXIT INT TERM

# ── Phase 0: preflight ─────────────────────────────────────────────
log "phase 0: preflight"
gcloud auth list --format='value(account)' --filter='status:ACTIVE' >/dev/null 2>&1 || { fail "gcloud not authed"; exit 1; }
gcloud container clusters get-credentials "${STAGE_CLUSTER}" --region "${STAGE_REGION}" --project "${STAGE_PROJECT}" >/dev/null 2>&1 \
    || { fail "kubectl get-credentials failed"; exit 1; }
for t in cargo jq curl xxd python3; do command -v "$t" >/dev/null 2>&1 || { fail "$t required"; exit 1; }; done
python3 -c "import aiohttp" 2>/dev/null || { fail "python3 -m pip install --user aiohttp"; exit 1; }

# ── Phase 1: read stage RSV config ─────────────────────────────────
SECRET_JSON="$(kubectl -n "${STAGE_NS}" get secret "${STAGE_SECRET}" -o json)"
AUDIENCE_HASH_HEX="$(echo "${SECRET_JSON}" | jq -r '.data.HAAP_AUDIENCE_HASH' | base64 -d)"
BEARER="$(echo "${SECRET_JSON}" | jq -r '.data.HAAP_RSV_AUTH_TOKEN' | base64 -d)"
[[ ${#AUDIENCE_HASH_HEX} -eq 64 ]] || { fail "audience_hash bad len"; exit 1; }
[[ ${#BEARER} -ge 32 ]] || { fail "bearer too short"; exit 1; }
[[ "$(curl -s -o /dev/null -w '%{http_code}' "${STAGE_RSV_URL}/healthz")" == "200" ]] || { fail "healthz != 200"; exit 1; }
pass "stage RSV reachable + config loaded"

# ── Phase 2: build helpers + mint token ────────────────────────────
log "phase 2: cargo build --release (mint + decrypt)"
( cd "${SCRIPT_DIR}/mint-helper" && cargo build --release ) >/dev/null 2>&1 || { fail "cargo build failed"; exit 1; }

# Bash arithmetic is signed 64-bit; `0xCAFEBABE << 32` overflows into
# negative-signed land. Hand the calculation to python3 (decimal-only).
SENTINEL_SID="$(python3 -c "import random; print((${SENTINEL_HIGH} << 32) | (random.getrandbits(32)))")"
PLAINTEXT='{"tool":"query_invoices","args":{"limit":10}}'
MINT_JSON="$("${MINT_BIN}" --audience-hash "${AUDIENCE_HASH_HEX}" --session-id "${SENTINEL_SID}" --plaintext "${PLAINTEXT}")"

SESSION_ID="$(   echo "${MINT_JSON}" | jq -r '.session_id'           )"
ISSUED_AT="$(    echo "${MINT_JSON}" | jq -r '.issued_at'            )"
EXPIRES_AT="$(   echo "${MINT_JSON}" | jq -r '.expires_at'           )"
POLICY_EPOCH="$( echo "${MINT_JSON}" | jq -r '.policy_epoch'         )"
VERIFIER_HEX="$( echo "${MINT_JSON}" | jq -r '.verifier_secret_hex'  )"
KSR_HEX="$(      echo "${MINT_JSON}" | jq -r '.k_session_root_hex'   )"
SEK_SECRET_HEX="$(echo "${MINT_JSON}" | jq -r '.sek_secret_hex'      )"
TQS_PUB_HEX="$(  echo "${MINT_JSON}" | jq -r '.tqs_public_hex'       )"
SEK_PUB_HEX="$(  echo "${MINT_JSON}" | jq -r '.sek_public_hex'       )"
RESP_KEY_HEX="$( echo "${MINT_JSON}" | jq -r '.response_key_hex'     )"
TOKEN_B64="$(    echo "${MINT_JSON}" | jq -r '.token_b64'            )"
ENCRYPTED_B64="$(echo "${MINT_JSON}" | jq -r '.encrypted_request_b64')"
AAD_B64="$(      echo "${MINT_JSON}" | jq -r '.request_aad_b64'      )"
SESSION_KEY="hawcx:session:${SESSION_ID}"
log "  session_id=${SESSION_ID}  key=${SESSION_KEY}"

# ── Phase 3: HSET substrate fields ────────────────────────────────
log "phase 3: launching helper pod ${HELPER_POD}"
kubectl run "${HELPER_POD}" -n "${STAGE_NS}" --image=redis:7-alpine --restart=Never --command -- sleep 600 >/dev/null
kubectl wait --for=condition=Ready "pod/${HELPER_POD}" -n "${STAGE_NS}" --timeout=120s >/dev/null \
    || { fail "pod not Ready"; exit 1; }

hset_bin() { kubectl exec -i "${HELPER_POD}" -n "${STAGE_NS}" -- \
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" -x HSET "${SESSION_KEY}" "$1" >/dev/null; }
u64_be() { python3 -c "import sys,struct; sys.stdout.buffer.write(struct.pack('>Q', int(sys.argv[1])))" "$1"; }

echo -n "${TQS_PUB_HEX}"    | xxd -r -p | hset_bin tqs_public
echo -n "${SEK_SECRET_HEX}" | xxd -r -p | hset_bin sek_secret
echo -n "${SEK_PUB_HEX}"    | xxd -r -p | hset_bin sek_public
u64_be $(( ISSUED_AT - 3600 ))  | hset_bin sek_valid_from
u64_be $(( EXPIRES_AT + 3600 )) | hset_bin sek_valid_until
echo -n "${VERIFIER_HEX}"   | xxd -r -p | hset_bin verifier_secret
echo -n "${KSR_HEX}"        | xxd -r -p | hset_bin k_session_root
u64_be "${POLICY_EPOCH}"        | hset_bin current_epoch
printf 'active'                 | hset_bin status
pass "substrate row provisioned"

# ── Phase 4: start mock MCP ───────────────────────────────────────
log "phase 4: starting mock MCP on :${MOCK_PORT} (log=${MOCK_LOG})"
HAAP_RSV_AUTH_TOKEN="${BEARER}" STAGE_RSV_URL="${STAGE_RSV_URL}" \
    python3 "${SCRIPT_DIR}/mock-mcp-server.py" --listen "127.0.0.1:${MOCK_PORT}" \
    --rsv-url "${STAGE_RSV_URL}" --rsv-bearer "${BEARER}" >"${MOCK_LOG}" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 20); do
    curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MOCK_PORT}/healthz" 2>/dev/null | grep -q '^200$' && break
    sleep 0.5
done
curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MOCK_PORT}/healthz" | grep -q '^200$' \
    || { fail "mock MCP never healthy"; exit 1; }
pass "mock MCP healthy"

# ── Phase 5: client → mock MCP → RSV round trip ────────────────────
log "phase 5: POST /query_invoices (acting as Assembler)"
CLIENT_RESP="$(mktemp)"
CLIENT_STATUS="$(curl -s -o "${CLIENT_RESP}" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${MOCK_PORT}/query_invoices" \
    -H "Authorization: HAAP ${TOKEN_B64}" -H "X-HAAP-AAD: ${AAD_B64}" \
    -H "Content-Type: application/octet-stream" --data-binary "${ENCRYPTED_B64}")"
CIPHERTEXT_RESP_B64="$(cat "${CLIENT_RESP}")"; rm -f "${CLIENT_RESP}"
echo "  client got status=${CLIENT_STATUS} ciphertext.len=${#CIPHERTEXT_RESP_B64}"
[[ "${CLIENT_STATUS}" == "200" ]] || { fail "client got ${CLIENT_STATUS}: ${CIPHERTEXT_RESP_B64}"; exit 1; }
pass "mock MCP returned 200 with response ciphertext"

# ── Phase 6: decrypt + assert ─────────────────────────────────────
DECRYPTED="$(printf '%s' "${CIPHERTEXT_RESP_B64}" | \
    "${DECRYPT_BIN}" --response-key "${RESP_KEY_HEX}" --session-id "${SESSION_ID}")"
echo "  decrypted=${DECRYPTED}"
# The mock MCP encodes the request plaintext as a JSON string inside
# `.result`, so inner quotes get backslash-escaped. Compare via jq so
# we're matching JSON semantics, not raw byte equality.
ACTUAL_RESULT="$(printf '%s' "${DECRYPTED}" | jq -r '.result' 2>/dev/null || echo "")"
EXPECTED_RESULT="echo: ${PLAINTEXT}"
if [[ "${ACTUAL_RESULT}" == "${EXPECTED_RESULT}" ]]; then pass "round-trip .result matches expected echo (${EXPECTED_RESULT})"
else fail "plaintext mismatch — expected_result=${EXPECTED_RESULT} got_result=${ACTUAL_RESULT}"; fi

# ── Phase 7: visible sidecar dance ────────────────────────────────
log "phase 7: mock MCP log (shows §45 cascade visible)"
grep -E '\[mock-mcp\]' "${MOCK_LOG}" || true

if [[ "${OVERALL}" -eq 0 ]]; then
    printf '\n\033[1;32m========== ALL ASSERTIONS PASSED ==========\033[0m\n'
else
    printf '\n\033[1;31m========== AT LEAST ONE FAIL ==========\033[0m\n'
fi
exit "${OVERALL}"
