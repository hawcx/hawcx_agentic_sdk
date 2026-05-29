#!/usr/bin/env bash
# stage-rsv-wire-test.sh — drive REAL HTTPS traffic through stage RSV
# (https://stage-authorizer.haapidemo.com) and prove the §9 cascade
# decodes a HAAP token + decrypts an AEAD body on the wire.
#
# What this script does, in order:
#
#   1. Reads `HAAP_AUDIENCE_HASH` and `HAAP_RSV_AUTH_TOKEN` from the
#      stage RSV's k8s secret (`haap-rsv-secrets`). The audience hash is
#      bound into the wire token; the bearer gates the HTTPS endpoint.
#   2. Builds `scripts/mint-helper` (cargo + cargo.hawcx.com) which mints
#      a token, derives a `k_session_root`, and AEAD-encrypts a body
#      with a matching `response_key`. Output is a JSON blob.
#   3. Launches a temporary `redis:7-alpine` pod in the stage GKE cluster
#      and HSETs the substrate fields the cascade reads (see
#      `hx_agent_crypto_core/crates/haap-redis/src/key_table.rs`) into
#      `hawcx:session:<sentinel>`. Sentinel id has 0xDEAD_BEEF prefix so
#      it cannot collide with real production sessions.
#   4. POSTs `/verify` with the token + encrypted body + AAD. Expects
#      200 with a `plaintext_b64` that decodes to the original input.
#   5. Tamper proofs (each MUST return 401):
#        - ciphertext byte flip
#        - bearer flip
#        - session record absent (DEL substrate, retry)
#   6. Cleanup: DEL the substrate row and delete the helper pod.
#
# Stage access prerequisites (verified at script start):
#   - gcloud authed as a human with `hawcx-stage-client` reader access
#     (the stage RSV lives in this project, NOT `hawcx-staging`).
#   - kubectl available; the script `get-credentials` itself.
#   - cargo on PATH with the `hawcx` registry credential configured
#     (~/.cargo/credentials.toml [registries.hawcx] token = "...").
#
# Cleanup is run from a trap so the substrate row is dropped even on
# script failure or Ctrl-C. The script exits non-zero on the first
# failing assertion and prints a "FAIL: <reason>" line.

set -u
set -o pipefail
# NB: we deliberately do NOT use `set -e` — every assertion needs to
# run so we can print PASS/FAIL for each, and the trap-driven cleanup
# needs the script to keep going after a failed step.

# ── Configuration ──────────────────────────────────────────────────

STAGE_PROJECT="${STAGE_PROJECT:-hawcx-stage-client}"
STAGE_CLUSTER="${STAGE_CLUSTER:-hx-stage-client-gke}"
STAGE_REGION="${STAGE_REGION:-us-east1}"
STAGE_NS="${STAGE_NS:-hx-agent-authorizer}"
STAGE_SECRET="${STAGE_SECRET:-haap-rsv-secrets}"
STAGE_RSV_URL="${STAGE_RSV_URL:-https://stage-authorizer.haapidemo.com}"
REDIS_HOST="${REDIS_HOST:-10.30.0.3}"
REDIS_PORT="${REDIS_PORT:-6379}"
HELPER_POD="${HELPER_POD:-rsv-wire-test-redis-$$}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINT_HELPER_DIR="${SCRIPT_DIR}/mint-helper"
MINT_BIN="${MINT_HELPER_DIR}/target/release/stage-rsv-mint"

# Cargo on PATH if invoked from a sterile shell.
export PATH="${HOME}/.cargo/bin:${PATH}"

# Final exit status: 0 means every assertion passed.
OVERALL=0

# ── Logging helpers ───────────────────────────────────────────────

log()  { printf '\033[1;34m[wire-test]\033[0m %s\n' "$*" >&2; }
pass() { printf '\033[1;32mPASS\033[0m: %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m: %s\n' "$*"; OVERALL=1; }

# ── Cleanup trap ──────────────────────────────────────────────────

SESSION_KEY=""
cleanup() {
    local exit_code=$?
    log "cleanup: dropping substrate row + helper pod (exit=${exit_code})"
    if [[ -n "${SESSION_KEY}" ]]; then
        kubectl exec "${HELPER_POD}" -n "${STAGE_NS}" -- \
            redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" DEL "${SESSION_KEY}" \
            >/dev/null 2>&1 || true
    fi
    kubectl delete pod "${HELPER_POD}" -n "${STAGE_NS}" --wait=false \
        >/dev/null 2>&1 || true
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# ── Phase 0 — preflight ──────────────────────────────────────────

log "preflight: gcloud auth + kubectl creds"
gcloud auth list --format='value(account)' --filter='status:ACTIVE' \
    >/dev/null 2>&1 || { fail "gcloud not authed"; exit 1; }
gcloud container clusters get-credentials "${STAGE_CLUSTER}" \
    --region "${STAGE_REGION}" --project "${STAGE_PROJECT}" >/dev/null 2>&1 \
    || { fail "kubectl get-credentials failed (cluster=${STAGE_CLUSTER})"; exit 1; }

command -v cargo >/dev/null 2>&1 || { fail "cargo not on PATH"; exit 1; }
command -v jq    >/dev/null 2>&1 || { fail "jq required"; exit 1; }
command -v curl  >/dev/null 2>&1 || { fail "curl required"; exit 1; }
command -v xxd   >/dev/null 2>&1 || { fail "xxd required"; exit 1; }

# ── Phase 1 — read stage RSV config ───────────────────────────────

log "phase 1: reading audience_hash + bearer from k8s secret ${STAGE_NS}/${STAGE_SECRET}"
SECRET_JSON="$(kubectl -n "${STAGE_NS}" get secret "${STAGE_SECRET}" -o json)"
AUDIENCE_HASH_HEX="$(echo "${SECRET_JSON}" | jq -r '.data.HAAP_AUDIENCE_HASH' | base64 -d)"
BEARER="$(echo "${SECRET_JSON}" | jq -r '.data.HAAP_RSV_AUTH_TOKEN' | base64 -d)"

if [[ ${#AUDIENCE_HASH_HEX} -ne 64 ]]; then
    fail "audience_hash is not 64 hex chars (got len=${#AUDIENCE_HASH_HEX})"; exit 1
fi
if [[ ${#BEARER} -lt 32 ]]; then
    fail "bearer token shorter than 32 bytes — would be rejected by RSV"; exit 1
fi
log "  audience_hash=${AUDIENCE_HASH_HEX}"
log "  bearer.len=${#BEARER} (redacted)"

log "  stage RSV URL: ${STAGE_RSV_URL}"
HEALTHZ="$(curl -s -o /dev/null -w '%{http_code}' "${STAGE_RSV_URL}/healthz")"
if [[ "${HEALTHZ}" != "200" ]]; then
    fail "healthz returned ${HEALTHZ}; aborting"; exit 1
fi
pass "/healthz reachable (HTTP 200)"

# ── Phase 2 — build mint helper + mint a token ───────────────────

log "phase 2: building mint helper (release)"
( cd "${MINT_HELPER_DIR}" && cargo build --release ) >/dev/null 2>&1 \
    || { fail "cargo build of mint-helper failed (run 'cd ${MINT_HELPER_DIR} && cargo build --release' for diagnostics)"; exit 1; }

log "phase 2: minting token + AEAD body"
MINT_JSON="$("${MINT_BIN}" --audience-hash "${AUDIENCE_HASH_HEX}")"

SESSION_ID="$(   echo "${MINT_JSON}" | jq -r '.session_id'              )"
ISSUED_AT="$(    echo "${MINT_JSON}" | jq -r '.issued_at'               )"
EXPIRES_AT="$(   echo "${MINT_JSON}" | jq -r '.expires_at'              )"
POLICY_EPOCH="$( echo "${MINT_JSON}" | jq -r '.policy_epoch'            )"
VERIFIER_HEX="$( echo "${MINT_JSON}" | jq -r '.verifier_secret_hex'     )"
KSR_HEX="$(      echo "${MINT_JSON}" | jq -r '.k_session_root_hex'      )"
SEK_SECRET_HEX="$(echo "${MINT_JSON}" | jq -r '.sek_secret_hex'         )"
TQS_PUB_HEX="$(  echo "${MINT_JSON}" | jq -r '.tqs_public_hex'          )"
SEK_PUB_HEX="$(  echo "${MINT_JSON}" | jq -r '.sek_public_hex'          )"
TOKEN_B64="$(    echo "${MINT_JSON}" | jq -r '.token_b64'               )"
ENCRYPTED_B64="$(echo "${MINT_JSON}" | jq -r '.encrypted_request_b64'   )"
AAD_B64="$(      echo "${MINT_JSON}" | jq -r '.request_aad_b64'         )"
PLAINTEXT_B64="$(echo "${MINT_JSON}" | jq -r '.plaintext_b64'           )"

SESSION_KEY="hawcx:session:${SESSION_ID}"
log "  session_id=${SESSION_ID}"
log "  redis key =${SESSION_KEY}"

# ── Phase 3 — inject SessionRecord into stage Redis ──────────────

log "phase 3: launching helper pod ${HELPER_POD} in ${STAGE_NS}"
kubectl run "${HELPER_POD}" -n "${STAGE_NS}" \
    --image=redis:7-alpine --restart=Never --command -- sleep 600 \
    >/dev/null
# Block until ready (autopilot scheduling can take ~10s).
kubectl wait --for=condition=Ready "pod/${HELPER_POD}" -n "${STAGE_NS}" \
    --timeout=120s >/dev/null \
    || { fail "helper pod never reached Ready"; exit 1; }

# Helper: write one binary HSET field. Value comes in on stdin so
# arbitrary 0x00 bytes pass through (the bundle test in
# hx_agent_authorizer/crates/haap-rsv-bin/tests/wire_e2e_against_deployed_bundle.rs
# uses the same -x pattern).
hset_bin() {
    local field="$1"
    kubectl exec -i "${HELPER_POD}" -n "${STAGE_NS}" -- \
        redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" -x \
        HSET "${SESSION_KEY}" "${field}" >/dev/null
}

# Wrap an 8-byte big-endian u64 from a decimal string. We do this in
# python3 if available, else awk-printf — pure-bash hex math on >32-bit
# values is unreliable. python3 is on every CI image we care about.
u64_be() {
    local n="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys,struct; sys.stdout.buffer.write(struct.pack('>Q', int(sys.argv[1])))" "${n}"
    else
        # Fall back to xxd-driven hex assembly.
        printf '%016x' "${n}" | xxd -r -p
    fi
}

log "phase 3: HSET substrate fields under ${SESSION_KEY}"
# Order/encoding mirrors `RawSessionRecord::record_to_fields` and the
# in-tree wire_e2e_against_deployed_bundle.rs reference test.
echo -n "${TQS_PUB_HEX}"    | xxd -r -p | hset_bin tqs_public
echo -n "${SEK_SECRET_HEX}" | xxd -r -p | hset_bin sek_secret
echo -n "${SEK_PUB_HEX}"    | xxd -r -p | hset_bin sek_public
u64_be $(( ISSUED_AT - 3600 ))  | hset_bin sek_valid_from
u64_be $(( EXPIRES_AT + 3600 )) | hset_bin sek_valid_until
echo -n "${VERIFIER_HEX}"   | xxd -r -p | hset_bin verifier_secret
echo -n "${KSR_HEX}"        | xxd -r -p | hset_bin k_session_root
u64_be "${POLICY_EPOCH}"        | hset_bin current_epoch
printf 'active'                 | hset_bin status

# Sanity: confirm field count and lengths.
FIELDS_PRESENT="$(kubectl exec "${HELPER_POD}" -n "${STAGE_NS}" -- \
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" HKEYS "${SESSION_KEY}" \
    | wc -l | tr -d ' ')"
log "  fields written: ${FIELDS_PRESENT} (expect 9)"
TQS_LEN="$(kubectl exec "${HELPER_POD}" -n "${STAGE_NS}" -- \
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" HSTRLEN "${SESSION_KEY}" tqs_public | tr -d '[:space:]')"
if [[ "${TQS_LEN}" != "32" ]]; then
    fail "tqs_public is ${TQS_LEN} bytes, expected 32"; exit 1
fi
pass "substrate row provisioned (${FIELDS_PRESENT} fields, tqs_public=32B)"

# ── Phase 4 — happy-path /verify ─────────────────────────────────

log "phase 4: POST /verify (happy path)"
VERIFY_BODY="$(jq -n \
    --arg t "${TOKEN_B64}" \
    --arg e "${ENCRYPTED_B64}" \
    --arg a "${AAD_B64}" \
    '{token_b64:$t, encrypted_request_b64:$e, request_aad_b64:$a}')"

RESP_FILE="$(mktemp)"
STATUS="$(curl -s -o "${RESP_FILE}" -w '%{http_code}' \
    -X POST "${STAGE_RSV_URL}/verify" \
    -H "Authorization: Bearer ${BEARER}" \
    -H "Content-Type: application/json" \
    -d "${VERIFY_BODY}")"
RESP_BODY="$(cat "${RESP_FILE}")"
rm -f "${RESP_FILE}"

echo "--- /verify response (status=${STATUS}) ---"
echo "${RESP_BODY}" | jq . 2>/dev/null || echo "${RESP_BODY}"
echo "--- end response ---"

if [[ "${STATUS}" != "200" ]]; then
    fail "expected 200, got ${STATUS}"
else
    RECOVERED_B64="$(echo "${RESP_BODY}" | jq -r '.plaintext_b64')"
    if [[ "${RECOVERED_B64}" == "${PLAINTEXT_B64}" ]]; then
        pass "happy path: 200 OK + plaintext byte-identical to input"
    else
        fail "200 but plaintext mismatch (sent=${PLAINTEXT_B64}, got=${RECOVERED_B64})"
    fi
fi

# ── Phase 5 — tamper proofs ──────────────────────────────────────

log "phase 5a: ciphertext byte flip (expect 401)"
# Decode → flip last byte → re-encode. base64 round-trip is stable.
TAMPER_ENC_B64="$(echo "${ENCRYPTED_B64}" | base64 -d \
    | python3 -c "import sys; b=bytearray(sys.stdin.buffer.read()); b[-1]^=1; sys.stdout.buffer.write(bytes(b))" \
    | base64 | tr -d '\n')"

VERIFY_TAMPER="$(jq -n \
    --arg t "${TOKEN_B64}" \
    --arg e "${TAMPER_ENC_B64}" \
    --arg a "${AAD_B64}" \
    '{token_b64:$t, encrypted_request_b64:$e, request_aad_b64:$a}')"
TSTATUS="$(curl -s -o /tmp/.wt_tamper.json -w '%{http_code}' \
    -X POST "${STAGE_RSV_URL}/verify" \
    -H "Authorization: Bearer ${BEARER}" -H "Content-Type: application/json" \
    -d "${VERIFY_TAMPER}")"
TBODY="$(cat /tmp/.wt_tamper.json)"; rm -f /tmp/.wt_tamper.json
echo "  tamper-ct status=${TSTATUS} body=${TBODY}"
if [[ "${TSTATUS}" == "401" ]]; then
    pass "ciphertext tamper → 401 (${TBODY})"
else
    fail "ciphertext tamper expected 401, got ${TSTATUS} (${TBODY})"
fi

log "phase 5b: bearer flip (expect 401)"
WRONG_BEARER="$(printf 'deadbeef%.0s' {1..8})"
BSTATUS="$(curl -s -o /tmp/.wt_bearer.json -w '%{http_code}' \
    -X POST "${STAGE_RSV_URL}/verify" \
    -H "Authorization: Bearer ${WRONG_BEARER}" -H "Content-Type: application/json" \
    -d "${VERIFY_BODY}")"
BBODY="$(cat /tmp/.wt_bearer.json)"; rm -f /tmp/.wt_bearer.json
echo "  bearer-flip status=${BSTATUS} body=${BBODY}"
if [[ "${BSTATUS}" == "401" ]]; then
    pass "bearer flip → 401 (${BBODY})"
else
    fail "bearer flip expected 401, got ${BSTATUS} (${BBODY})"
fi

log "phase 5c: substrate absent — DEL row, retry (expect 401)"
kubectl exec "${HELPER_POD}" -n "${STAGE_NS}" -- \
    redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" DEL "${SESSION_KEY}" >/dev/null
DSTATUS="$(curl -s -o /tmp/.wt_del.json -w '%{http_code}' \
    -X POST "${STAGE_RSV_URL}/verify" \
    -H "Authorization: Bearer ${BEARER}" -H "Content-Type: application/json" \
    -d "${VERIFY_BODY}")"
DBODY="$(cat /tmp/.wt_del.json)"; rm -f /tmp/.wt_del.json
echo "  no-substrate status=${DSTATUS} body=${DBODY}"
if [[ "${DSTATUS}" == "401" ]]; then
    pass "session absent → 401 (${DBODY})"
else
    fail "session absent expected 401, got ${DSTATUS} (${DBODY})"
fi

# Mark SESSION_KEY empty so cleanup doesn't try a redundant DEL — the
# row is already gone. Defensive only; redis-cli DEL on absent keys is
# a no-op anyway.
SESSION_KEY=""

# ── Summary ──────────────────────────────────────────────────────

if [[ "${OVERALL}" -eq 0 ]]; then
    printf '\n\033[1;32m========== ALL ASSERTIONS PASSED ==========\033[0m\n'
else
    printf '\n\033[1;31m========== AT LEAST ONE FAIL ==========\033[0m\n'
fi
exit "${OVERALL}"
