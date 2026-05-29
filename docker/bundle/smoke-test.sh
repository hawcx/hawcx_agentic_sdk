#!/usr/bin/env bash
# Smoke test for the HAAP evaluation bundle.
#
# Brings up the bundle, waits for the gRPC + HTTP ports to open, and reports
# pass/fail. Does NOT verify functional correctness — see integration tests
# in the SDK + CAA repos for that.
#
# CI mode: set CI=1 (or SMOKE_TEST_AUTO_TEARDOWN=1) to skip the interactive
# teardown prompt and tear down automatically.

set -euo pipefail

cd "$(dirname "$0")"

# Generate a .env if one doesn't exist, using throwaway placeholders so
# containers can at least start. Real evaluation requires customer-provided
# values — see .env.example for the list.
if [ ! -f .env ]; then
    cp .env.example .env
    if command -v openssl >/dev/null; then
        # Throwaway placeholders to let containers initialize past env-validation.
        # The values are not valid tenant credentials — CAA admin-auth may
        # fail to decode IK_c and exit. RSV passes env validation and serves
        # /healthz successfully.
        AUDIENCE=$(openssl rand -hex 32)
        IK_C=$(openssl rand -hex 32)
        OTRC=$(openssl rand -hex 32)
        K_ADMIN=$(openssl rand -hex 32)
        RSV_AUTH=$(openssl rand -hex 32)

        sed -i.bak \
            -e "s|^HAWCX_ORG_ID=$|HAWCX_ORG_ID=smoke-test-org|" \
            -e "s|^HAWCX_IK_C=$|HAWCX_IK_C=${IK_C}|" \
            -e "s|^HAAP_BOOTSTRAP_OTRC=$|HAAP_BOOTSTRAP_OTRC=${OTRC}|" \
            -e "s|^HAAP_AUDIENCE_HASH=$|HAAP_AUDIENCE_HASH=${AUDIENCE}|" \
            -e "s|^HAAP_CAA_K_ADMIN_SESSION_HEX=$|HAAP_CAA_K_ADMIN_SESSION_HEX=${K_ADMIN}|" \
            -e "s|^HAAP_RSV_AUTH_TOKEN=$|HAAP_RSV_AUTH_TOKEN=${RSV_AUTH}|" \
            .env
        rm -f .env.bak
    fi
fi

# Pre-check: the bundle pulls TWO images that live in separate repos and
# release on independent cadences — hx-caa (from hx_agent_client_admin_service)
# and haap-rsv (from hx_agent_authorizer). When the SDK release-line tags
# ahead, either of those `${TAG}` manifests may not exist yet — `docker
# compose pull` would then fail with `denied` from GHCR.
#
# Skip cleanly with exit 0 in that case so the release CI signal stays
# meaningful: a red here means a real structural break (compose syntax,
# entrypoint, env handling), not "we haven't tagged the dependency yet."
BUNDLE_VERSION="${HAAP_VERSION:-v0.1.0-alpha.13}"
REQUIRED_IMAGES=(
    "ghcr.io/hawcx/hx-caa:${BUNDLE_VERSION}"
    "ghcr.io/hawcx/haap-rsv:${BUNDLE_VERSION}"
)
echo "=== Checking matching images for ${BUNDLE_VERSION} ==="
for IMG in "${REQUIRED_IMAGES[@]}"; do
    if ! docker manifest inspect "${IMG}" >/dev/null 2>&1; then
        cat <<EOF

Skipping bundle smoke test: ${IMG} is not published.

The HAAP evaluation bundle pulls hx-caa and haap-rsv together at the same
version tag. Those images are released from separate repositories
(hx_agent_client_admin_service and hx_agent_authorizer respectively) on
their own cadences. When the SDK release-line tags ahead, this test waits
for the matching dependency tags to appear.

To enable end-to-end bundle verification at this release: tag
${BUNDLE_VERSION} in the missing repository above and re-run this job.
EOF
        exit 0
    fi
    echo "  ${IMG}: manifest exists"
done

echo ""
echo "=== Pulling images ==="
docker compose pull

echo ""
echo "=== Starting bundle ==="
docker compose up -d

# Wait for endpoints to respond rather than for container health (distroless
# services have healthchecks disabled).
#
# RSV serves /healthz so we verify it with curl. CAA's gRPC port is verified
# with a TCP probe — gRPC reflection isn't enabled in alpha-1 so we don't try
# to handshake. With throwaway IK_c, CAA admin-auth may fail to decode the
# key and exit; the orchestrator may then not bind its gRPC port. We treat
# CAA as PROBE-ONLY (best-effort) and only require RSV + Redis as hard pass.
echo ""
echo "=== Waiting for endpoints to respond (max 90s) ==="
TIMEOUT=90
ELAPSED=0
CAA_OPEN=0
RSV_OPEN=0
REDIS_OPEN=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if [ $CAA_OPEN -eq 0 ] && nc -z localhost "${CAA_GRPC_PORT:-9443}" 2>/dev/null; then
        echo "  CAA gRPC port ${CAA_GRPC_PORT:-9443}: open after ${ELAPSED}s"
        CAA_OPEN=1
    fi
    if [ $RSV_OPEN -eq 0 ] && curl -fsS "http://localhost:${RSV_PORT:-8443}/healthz" 2>/dev/null | grep -q "^ok$"; then
        echo "  RSV /healthz: ok after ${ELAPSED}s"
        RSV_OPEN=1
    fi
    if [ $REDIS_OPEN -eq 0 ] && docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
        echo "  Redis: responsive after ${ELAPSED}s"
        REDIS_OPEN=1
    fi
    if [ $RSV_OPEN -eq 1 ] && [ $REDIS_OPEN -eq 1 ]; then
        break
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
done

echo ""
echo "=== Results ==="
FAIL=0
[ $RSV_OPEN -eq 1 ]   && echo "  RSV /healthz: ok ✓"    || { echo "  RSV /healthz: NOT READY ✗"; FAIL=1; }
[ $REDIS_OPEN -eq 1 ] && echo "  Redis:        ready ✓" || { echo "  Redis:        NOT READY ✗"; FAIL=1; }
[ $CAA_OPEN -eq 1 ]   && echo "  CAA gRPC port: open ✓ (real tenant creds required for the AdminControlPlane to be functional)" \
                      || echo "  CAA gRPC port: not listening (expected with throwaway IK_c — real tenant credentials required)"

if [ $FAIL -ne 0 ]; then
    echo ""
    echo "=== Smoke test FAILED — dumping container logs ==="
    docker compose ps
    echo "--- caa-admin-auth ---"
    docker compose logs --tail=50 caa-admin-auth || true
    echo "--- caa ---"
    docker compose logs --tail=50 caa || true
    echo "--- rsv ---"
    docker compose logs --tail=50 rsv || true
    docker compose down -v
    exit 1
fi

echo ""
echo "=== Bundle smoke test PASSED ==="

# Teardown: automatic in CI, prompt otherwise.
if [ "${CI:-}" = "1" ] || [ "${SMOKE_TEST_AUTO_TEARDOWN:-}" = "1" ]; then
    docker compose down -v
    echo "Bundle torn down (auto)."
else
    read -r -p "Tear down the bundle now? [Y/n] " ans
    if [ "${ans:-Y}" != "n" ] && [ "${ans}" != "N" ]; then
        docker compose down -v
        echo "Bundle torn down."
    else
        echo "Bundle left running. Tear down with: docker compose down -v"
    fi
fi
