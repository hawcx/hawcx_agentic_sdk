#!/usr/bin/env bash
# Lint + render + validate the haap-agent-pod chart. Real render, no mocks.
#
#   1. helm lint
#   2. helm template for the standard tier (chart defaults) AND the critical
#      tier (microvm posture) — covers the runtimeClassName branch.
#   3. kubeconform schema validation if available (CI installs it, pinned).
#   4. structural invariant validation (validate_manifest.py).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="$(dirname "$HERE")"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "== helm lint =="
helm lint "$CHART" --values "$HERE/test-values-critical.yaml"

render() {
  local name="$1"; shift
  echo "== helm template ($name) =="
  helm template "$name" "$CHART" "$@" >"$OUT/$name.yaml"
  if command -v kubeconform >/dev/null 2>&1; then
    echo "== kubeconform ($name) =="
    kubeconform -strict -summary "$OUT/$name.yaml"
  else
    echo "kubeconform not found — skipping schema validation (structural checks still run)"
  fi
  echo "== structural validation ($name) =="
  python3 "$HERE/validate_manifest.py" "$OUT/$name.yaml"
}

render standard                                   # chart defaults (runc)
render critical --values "$HERE/test-values-critical.yaml"

echo "ALL OK"
