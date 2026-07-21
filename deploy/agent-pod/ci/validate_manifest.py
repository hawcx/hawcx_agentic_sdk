#!/usr/bin/env python3
"""Structural validator for a rendered haap-agent-pod manifest.

Asserts the HST-1 invariants that must hold for EVERY rendered agent pod,
independent of Kubernetes schema validation (kubeconform covers schema). Reads
one rendered manifest file (argv[1]) produced by `helm template`.

The REQUIRED preflight keys mirror the orchestrator's
`provisioning::manifest::REQUIRED_PREFLIGHT_KEYS` — the two are the shared
fail-closed contract (HST-1 PR #82).
"""
import sys
import yaml

REQUIRED_PREFLIGHT_KEYS = {
    "HAAP_PRODUCTION_MODE",
    "HAAP_REQUIRED_ISOLATION_POSTURE",
    "HAAP_AGENT_EXPECTED_UID",
    "HAAP_SHARED_INFRA_UIDS",
    "HAAP_AGENT_NS_ISOLATION",
    "HAAP_TQS_PEER_AUTHENTICATOR_UID",
    "HAAP_TQS_PEER_JIT_UID",
}
UID_BAND = range(100_000, 200_000)  # 100000-199999 inclusive


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main(path):
    docs = [d for d in yaml.safe_load_all(open(path)) if d]
    pods = [d for d in docs if d.get("kind") == "Pod"]
    if len(pods) != 1:
        fail(f"expected exactly one Pod, got {len(pods)} (kinds: {[d.get('kind') for d in docs]})")
    spec = pods[0]["spec"]

    # No host namespaces — a shared host ns erases the per-agent boundary.
    for ns in ("hostPID", "hostIPC", "hostNetwork"):
        if spec.get(ns, False):
            fail(f"{ns} must be false/absent, got {spec.get(ns)!r}")
    if spec.get("shareProcessNamespace", False):
        fail("shareProcessNamespace must be false (keeper/agent separate pid ns)")
    if spec.get("automountServiceAccountToken", True):
        fail("automountServiceAccountToken must be false")

    containers = {c["name"]: c for c in spec["containers"]}
    if set(containers) != {"keeper", "agent"}:
        fail(f"expected containers {{keeper, agent}}, got {set(containers)}")

    cred = containers["keeper"]["securityContext"]["runAsUser"]
    llm = containers["agent"]["securityContext"]["runAsUser"]
    for role, uid in (("keeper/cred", cred), ("agent/llm", llm)):
        if uid not in UID_BAND:
            fail(f"{role} runAsUser {uid} outside reserved band 100000-199999")
    if cred == llm:
        fail(f"keeper and agent share UID {cred} — must be two distinct principals")

    # keeper env carries every required preflight key.
    keeper_env = {e["name"]: e for e in containers["keeper"].get("env", [])}
    missing = REQUIRED_PREFLIGHT_KEYS - keeper_env.keys()
    if missing:
        fail(f"keeper missing required preflight keys: {sorted(missing)}")

    # posture ⟺ runtimeClassName (step 6: no drift).
    posture = keeper_env["HAAP_REQUIRED_ISOLATION_POSTURE"]["value"]
    rtc = spec.get("runtimeClassName")
    if (posture == "microvm") != bool(rtc):
        fail(f"posture {posture!r} and runtimeClassName {rtc!r} disagree")

    # HAAP_AGENT_EXPECTED_UID must be the agent's (llm) UID, peers the keeper's.
    if keeper_env["HAAP_AGENT_EXPECTED_UID"]["value"] != str(llm):
        fail("HAAP_AGENT_EXPECTED_UID != agent runAsUser")
    for k in ("HAAP_TQS_PEER_AUTHENTICATOR_UID", "HAAP_TQS_PEER_JIT_UID"):
        if keeper_env[k]["value"] != str(cred):
            fail(f"{k} != keeper runAsUser")

    # The agent container must mount ONLY the shared assembler IPC volume,
    # never the keeper-internal socket dir.
    agent_mounts = {m["name"] for m in containers["agent"].get("volumeMounts", [])}
    if agent_mounts != {"haap-ipc"}:
        fail(f"agent must mount only haap-ipc, got {agent_mounts}")

    # IPC volumes are tmpfs (emptyDir medium: Memory).
    vols = {v["name"]: v for v in spec["volumes"]}
    for name in ("haap-ipc", "haap-keeper-internal"):
        med = vols.get(name, {}).get("emptyDir", {}).get("medium")
        if med != "Memory":
            fail(f"volume {name} must be emptyDir medium=Memory, got {med!r}")

    print(f"OK: {path} — posture={posture} cred={cred} llm={llm} rtc={rtc!r}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: validate_manifest.py <rendered.yaml>")
    main(sys.argv[1])
