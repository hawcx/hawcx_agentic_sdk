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
    stsl = [d for d in docs if d.get("kind") == "StatefulSet"]
    if len(stsl) != 1:
        fail(f"expected exactly one StatefulSet, got {len(stsl)} (kinds: {[d.get('kind') for d in docs]})")
    sts = stsl[0]
    sts_spec = sts["spec"]

    # StatefulSet-of-1: exactly one agent replica, stable identity.
    if sts_spec.get("replicas") != 1:
        fail(f"StatefulSet replicas must be 1, got {sts_spec.get('replicas')!r}")

    # A StatefulSet requires a governing headless Service (clusterIP: None)
    # matching spec.serviceName — that's what gives the pod stable identity.
    svc_name = sts_spec.get("serviceName")
    if not svc_name:
        fail("StatefulSet must set spec.serviceName")
    svcs = [d for d in docs if d.get("kind") == "Service" and d.get("metadata", {}).get("name") == svc_name]
    if len(svcs) != 1:
        fail(f"expected exactly one Service named {svc_name!r} (serviceName), got {len(svcs)}")
    if svcs[0]["spec"].get("clusterIP") != "None":
        fail(f"Service {svc_name!r} must be headless (clusterIP: None)")

    # No PVC / volumeClaimTemplates — sealed key material must stay ephemeral
    # tmpfs, never persistent. A PVC here would survive UID reuse / pod death,
    # which the isolation model deliberately refuses.
    if sts_spec.get("volumeClaimTemplates"):
        fail("StatefulSet must not use volumeClaimTemplates (IPC/seal state must stay tmpfs, never persistent)")

    spec = sts_spec["template"]["spec"]

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
