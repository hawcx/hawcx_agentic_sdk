# haap-agent-pod (HST-1 robust-tier)

One **StatefulSet-of-1** per agent instance (`replicas: 1`, a governing
headless `Service` for `spec.serviceName`). Two containers, two kernel
principals:

| container | runAsUser | runs |
|-----------|-----------|------|
| `keeper`  | `credUid` | sk-holding supervisor → agent-group (unseal-orch, authenticator, tqs-precompute, tqs-jit, assembler, eib) |
| `agent`   | `llmUid`  | customer/LLM loop |

Two UIDs (not one) is deliberate — it closes ADR-0022 D-22-1 (intra-pod
Agent↔credential boundary). UIDs come from the reserved band `100000-199999`,
disjoint from the infra band (`<100000`; distroless/orchestrator use `65532`),
cluster-unique.

The `agent` container mounts only the shared `haap-ipc` tmpfs volume, so it can
reach nothing but the assembler socket. The keeper's other daemon sockets live
on `haap-keeper-internal`, which the agent never mounts. No host namespaces
(`hostPID/hostIPC/hostNetwork` all false); keeper and agent stay in separate PID
namespaces (`shareProcessNamespace: false`).

## Who renders this

The orchestrator provisioning controller
(`hx_agent_admin_orchestrator_service` → `provisioning`) allocates the UIDs,
resolves the risk tier → `runtimeClassName`, and injects the fail-closed
preflight contract (`keeperEnv`), then `helm template … | kubectl apply`. The
env-var names in `keeperEnv` are the shared contract with
`provisioning::manifest::REQUIRED_PREFLIGHT_KEYS`.

`runtimeClassName` is set only for the microvm posture (critical tier) and is
kept consistent with `HAAP_REQUIRED_ISOLATION_POSTURE` by the controller.

## Why StatefulSet, not a bare Pod

A bare `Pod` never gets rescheduled on node failure — it just vanishes, and
whatever provisioned it has to notice and re-create it from scratch. A
`StatefulSet` of one replica gives the same single agent a stable identity
(name, DNS via the headless Service) and lets the control plane reschedule it
automatically.

**This is not a resume mechanism.** The IPC/seal `emptyDir` volumes stay
`medium: Memory` (tmpfs) — deliberately **not** a `volumeClaimTemplate` / PVC.
Sealed key material dies with the pod, which is what makes UID reuse safe (a
rescheduled pod is the same agent identity, never a stranger inheriting old
keys). The trade-off: a reschedule to a different node starts the agent with
fresh, re-enrolled state, not the previous session resumed. Full
resume-after-reschedule would require persisting key material in a PVC — a
materially different security posture (durable key material off the node,
new backup/rotation/encryption-at-rest obligations) that this chart
deliberately does **not** adopt. If a workload needs resume-on-reschedule,
that's a separate design decision, not a drop-in flag here.

## Dev vs prod

This chart is the PRODUCTION topology. The `docker/` docker-compose bundle is
the dev-mode profile (same-UID, single node) and is **not** a security boundary.

## Not yet wired (gated, tracked elsewhere)

- Canary rollout + the ADR-0026 cross-agent-unseal-refusal acceptance test
  (gated on REL-1).
- The strong ATTESTED microVM path — key release gated on Confidential-Space
  attestation (gated on INF-8/D6). Today `runtimeClassName` for critical is a
  plain sandbox class (e.g. `gvisor`), not the attested confidential-space
  runtime.

## Local check

```
bash deploy/agent-pod/ci/render_and_validate.sh
```

Runs `helm lint`, renders the standard and critical tiers, validates against
Kubernetes schemas (`kubeconform`, if installed) and the structural invariants
(`ci/validate_manifest.py`).
