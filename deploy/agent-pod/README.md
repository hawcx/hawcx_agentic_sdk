# haap-agent-pod (HST-1 robust-tier)

One pod per agent instance. Two containers, two kernel principals:

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
