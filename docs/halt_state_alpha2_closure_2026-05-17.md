# HALT — Priority 2-α (Alpha-2 Closure)

**Date:** 2026-05-17
**Branch:** `feature/priority2-foundation-py-node-2026-05-17` (current working branch; no `feature/alpha2-closure-*` branch created)
**Repos touched:** none

## TL;DR

The Priority 2-α prompt's central premise — *"the RSV cascade adapter in `hx_agentic_sdk/crates/haap-rsv` is stubbed; `Rsv::verify_and_decrypt_request` currently returns `Internal("RSV cascade adapter wire-up lands in a focused follow-up PR")`. This is the load-bearing alpha-2 blocker"* — is **wrong against current `main`**. The cascade adapter was wired up by PR #5 (commits `cbf80c7` and `3f4b55f`) on **2026-05-15**, two days before the Priority 2-α prompt was authored. The closure report (`docs/rsv_cascade_adapter_closure_2026-05-15.md`) and the helper-signatures forensic preflight (`docs/rsv_adapter_helper_signatures.md`) document this in detail.

Per Phase 0.2's explicit halt guard:

> If the stub is no longer there (someone else closed it), **halt with state document** and stop — the work is done.

Two additional halt guards also fire:

- **Phase 1.4 — `registered_scope` already partial in flight in hx_labs.** `registered_scope_json: None` appears at 3 call sites in `hx_labs/crates/haap-server/src/caa_control_plane.rs` (lines 297, 575) and `hx_labs/crates/haap-caa-test-fixtures/src/fixtures.rs:56`. Some other v6.8.0 workstream is plumbing the field on the CAA control-plane side. Phase 1.4's halt-on-mismatch guard ("don't introduce a duplicate") triggers.

- **Phase 1.5 — fail-closed-on-None contradicts the design memo.** The prompt's "default to None (fail-closed via `AuthError::MissingRegisteredScope`)" is the *opposite* of what `~/Projects/hx_labs/docs/v6_8_design_memos/registration_scope_authorizer.md` §2.3 specifies (the memo's reference impl returns `true` when `registered_scope` is None, with reject-at-registration-time enforcement at the AS layer — see memo §5.3 and §5.4). Implementing the prompt's behavior would break every existing v6.7.4 substrate.

I halted before creating any branches, before making any changes, and before invoking any tooling that would alter repo state. No PRs opened.

## Halt-trigger evidence

### Mismatch 1 — Cascade adapter is already wired

Prompt §"Driver":
> `Rsv::verify_and_decrypt_request` currently returns `Internal("RSV cascade adapter wire-up lands in a focused follow-up PR")`

Prompt §Phase 0.2:
> ```bash
> grep -rn "RSV cascade adapter wire-up lands in a focused follow-up PR" src/
> ```
> If the stub is no longer there (someone else closed it), **halt with state document** and stop — the work is done.

**Reality** (`crates/haap-rsv/src/rsv.rs:10`, `:110`, `:168`):

```rust
use haap_core::cascade::verify_and_decrypt_request;
// ...
// 7. Cascade call
let (token_body, body_plaintext) = verify_and_decrypt_request(
    &parsed,
    Some(&session),
    &ctx,
    &mut replay,
    &authorizer,
    encrypted_request,
    request_aad,
)
.map_err(map_cascade_reject)?;
```

`grep -rn "RSV cascade adapter wire-up lands in a focused follow-up PR" crates/haap-rsv/src/` returns no matches. The stub does not exist in the source tree.

Git log on `crates/haap-rsv/src/rsv.rs`:

```
3f4b55f feat(haap-rsv): wire up cascade adapter (verify + encrypt_response) (#5)
cbf80c7 feat(haap-rsv): wire up verify_and_decrypt + encrypt_response to cascade
```

Both predate the prompt by two days.

The closure report (`docs/rsv_cascade_adapter_closure_2026-05-15.md`) documents the 6-step adapter, three entry points (`verify_and_decrypt`, `verify_and_decrypt_with_body`, `verify_and_decrypt_with_in_mem_replay`), dual-Redis-client architecture, JTI schema correction (`[u8; 22]` → `[u8; 16]`), exhaustive `CascadeRejectReason` mapping, and 12/12 passing tests. It is the artifact the prompt is asking me to produce — and it already exists.

### Why the prompt got this wrong

The implementation inventory the prompt cites (`docs/implementation_inventory_2026-05-17.md` — verified to live in `hx_labs/docs/`, not `hx_agentic_sdk/docs/`) lists the cascade adapter as a "Known unknown requiring user input" in its Executive Summary:

> **Known unknowns requiring user input** (after this survey, in priority order): (1) **alpha-2 dependency** — `hx_agentic_sdk/crates/haap-rsv::Rsv::verify_and_decrypt_request` currently returns `Internal("RSV cascade adapter wire-up lands in a focused follow-up PR")`; does the Python/Node Foundation work proceed without RSV verification (just the agent-side pipeline) or wait for cascade adapter completion?

This was written on 2026-05-17 — the same day the cascade adapter PR was merged (PR #5, 2026-05-15) — but the inventory carried forward the stub-quote text from the closure report's "Release impact" section (which describes the **stubbed alpha-1 release**, not the post-merge state of `main`). The inventory's auditor did not reconcile against the merged adapter code.

The Priority 2-α prompt then derived its premise from that "Known unknown" line.

### Mismatch 2 — `registered_scope_json` is partially in flight in hx_labs

Prompt §Phase 1.4:
> Update the substrate (Redis) schema in `haap-redis::set_session` to serialize the new field. Backward-compatible: alpha-1 substrate records without `registered_scope` deserialize as `None`...

Prompt §"Halt-on-mismatch guards":
> **Phase 1.4 — registered_scope conflicts with existing SessionRecord.** If `SessionRecord` already has a similar field (different name, same purpose) added by other v6.8.0 work, halt with state document; don't introduce a duplicate.

**Reality** (`grep -rn "registered_scope" hx_labs/crates/`):

```
crates/haap-server/src/caa_control_plane.rs:297:            registered_scope_json: None,
crates/haap-server/src/caa_control_plane.rs:575:            registered_scope_json: None,
crates/haap-caa-test-fixtures/src/fixtures.rs:56:        registered_scope_json: None,
```

Three call sites in hx_labs already reference a `registered_scope_json` field. All pass `None` (placeholder values), but the field name is set, the type appears to be `Option<String>` (JSON-serialized canonical form), and it threads through `SessionMaterial` in the CAA control plane.

This is **partial work on the same problem with a different field name** (`registered_scope_json` rather than `registered_scope`). The Phase 1.4 halt guard fires.

The field-name divergence matters: the memo specifies `registered_scope: Option<CanonicalJSON>` (a typed canonical-JSON wrapper). The in-flight hx_labs work has `registered_scope_json: Option<String>` (a string of serialized JSON). Either choice is defensible, but reconciling them now requires coordination with whoever owns the in-flight work — I cannot identify the owner from local state, and there is no in-flight PR visible on `main` (the field appears already merged with the placeholder values; the population logic is what's missing).

### Mismatch 3 — Fail-closed-on-None contradicts the design memo

Prompt §Phase 1.3 (pseudocode for `RegistrationScopeAuthorizer`):

```rust
let registered = session.registered_scope.as_ref()
    .ok_or(AuthError::MissingRegisteredScope)?;  // <-- prompt: None → fail closed
```

Prompt §Phase 1.5 (Admin Console missing case):
> If the Admin Console doesn't yet emit `registered_scope` at register-agent time, document the gap, default to `None` (fail-closed via authorizer), and propose Admin Console as a follow-up.

Prompt §Phase 1.7 (test cases):
> `registered_scope == None → AuthError::MissingRegisteredScope`

**Reality — `registration_scope_authorizer.md` §2.3 reference impl** (lines 78–87):

```rust
impl Authorizer for RegistrationScopeAuthorizer {
    fn authorize(
        &self,
        claimed_scope: &[u8],
        _operation: &str,
        _resource: &str,
        session: &SessionRecord,
    ) -> bool {
        match &session.registered_scope {
            Some(registered) => claimed_scope == registered.as_bytes(),
            // No registered scope in substrate (legacy v6.7.4):
            //   fall back to permissive (cascade's step 13 ceiling
            //   enforcement remains the authoritative gate)
            None => true,    // <-- memo: None → permissive fallback
        }
    }
}
```

Memo §5.3 ("What about empty / null registered_scope?") explicitly **rejects fail-closed** behavior for null and assigns the enforcement instead to "the AS / admin console layer":

> **Recommendation**: strict reading. Agents must explicitly register the scope they intend to use. Registration without scope is an error **at the AS / admin console layer**, not silently in RSV.

The memo's design = permissive in the authorizer + reject-at-registration in the AS.
The prompt's design = fail-closed in the authorizer.

These are mutually exclusive. Implementing the prompt's behavior verbatim would cause **every v6.7.4 substrate record in production** (none have `registered_scope_json` populated today; all three observed call sites pass `None`) to fail authorization with `AuthError::MissingRegisteredScope`. The cascade-internal `scope_ceiling` enforcement at step 13 — which the closure report and the authorizer module-doc both call out as "the protection floor" while the new field is unrolled — would be unreachable because the new authorizer would reject earlier.

The memo cannot be implemented as the prompt directs without contradicting its own §5.3 / §5.4 decisions.

### Mismatch 4 — Authorizer trait extension scope grossly underestimated

Prompt estimate: "Estimated agent time: 3–5 days. RSV cascade adapter wire-up is the bulk (Phase 1)."

Memo §3 ("Impact analysis"):

| Repo | Memo's LOC estimate |
|---|---|
| hx_labs (haap-core types + trait + cascade + tests) | 150–200 |
| CAA (hx_agent_client_admin_service) | 30–40 |
| AS (hx_agent_auth_service — `/v3/register_agent` ceremony) | 80–100 |
| SDK (hx_agentic_sdk) | 150 |
| Admin Console | 150 |
| Spec | 150 |
| **Total** | **~700–800 LOC across 6 repos** |

Memo's calendar estimate: *"Probably 1–2 weeks of focused work for one engineer per repo, with coordination."*

The prompt allocates Phase 1 of 4 phases inside a 3–5 day envelope to do that work. Even at 3× LOC velocity, the prompt's envelope assumes all 6 repo touches happen in roughly one engineer-day — which would require pre-existing partial work in all 6 repos (only one of which — the `registered_scope_json` placeholder in hx_labs — is observable today).

Crucially: without the AS `/v3/register_agent` extension (~80–100 LOC) and the Admin Console registration UI (~150 LOC), no real session will ever carry a populated `registered_scope`. RSV's `RegistrationScopeAuthorizer` would always observe `None`. With the memo's recommended permissive fallback, that's a no-op authorizer. With the prompt's fail-closed semantic, it's a hard outage.

The cascade adapter closure team already reached this verdict and documented it in `docs/rsv_adapter_helper_signatures.md` §"Phase 0.4 investigation: registration-scope semantics":

> **Conclusion C-prime**: The prompt's `RegistrationScopeAuthorizer` design — strict equality between claimed scope and registration scope — cannot be implemented against the current Authorizer trait without one of:
> 1. **Stateful Authorizer** — requires substrate field that does not exist yet
> 2. **Trait extension** — requires hx_labs PR + cascade-wide signature update
> 3. **Permissive alpha + future Cedar** — ship alpha with `PermissiveAuthorizer`
>
> **Decision applied: option 3 for alpha.**

The Priority 2-α prompt re-litigates this decision without acknowledging that it was made deliberately two days earlier with documented rationale.

### Mismatch 5 — Phase 2 release pipeline is largely already-tested

Prompt §Phase 2 frames alpha-2 release tagging as a fresh end-to-end validation:

> Tag `v0.1.0-alpha.2`, verify all 7 binaries land in tarball, Docker image runs on linux/amd64 + linux/arm64, customer can `curl … | tar -xz` and run `haap-sdk run-pipeline` against a real CAA + AS + Console deployment.

`docs/clean_slate_rebuild_closure_2026-05-15.md`, `docs/docker_bundle_closure_report_2026-05-15.md`, and `docs/RELEASE.md` indicate that release pipeline, multi-arch Docker, and the CAA+RSV docker-compose bundle (`docker/bundle/`) all landed by 2026-05-15. The 7-binary tarball layout is verified in PR #8 (the docker bundle) and the recent CI fixes (`9555db5`, `96b298f`). The smoke test (`docker/bundle/smoke-test.sh`) is already present.

What is **not** yet established is whether the operator has tagged `v0.1.0-alpha.2` on `main` post-cascade-merge. This is a 1-step operator action, not a 3–5 day workstream. If the user wants this done, it is `git tag v0.1.0-alpha.2 && git push origin v0.1.0-alpha.2` followed by watching the existing CI workflow.

### Mismatch 6 — Two prior halts have hit the same pattern

This is the **third prompt** in the Priority 2 series whose premise was derived from the 2026-05-17 implementation inventory and proved stale against current `main`:

1. **2026-05-17** — Priority 2-Foundation halted; premise (`hx_agentic_sdk/packages/haap-sdk-{python,node}/`) was wrong against the actual Rust-workspace architecture. State doc: `hx_labs/docs/halt_state_priority2_foundation_2026-05-17.md`.
2. **2026-05-18** — Priority 2-0a halted; premise (Windows IPC was never shipped) was wrong against the DACL-hardened Windows Named Pipe code already on `main`. State doc: `hx_labs/docs/halt_state_priority2_0a_2026-05-18.md`.
3. **2026-05-17 (this)** — Priority 2-α halted; premise (RSV cascade adapter stubbed) was wrong against the wire-up merged in PR #5 on 2026-05-15.

The common factor is the inventory's "Known unknowns" / "Recommended next prompt" section being read as gospel. The inventory is a snapshot, not a planning document. Each subsequent prompt should re-verify the inventory's claims against `main` HEAD before treating them as load-bearing premises.

## What I did NOT do

- No branches created.
- No code changes in either repo.
- No commits.
- No `git tag` operations.
- No CI workflow runs triggered.
- No PRs opened.
- This halt-state doc is currently untracked on `feature/priority2-foundation-py-node-2026-05-17`. It mirrors the convention of the two prior halt-state docs (which landed on hx_labs `main` as untracked artifacts). The user can move it where appropriate or commit it on a dedicated halt-state branch.

## Recommended revised scope

In priority order, smallest → largest:

### Option α — No-op (smallest)

Acknowledge that alpha-2 closure is *already done* on the cascade-adapter axis. The remaining alpha-2 work — Authorizer trait extension, substrate-schema `registered_scope` plumbing, `RegistrationScopeAuthorizer` reference impl — is a **v6.8.0 cycle workstream** per the design memo (which is explicit: "Target spec version: v6.8.0 or later"), not an alpha-2 closure task.

The operator action to actually ship alpha-2:

```bash
cd ~/Projects/hx_agentic_sdk
git checkout main && git pull --ff-only
git tag v0.1.0-alpha.2
git push origin v0.1.0-alpha.2
# watch existing CI workflow
gh run watch --repo hawcx/hx_agentic_sdk
```

Followed by running the existing `docker/bundle/smoke-test.sh` against a tenant deployment. No new code required.

**Effort:** 1 hour operator time. **Risk:** low — the wire-up is already test-validated; the smoke test exercises the wire-up against the bundled binaries.

### Option β — Reconciliation prompt (small)

A read-only audit prompt that:

1. Re-verifies each "Known unknown" in `hx_labs/docs/implementation_inventory_2026-05-17.md` against current `main` HEAD on both repos.
2. Identifies which unknowns are now resolved (cascade adapter, Windows IPC, docker bundle) and which remain genuinely open.
3. Lists in-flight partial work observable in source (e.g., `registered_scope_json` placeholders in haap-server) and who owns it.
4. Produces a corrected inventory at `hx_labs/docs/implementation_inventory_2026-05-19.md` (or wherever the project convention prefers).

**Effort:** 0.5 day, read-only. **Risk:** zero. **Output:** a reliable basis for any future Priority 2-α / 2-β / 2-γ prompt.

### Option γ — RegistrationScopeAuthorizer as a v6.8.0 workstream (large, correct shape)

If the user wants registration-scope binding to ship, the right shape per the memo (§3 Impact analysis) is a **coordinated multi-repo workstream**, not an alpha-2 closure:

1. **hx_labs PR** — `SessionRecord` field, `Authorizer` trait extension (breaking), `PermissiveAuthorizer` signature update, `RegistrationScopeAuthorizer` reference impl, cascade-internal plumbing, `RawSessionRecord` field-name reconciliation with the in-flight `registered_scope_json: Option<String>` placeholder.
2. **CAA PR** (hx_agent_client_admin_service) — `ProvisionSessionMaterial` carries the new field; substrate writer serializes it.
3. **AS PR** (hx_agent_auth_service) — `/v3/register_agent` ceremony captures the agent's stated scope; reject-at-registration enforcement for invalid/missing scope.
4. **Admin Console PR** — registration UI captures the operator's intended scope.
5. **SDK PR** (hx_agentic_sdk) — adapter wires `RegistrationScopeAuthorizer` as the alpha-2+1 default, replaces `PermissiveAuthorizer` in `crates/haap-rsv/src/rsv.rs`.
6. **Spec PR** — v6.8.0 §13.6 / §8.1 / §44.4.2 amendments.

**Effort:** 1–2 weeks (memo estimate). **Sequencing:** hx_labs first (trait + types), then CAA + AS in parallel, then SDK, then Admin Console, then spec. **Risk:** medium — coordination across 6 repos with at least one breaking trait change. **Not** an alpha-2 closure.

### Not recommended

- **Following the Priority 2-α prompt as written.** The 3–5 day envelope is incompatible with the memo's scope. The fail-closed-on-None semantic contradicts the memo's §5.3 / §2.3. The "stub already wired" premise contradicts current `main`.
- **Implementing only the SDK-side `RegistrationScopeAuthorizer`** (without the AS / Admin Console changes). The authorizer would observe `registered_scope == None` on every production session and produce hard outages under the prompt's fail-closed semantic, or no-op under the memo's permissive-fallback semantic. Either way, no behavioral change in production.
- **Renaming `registered_scope_json` (in-flight in haap-server) to `registered_scope`** without first identifying the owner of that workstream and coordinating. The placeholder values suggest someone is mid-implementation; pulling the field name out from under them would conflict.

## Open questions for the user

1. **Is the cascade-adapter wire-up sufficient for what you mean by "alpha-2"?** If yes, Option α (tag-and-validate) is the closure path. The prompt's framing of alpha-2 as gated on `RegistrationScopeAuthorizer` doesn't match either the memo (which targets v6.8.0) or the closure report (which calls v0.1.0-alpha.2 the cascade-wire-up tag).
2. **Who owns the in-flight `registered_scope_json` work in hx_labs?** Three call sites with `None` placeholders suggest active development. Without knowing the owner, any SDK-side `RegistrationScopeAuthorizer` work would land in conflict.
3. **Should the inventory be corrected before the next Priority 2 prompt?** Three of three Priority 2 prompts so far have built on inventory premises that turned out to be stale. Option β fixes the upstream cause.
4. **Should the Priority 2-α prompt be retired, deferred to v6.8.0 cycle, or rewritten as a coordinated multi-repo workstream?** If retired, the alpha-2 closure simply ships as Option α. If deferred, the memo's design lands as part of v6.8.0 work. If rewritten, Option γ is the shape.

## State to clean up

- This halt-state doc is untracked on `feature/priority2-foundation-py-node-2026-05-17`. That branch is the active Python/Node Foundation branch; this doc isn't germane to it. Recommend moving the doc to `main` (uncommitted) or a dedicated `halt-state/alpha2-closure-2026-05-17` branch.
- No stashes created.
- No branches created.
- The `node/` directory is untracked on the working branch (pre-existing from the Python/Node Foundation workstream); not touched by this halt.

## Cross-references

- `docs/rsv_cascade_adapter_closure_2026-05-15.md` — the cascade-adapter wire-up closure report (the artifact the prompt's Phase 1 asks me to produce)
- `docs/rsv_adapter_helper_signatures.md` — Phase 0.4 verdict on why `RegistrationScopeAuthorizer` cannot be alpha-2 scope
- `~/Projects/hx_labs/docs/v6_8_design_memos/registration_scope_authorizer.md` — the design memo the prompt references; its own §3 estimates 700–800 LOC across 6 repos
- `~/Projects/hx_labs/docs/implementation_inventory_2026-05-17.md` — the upstream survey whose "Known unknowns" section drove the prompt's premise
- `~/Projects/hx_labs/docs/halt_state_priority2_foundation_2026-05-17.md` — first halt in this series
- `~/Projects/hx_labs/docs/halt_state_priority2_0a_2026-05-18.md` — second halt in this series
- `crates/haap-rsv/src/rsv.rs:110, :168` — the actual cascade call sites (proving wire-up exists)
- `crates/haap-rsv/src/authorizer.rs:1–32` — module-doc explaining the `RegistrationScopeAuthorizer` deferral rationale
- `~/Projects/hx_labs/crates/haap-server/src/caa_control_plane.rs:297, :575`, `~/Projects/hx_labs/crates/haap-caa-test-fixtures/src/fixtures.rs:56` — in-flight `registered_scope_json: None` placeholders
