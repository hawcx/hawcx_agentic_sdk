"""``hawcx/agent-template/v1`` loading + validation.

Auto-wrap plan U1/U2 (`hx_agent_canonical_spec/docs/plans/auto-wrap-tool-calls-2026-08-17.md`).

WHY THIS LIVES IN THE CORE PACKAGE
----------------------------------
The scaffolder (:mod:`hawcx_haap.wrap`) must refuse to generate from an invalid
template, and the CLI's ``validate`` subcommand needs the same answer. One
implementation, not two — a second copy is how the generator and the validator
drift into disagreeing about what is acceptable.

THE ORACLE IS NOT THIS FILE
---------------------------
The normative accept/deny behaviour is the reference validator in
``hx_agent_canonical_spec/spec/conformance/test_vectors_template.py``
(``validate_v1``), pinned by the vector set at
``spec/conformance/vectors/agent-template-v1.json``. This module is an
*implementation* of those rules (schema doc §2, V1–V17), and
``tests/test_template_conformance.py`` replays the canonical vector set through
it to prove they agree. If the two ever disagree, the canonical one is right.

SUGGESTION IS NEVER AUTHORITY
-----------------------------
The load-bearing rule (plan §1): a template is a *description*. Authority
attaches at publish/assign and is enforced by HAAP. A template that claims
authority is ``E_AUTHORITY_CLAIM`` — **rejected, never stripped**. Stripping
would silently turn a caller's authority claim into a valid submission, which
is exactly the failure the fence exists to prevent.
"""

from __future__ import annotations

import json
import re
from typing import Any

__all__ = [
    "TEMPLATE_HEADER",
    "ACTIONS",
    "FRAMEWORKS",
    "RISK_ENUM",
    "TemplateError",
    "load_template",
    "validate_v1",
    "tool_entries",
]

TEMPLATE_HEADER = "hawcx/agent-template/v1"

# V2 — a key claiming authority ANYWHERE in the document invalidates it. Matched
# case-insensitively at every depth, not just the top level, because
# `suggested_levels.L1.approved` is the same claim wearing a nested costume.
AUTHORITY_KEYS = frozenset({
    "granted_scopes", "granted", "authority", "approved", "approval",
    "policy", "policy_set", "policyset", "signature", "signatures", "signed",
    "assigned", "assignments", "publish_status", "published", "auto_approve",
    "scope_ceiling", "org_token", "ciba_waiver",
})
RISK_ENUM = frozenset({
    "read_public", "read_internal", "read_financial",
    "write_internal", "move_money", "admin",
})
ACTIONS = frozenset({"read", "write", "execute"})
FRAMEWORKS = frozenset({"crewai", "langchain", "composio", "openshell", "visual"})
TOP_KEYS = frozenset({
    "template", "name", "version", "framework", "tools",
    "constraints", "suggested_levels",
})
REQUIRED_TOP = frozenset({"template", "name", "version", "framework", "tools"})
# V14 — a privileged-looking verb must be declared `move_money`. Stops
# `stripe.refund` being smuggled in as `read_public`.
PRIVILEGED_SUFFIXES = frozenset({
    "refund", "transfer", "payout", "wire", "payment", "payments",
})

_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
_TOOL_ID_RE = re.compile(r"[a-z0-9_]+(\.[a-z0-9_]+)+")


class TemplateError(Exception):
    """Raised when a template cannot be loaded or is invalid.

    ``errors`` carries the full ``[(code, json_path), ...]`` list rather than
    only the first, so the CLI can print every problem in one pass instead of
    making the developer fix them one round-trip at a time.
    """

    def __init__(self, message: str, errors: list[tuple[str, str]] | None = None):
        super().__init__(message)
        self.errors: list[tuple[str, str]] = errors or []


def _scan_authority(node: Any, path: str, errs: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in AUTHORITY_KEYS:
                errs.append(("E_AUTHORITY_CLAIM", f"{path}.{k}"))
            _scan_authority(v, f"{path}.{k}", errs)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan_authority(v, f"{path}[{i}]", errs)


def validate_v1(doc: Any) -> list[tuple[str, str]]:
    """Return ``[]`` iff *doc* is a valid ``hawcx/agent-template/v1``.

    Otherwise a list of ``(error_code, json_path)``. Deterministic and
    key-order independent (canonical property TPL-P2) — callers may compare
    two results directly.
    """
    if not isinstance(doc, dict):
        return [("E_ROOT_TYPE", "$")]

    errs: list[tuple[str, str]] = []
    _scan_authority(doc, "$", errs)                                    # V2

    if doc.get("template") != TEMPLATE_HEADER:                         # V3
        errs.append(("E_TEMPLATE_HEADER", "$.template"))
    for k in sorted(REQUIRED_TOP - set(doc)):                          # V4
        errs.append(("E_MISSING_KEY", f"$.{k}"))
    for k in sorted(set(doc) - TOP_KEYS):                              # V5 fail-closed
        # An authority key is already reported by V2; reporting it twice under a
        # second code would make the CLI output read as two separate problems.
        if not (isinstance(k, str) and k.lower() in AUTHORITY_KEYS):
            errs.append(("E_UNKNOWN_KEY", f"$.{k}"))

    name = doc.get("name")
    if not (isinstance(name, str) and _NAME_RE.fullmatch(name)):        # V6
        errs.append(("E_BAD_NAME", "$.name"))
    version = doc.get("version")
    if not (isinstance(version, str) and _VERSION_RE.fullmatch(version)):  # V7
        errs.append(("E_BAD_VERSION", "$.version"))
    framework = doc.get("framework")
    if not (isinstance(framework, dict) and framework.get("kind") in FRAMEWORKS):  # V8
        errs.append(("E_BAD_FRAMEWORK", "$.framework"))

    tools = doc.get("tools")
    if not (isinstance(tools, list) and tools):                        # V9
        errs.append(("E_TOOLS_EMPTY", "$.tools"))
        tools = []

    ids: list[str] = []
    for i, tool in enumerate(tools):
        path = f"$.tools[{i}]"
        if not (isinstance(tool, dict) and {"id", "actions", "risk"} <= set(tool)):
            errs.append(("E_BAD_TOOL", path))
            continue
        tid = tool["id"]
        # `isascii()` matters: without it a Cyrillic homoglyph passes the regex
        # under Python's Unicode-aware character classes and two visually
        # identical tool ids become distinct principals.
        if not (isinstance(tid, str) and tid.isascii() and _TOOL_ID_RE.fullmatch(tid)):
            errs.append(("E_BAD_TOOL", path + ".id"))
            continue
        if tid in ids:                                                 # V11
            errs.append(("E_DUP_TOOL_ID", path + ".id"))
        ids.append(tid)

        actions = tool["actions"]
        if not (isinstance(actions, list) and actions and set(actions) <= ACTIONS):  # V12
            errs.append(("E_BAD_ACTION", path + ".actions"))
        risk = tool["risk"]
        if risk not in RISK_ENUM:                                      # V13
            errs.append(("E_BAD_RISK", path + ".risk"))
        if tid.split(".")[-1] in PRIVILEGED_SUFFIXES and risk != "move_money":  # V14
            errs.append(("E_RISK_SMUGGLE", path))
        if risk == "move_money":                                       # V15
            cons = doc.get("constraints")
            entry = cons.get(tid) if isinstance(cons, dict) else None
            if not (isinstance(entry, dict) and any(str(k).startswith("max_") for k in entry)):
                errs.append(("E_MISSING_CEILING", f"$.constraints.{tid}"))
            if not (isinstance(entry, dict) and any(str(k).startswith("ciba_") for k in entry)):
                errs.append(("E_MISSING_CIBA", f"$.constraints.{tid}"))

    constraints = doc.get("constraints")
    if constraints is not None:
        if not isinstance(constraints, dict):
            errs.append(("E_BAD_CONSTRAINTS", "$.constraints"))
        else:
            for k in constraints:                                      # V16
                if k not in ids:
                    errs.append(("E_UNKNOWN_CONSTRAINT_REF", f"$.constraints.{k}"))
    return errs


def _parse(text: str, *, path_hint: str) -> Any:
    """Parse YAML or JSON without making PyYAML a hard dependency.

    ``hawcx-haap`` ships ``dependencies = []`` on purpose. JSON is handled by
    the stdlib; YAML imports lazily so a JSON template works in an environment
    with no PyYAML at all, and the missing-dependency error names the extra to
    install instead of surfacing a bare ImportError.
    """
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise TemplateError(f"{path_hint}: invalid JSON: {e}") from e
    try:
        import yaml  # noqa: PLC0415 — lazy on purpose, see above
    except ImportError as e:
        raise TemplateError(
            f"{path_hint} looks like YAML but PyYAML is not installed. "
            "Install the CLI extra (`pip install 'hawcx-haap[cli]'`) or supply "
            "the template as JSON."
        ) from e
    try:
        # `safe_load` is not a style preference: `yaml.load` would construct
        # arbitrary Python objects from a template, and templates arrive from
        # developers and (post-submit) from other orgs. The canonical fuzz
        # corpus has an `unsafe_tag` category for exactly this.
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise TemplateError(f"{path_hint}: invalid YAML: {e}") from e


def load_template(source: str | bytes, *, path_hint: str = "<template>") -> dict[str, Any]:
    """Parse and validate a template. Returns the document, or raises.

    Raising rather than returning ``(doc, errors)`` is deliberate: every caller
    in this package must not proceed on an invalid template, and an ignored
    error list is easier to write than a swallowed exception.
    """
    if isinstance(source, bytes):
        try:
            source = source.decode("utf-8")
        except UnicodeDecodeError as e:
            raise TemplateError(f"{path_hint}: not valid UTF-8: {e}") from e
    doc = _parse(source, path_hint=path_hint)
    errors = validate_v1(doc)
    if errors:
        detail = ", ".join(f"{c} at {p}" for c, p in errors)
        raise TemplateError(f"{path_hint}: {len(errors)} validation error(s): {detail}", errors)
    return doc


def tool_entries(doc: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    """The ONLY projection the generator is allowed to see: ``(id, actions)``.

    Plan §1: *"Path 2 generates from ``tools[].{id, actions}`` only. It must not
    bake ``constraints`` or ``suggested_levels`` into generated code."* Those are
    suggestions, and a suggestion compiled into a shipped artifact starts
    behaving like a control. Endpoints, providers and bearers are likewise absent
    — they come from the org tool registry / EIB at runtime (Pattern Z).

    Returning a narrow projection rather than the raw dicts is what makes that
    rule enforceable instead of aspirational: the generator cannot reach a field
    it was never handed.
    """
    return [(t["id"], tuple(t["actions"])) for t in doc["tools"]]
