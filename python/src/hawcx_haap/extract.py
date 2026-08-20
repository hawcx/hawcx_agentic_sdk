"""``hawcx extract`` -- draft a template from an existing agent's tool list.

Auto-wrap plan U8: *"Infer ids/actions from CrewAI/LangChain/MCP lists; never
guess RS URLs."* The point is that the next customer does not hand-write YAML.

WHAT IT WILL NOT DO, AND WHY THAT IS MOST OF THE DESIGN
------------------------------------------------------
Extraction is inference, and a template is the document an admin later publishes
into real authority. So every inference here is either conservative or refused
outright:

* **No endpoints, providers or bearers. Ever.** Not "left blank" -- absent from
  the output schema. They come from the org tool registry / EIB at runtime
  (Pattern Z). A URL guessed from a tool's description would be a plausible,
  wrong destination that survives review because it looks filled in.
* **No `constraints`, no `suggested_levels`.** Suggestions the extractor invented
  would be indistinguishable from suggestions a human considered.
* **`risk` is derived from the inferred action**, never guessed from the tool
  name, and is always the mildest value CONSISTENT with that action. Never
  `admin`, never `move_money`. Under-claiming is visible at review;
  over-claiming reads as authoritative and gets rubber-stamped; and
  contradicting the action (`write` + `read_public`, which the first version of
  this emitted) discredits the whole document.
* **Privileged verbs are refused, not downgraded.** A tool whose last segment is
  `refund`/`transfer`/… must be `move_money` (rule V14), which then requires
  `max_*` and `ciba_*` constraints (V15) that only a human can set. The extractor
  reports it for hand-completion instead of emitting a template that cannot
  validate — or worse, silently renaming the tool to dodge the rule.

Actions ARE inferred, because a wrong action is caught by the RSV rather than
being latent, and a template with no actions cannot validate at all. Inference is
prefix-based and every inferred tool is listed in the report so a reviewer knows
which lines were guessed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .template import ACTIONS, FRAMEWORKS, TEMPLATE_HEADER, validate_v1

__all__ = [
    "ExtractError",
    "ExtractReport",
    "extract_from_names",
    "extract_from_mcp_tools_list",
    "build_template",
]

# Verb prefixes -> TBAC action. Deliberately small: an unrecognised verb yields
# no inference and is reported, rather than being bucketed into a default that
# looks considered.
_READ_PREFIXES = (
    "get", "list", "read", "fetch", "search", "query", "find", "lookup",
    "describe", "show", "count", "check", "view",
)
_WRITE_PREFIXES = (
    "create", "add", "update", "set", "put", "post", "delete", "remove",
    "insert", "patch", "write", "upsert", "assign", "invite", "send", "archive",
)
_EXECUTE_PREFIXES = ("run", "execute", "invoke", "trigger", "start", "stop", "call")

# Mirrors template.PRIVILEGED_SUFFIXES (rule V14). Duplicated as a literal on
# purpose: importing it would couple the extractor's REFUSAL set to the
# validator's, and if the validator ever narrows its list the extractor should
# keep refusing until someone re-decides that deliberately.
_PRIVILEGED_SUFFIXES = frozenset({
    "refund", "transfer", "payout", "wire", "payment", "payments",
})

_SEGMENT_RE = re.compile(r"[a-z0-9_]+")

# Risk is DERIVED FROM THE INFERRED ACTION, not defaulted independently. The
# first version of this emitted `actions: ["write"], risk: "read_public"` — the
# lowest risk that validates — and that is worse than a guess: it is internally
# contradictory, and a reviewer who spots one such line rightly stops trusting
# the whole file. So each action maps to the mildest risk that is CONSISTENT with
# it. Still conservative (never `admin`, never `move_money` — those are refused
# or hand-set), just not self-contradicting.
_RISK_FOR_ACTION = {
    "read": "read_public",
    "write": "write_internal",
    "execute": "write_internal",
}


class ExtractError(Exception):
    """Extraction could not produce anything usable."""


@dataclass
class ExtractReport:
    """What was extracted, and -- more usefully -- what a human must still do."""

    tools: list[dict[str, Any]] = field(default_factory=list)
    #: (source name, reason) for tools left OUT of the template entirely.
    refused: list[tuple[str, str]] = field(default_factory=list)
    #: Source names whose actions were inferred from a verb prefix.
    inferred_actions: list[str] = field(default_factory=list)
    #: Source names that got no action inference and were defaulted.
    unknown_verbs: list[str] = field(default_factory=list)
    #: Source names rewritten to satisfy the id grammar.
    normalized: list[tuple[str, str]] = field(default_factory=list)

    @property
    def needs_review(self) -> bool:
        return bool(self.refused or self.unknown_verbs or self.normalized)


def _normalize_segment(text: str) -> str:
    """`AddGroupMember` / `add-group-member` -> `add_group_member`."""
    # camelCase -> snake, then fold anything else to `_`.
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    snake = re.sub(r"[^A-Za-z0-9]+", "_", snake).strip("_").lower()
    return "_".join(_SEGMENT_RE.findall(snake))


def _infer_actions(name: str) -> tuple[tuple[str, ...], bool]:
    """Return ``(actions, inferred)``. ``inferred=False`` means "defaulted"."""
    head = _normalize_segment(name).split("_")[0]
    if head in _READ_PREFIXES:
        return ("read",), True
    if head in _WRITE_PREFIXES:
        return ("write",), True
    if head in _EXECUTE_PREFIXES:
        return ("execute",), True
    # No recognised verb. Default to the least-privileged action that validates,
    # and REPORT it — a silent `execute` here would be the extractor inventing
    # capability.
    return ("read",), False


def extract_from_names(
    names: list[str], *, namespace: str, report: ExtractReport | None = None
) -> ExtractReport:
    """Build tool entries from bare tool names under *namespace*.

    A namespace is REQUIRED because the v1 id grammar is dotted
    (``[a-z0-9_]+(\\.[a-z0-9_]+)+``) and a bare `add_group_member` cannot satisfy
    it. Synthesising one (`tool.add_group_member`, say) would mint a HAAP tool
    identity out of nothing, and identity is what policy binds to.
    """
    rep = report or ExtractReport()
    ns = _normalize_segment(namespace)
    if not ns:
        raise ExtractError(
            f"namespace {namespace!r} normalises to nothing; it must contain "
            "at least one ASCII alphanumeric character"
        )

    seen: set[str] = set()
    for raw in names:
        seg = _normalize_segment(raw)
        if not seg:
            rep.refused.append((raw, "name normalises to an empty id segment"))
            continue

        # DELIBERATELY STRICTER THAN RULE V14, which inspects only the last
        # DOTTED segment (`tid.split(".")[-1]`). That lets `billing.wire_funds`
        # and `x.transfer_money` past the privileged-verb check entirely -- the
        # privileged word is there, just not last. Measured: `wire_funds` was
        # emitted as plain `write_internal` by the first version of this, and the
        # canonical validator accepts it too.
        #
        # An inference tool has no business being exactly as permissive as the
        # gate it feeds, so this checks EVERY segment. The V14 gap itself is a
        # spec matter and is reported separately; refusing here does not depend
        # on it being fixed.
        segments = set(seg.split("_"))
        if segments & _PRIVILEGED_SUFFIXES:
            rep.refused.append((
                raw,
                f"'{'/'.join(sorted(segments & _PRIVILEGED_SUFFIXES))}' is a privileged verb: "
                "rule V14 requires risk='move_money', "
                "which rule V15 then requires max_* and ciba_* constraints for. Those are "
                "a human decision -- add this tool by hand.",
            ))
            continue

        tool_id = f"{ns}.{seg}"
        if tool_id in seen:
            rep.refused.append((raw, f"duplicate id {tool_id} after normalisation"))
            continue
        seen.add(tool_id)
        if seg != raw:
            rep.normalized.append((raw, tool_id))

        actions, inferred = _infer_actions(raw)
        (rep.inferred_actions if inferred else rep.unknown_verbs).append(raw)
        rep.tools.append({
            "id": tool_id,
            "actions": list(actions),
            # Consistent with the action, and the mildest such value. See
            # `_RISK_FOR_ACTION`: under-claiming is visible at review,
            # over-claiming gets rubber-stamped, and CONTRADICTING the action
            # discredits the whole document.
            "risk": _RISK_FOR_ACTION[actions[0]],
        })
    return rep


def extract_from_mcp_tools_list(payload: Any, *, namespace: str) -> ExtractReport:
    """Extract from an MCP ``tools/list`` response (or its ``result``/``tools``).

    Accepts the whole JSON-RPC envelope, the ``result`` object, or a bare list,
    because all three are what people actually have on disk after capturing a
    session.
    """
    node = payload
    if isinstance(node, dict):
        node = node.get("result", node)
        node = node.get("tools", node)
    if not isinstance(node, list):
        raise ExtractError(
            "could not find a tools array: expected an MCP tools/list response, "
            "its `result`, or a bare list of tool objects"
        )
    names: list[str] = []
    rep = ExtractReport()
    for entry in node:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
            names.append(entry["name"])
        else:
            rep.refused.append((json.dumps(entry)[:60], "no string `name` field"))
    if not names and not rep.refused:
        raise ExtractError("the tools array is empty")
    return extract_from_names(names, namespace=namespace, report=rep)


def build_template(
    report: ExtractReport, *, name: str, version: str = "0.1.0", framework: str = "mcp-native"
) -> dict[str, Any]:
    """Assemble a `hawcx/agent-template/v1` from an extraction report.

    Validates before returning: an extractor that emits an invalid template has
    moved the failure from here to the reviewer's `hawcx validate` run, or worse
    to `submit`.
    """
    if not report.tools:
        raise ExtractError(
            "nothing extractable: every tool was refused. See the report -- "
            "privileged verbs and unnameable tools must be added by hand."
        )
    # `mcp-native` is what the plan calls this lane, but the SCHEMA's enum is the
    # authority and does not contain it. Fail with the accepted set rather than
    # silently substituting a framework the agent does not use.
    if framework not in FRAMEWORKS:
        raise ExtractError(
            f"framework {framework!r} is not accepted by hawcx/agent-template/v1 "
            f"(accepted: {', '.join(sorted(FRAMEWORKS))})"
        )
    doc = {
        "template": TEMPLATE_HEADER,
        "name": name,
        "version": version,
        "framework": {"kind": framework},
        "tools": report.tools,
        # No `constraints`, no `suggested_levels`, no endpoints. See the module
        # docstring — their absence is the design, not an omission.
    }
    errors = validate_v1(doc)
    if errors:
        raise ExtractError(
            "the extracted template does not validate "
            f"({', '.join(f'{c} at {p}' for c, p in errors)}). This is a bug in the "
            "extractor, not in your tool list -- please report it."
        )
    return doc


# Sanity: the inference tables must only ever produce valid actions. A typo here
# would surface as an E_BAD_ACTION on a user's extracted template, blamed on
# their tool list.
assert {"read", "write", "execute"} <= ACTIONS
