"""The LangChain M365 example, pinned against the two files it must agree with.

The example is a bridge between two vocabularies that live in other files: the
agent template's DOTTED HAAP tool ids, and the downstream MCP server's KEBAB
tool names. Nothing else checks that bridge, so a rename in either file would
otherwise surface at demo time as an agent that silently never calls a tool.

These tests import only ``ToolSpec``/``TOOL_SPECS`` — plain data — so they run
without LangChain or pydantic installed. The adaptation itself
(``build_m365_tools``) imports LangChain lazily for exactly that reason.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

from hawcx_haap.template import ACTIONS, RISK_ENUM, load_template

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
_TEMPLATE = _EXAMPLES / "m365_agent_template.yaml"
_EXAMPLE = _EXAMPLES / "langchain_integration.py"


def _load_example():
    """Import the example by path — `examples/` is not an installed package."""
    name = "langchain_integration"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register BEFORE exec: @dataclass resolves its annotations through
    # sys.modules[cls.__module__], which is None for a module that was created
    # from a spec but never registered.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        del sys.modules[name]
        raise
    return module


def _load_agent_template() -> dict:
    text = _TEMPLATE.read_text(encoding="utf-8")
    try:
        return load_template(text, path_hint=str(_TEMPLATE))
    except Exception as e:  # noqa: BLE001 - PyYAML is a CLI extra, not a test dep
        if "PyYAML" in str(e):
            pytest.skip("PyYAML not installed (CLI extra); template parse skipped")
        raise


def test_the_shipped_agent_template_is_valid():
    """`hawcx validate` in test form: the example's template must load."""
    doc = _load_agent_template()
    assert doc["framework"]["kind"] == "langchain"
    for tool in doc["tools"]:
        assert set(tool["actions"]) <= ACTIONS
        assert tool["risk"] in RISK_ENUM


def test_every_spec_names_a_tool_id_the_template_actually_requests():
    """A spec pointing at an id absent from the template is unbuildable.

    `build_m365_tools` raises on this at construction, but only when someone
    runs it with a generated module to hand — which is after the demo has been
    set up. Catch it here instead.
    """
    doc = _load_agent_template()
    template_ids = {t["id"] for t in doc["tools"]}
    module = _load_example()
    for spec in module.TOOL_SPECS:
        assert spec.tool_id in template_ids, (
            f"{spec.mcp_name} binds to {spec.tool_id!r}, which the agent template "
            "does not request"
        )


def test_the_template_and_the_specs_account_for_each_other_exactly():
    """No template id is silently unreachable, and none is silently dropped.

    Every requested id must either back at least one LangChain tool or be
    listed as unimplemented. Without this, deleting a spec would quietly shrink
    what the agent can do while the template still claims the entitlement.
    """
    doc = _load_agent_template()
    template_ids = {t["id"] for t in doc["tools"]}
    module = _load_example()
    exposed = {spec.tool_id for spec in module.TOOL_SPECS}
    accounted = exposed | set(module.UNIMPLEMENTED_TOOL_IDS)
    assert accounted == template_ids, (
        "template ids and example coverage disagree: "
        f"unaccounted={template_ids - accounted}, unknown={accounted - template_ids}"
    )
    # An id cannot be both exposed and declared unimplemented.
    assert not (exposed & set(module.UNIMPLEMENTED_TOOL_IDS))


def test_specs_are_well_formed_for_langchain():
    """Names, uniqueness, and argument shapes LangChain will not tolerate."""
    module = _load_example()
    seen: set[str] = set()
    for spec in module.TOOL_SPECS:
        assert spec.mcp_name and spec.mcp_name.islower()
        # LangChain tool names must be identifier-safe; the adapter converts
        # dashes, so the converted form is what has to be unique and valid.
        converted = spec.mcp_name.replace("-", "_")
        assert converted.isidentifier(), f"{spec.mcp_name} is not identifier-safe"
        assert converted not in seen, f"duplicate tool name {converted}"
        seen.add(converted)
        assert spec.description.strip(), f"{spec.mcp_name} has no description"
        for arg, triple in spec.args.items():
            assert arg.isidentifier(), f"{spec.mcp_name}.{arg} is not a valid argument name"
            py_type, required, desc = triple
            assert isinstance(py_type, type)
            assert isinstance(required, bool)
            assert desc.strip(), f"{spec.mcp_name}.{arg} has no description"


def test_write_tools_require_their_target_explicitly():
    """A mutation must not have an all-optional signature.

    A write tool whose arguments are all optional can be called with none of
    them, which is how an agent ends up issuing an unscoped mutation that the
    ceiling's argument predicates then cannot constrain — `member_of_set`
    resolves Absent and denies, so the failure reads as a permission bug rather
    than a missing argument.
    """
    doc = _load_agent_template()
    writes = {t["id"] for t in doc["tools"] if "write" in t["actions"]}
    module = _load_example()
    for spec in module.TOOL_SPECS:
        if spec.tool_id in writes:
            required = [a for a, (_, req, _) in spec.args.items() if req]
            assert required, f"{spec.mcp_name} is a write tool with no required argument"


@pytest.mark.parametrize("tool_map_path", [
    pathlib.Path(__file__).resolve().parents[3] / "hx_m365_sync" / "tool_map.json",
])
def test_the_bridge_matches_tool_map_json_when_it_is_available(tool_map_path):
    """`tool_map.json` is the mapping's home; this file must not diverge from it.

    Skipped when the sibling repo is not checked out — the example has to stand
    alone in a clone of just this repo — but when it IS present, a disagreement
    is a real defect: the same pair drives the gateway's routing map, so a
    mismatch here means the agent calls something the gateway will not route.
    """
    if not tool_map_path.exists():
        pytest.skip("hx_m365_sync not checked out alongside this repo")
    doc = json.loads(tool_map_path.read_text(encoding="utf-8"))
    canonical: dict[str, str] = {}
    for entry in doc["tools"]:
        for mcp in entry.get("mcp_tools") or []:
            canonical[mcp] = entry["tool_id"]

    module = _load_example()
    for spec in module.TOOL_SPECS:
        assert spec.mcp_name in canonical, (
            f"{spec.mcp_name} is not an MCP tool name tool_map.json knows"
        )
        assert canonical[spec.mcp_name] == spec.tool_id, (
            f"{spec.mcp_name}: example binds {spec.tool_id!r}, "
            f"tool_map.json says {canonical[spec.mcp_name]!r}"
        )

    # And the reverse: an MCP tool tool_map.json knows, for an id this agent
    # requests, must be exposed — otherwise the agent silently cannot make a
    # call the deployment believes it can.
    requested = {t["id"] for t in _load_agent_template()["tools"]}
    exposed = {spec.mcp_name for spec in module.TOOL_SPECS}
    for mcp, tid in canonical.items():
        if tid in requested:
            assert mcp in exposed, (
                f"tool_map.json maps {mcp} -> {tid}, which this agent requests, "
                "but the example exposes no tool for it"
            )
