"""The LangChain M365 example, pinned against the contracts it actually binds to.

The example bridges two vocabularies that live elsewhere: the dotted HAAP tool
ids policy is written against, and the kebab MCP names `params.name` carries.

An earlier version of this file cross-checked that bridge against
`hx_m365_sync/tool_map.json` **when the sibling repo happened to be checked out
alongside** — and skipped otherwise, silently, in most trees including the
reviewer's. A test that skips in the environment where a rename would land is
not coverage. The mapping is now vendored as
`examples/m365_tool_map.fixture.json`, so these tests run everywhere, and the
upstream comparison became a STALENESS check that fails on drift rather than
skipping past it.

These import only plain data — no LangChain, no pydantic — so they run in a
bare test env. The adaptation imports LangChain lazily for that reason.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
_TEMPLATE = _EXAMPLES / "m365_agent_template.yaml"
_EXAMPLE = _EXAMPLES / "langchain_integration.py"
_FIXTURE = _EXAMPLES / "m365_tool_map.fixture.json"
_UPSTREAM = (
    pathlib.Path(__file__).resolve().parents[3] / "hx_m365_sync" / "tool_map.json"
)


def _load_example():
    """Import the example by path — `examples/` is not an installed package."""
    name = "langchain_integration"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register BEFORE exec: @dataclass resolves annotations through
    # sys.modules[cls.__module__], which is None for an unregistered module.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        del sys.modules[name]
        raise
    return module


def _fixture() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _subset_digest(tools: list[dict]) -> str:
    """The same canonicalization the vendoring step used."""
    return hashlib.sha256(
        json.dumps(tools, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# ── The vendored fixture ─────────────────────────────────────────────────────


def test_the_fixture_matches_its_own_recorded_digest():
    """Catches a hand-edit of the vendored copy, which is explicitly forbidden."""
    fx = _fixture()
    assert _subset_digest(fx["tools"]) == fx["upstream_sha256"], (
        "m365_tool_map.fixture.json was edited by hand — re-vendor it from "
        "hx_m365_sync/tool_map.json instead"
    )


def test_the_fixture_is_not_stale_against_upstream():
    """STALENESS check, not a cross-repo import.

    Skips only when the sibling repo genuinely is not present — but unlike the
    version this replaces, the fixture means every other assertion in this file
    still runs in that case. Here, a skip costs one check rather than all of
    them.
    """
    if not _UPSTREAM.exists():
        pytest.skip("hx_m365_sync not checked out alongside; fixture digest still enforced")
    upstream = json.loads(_UPSTREAM.read_text(encoding="utf-8"))
    subset = [
        {
            "tool_id": t["tool_id"],
            "label": t.get("label"),
            "mcp_tools": t.get("mcp_tools") or [],
            "routing": t.get("routing"),
        }
        for t in upstream["tools"]
    ]
    assert _subset_digest(subset) == _fixture()["upstream_sha256"], (
        "tool_map.json has drifted from the vendored fixture. Re-vendor it — a "
        "rename upstream silently breaks the demo otherwise."
    )


def test_the_provider_is_the_one_the_scope_gate_matches():
    """`o365` finds no mapping in the armed PolicySet and refuses every call."""
    module = _load_example()
    assert module.PROVIDER == "microsoft-graph"
    providers = {
        t["routing"]["provider"] for t in _fixture()["tools"] if t.get("routing")
    }
    assert providers == {"microsoft-graph"}


# ── The tool surface handed to the model ─────────────────────────────────────


def test_every_callable_tool_has_a_schema_and_a_description():
    """The one hand-authored table must cover exactly the callable surface.

    Without this the provisional schemas could drift out of step with the ids —
    which is what made the previous free-standing spec table objectionable.
    """
    module = _load_example()
    callable_names = {
        name for t in _fixture()["tools"] for name in t["mcp_tools"]
    }
    assert set(module.ARGUMENT_SCHEMAS) == callable_names
    assert set(module.DESCRIPTIONS) == callable_names
    for name, schema in module.ARGUMENT_SCHEMAS.items():
        for arg, (py_type, required, desc) in schema.items():
            assert arg.isidentifier(), f"{name}.{arg} is not a valid argument name"
            assert isinstance(py_type, type)
            assert isinstance(required, bool)
            assert desc.strip(), f"{name}.{arg} has no description"


def test_unimplemented_ids_are_derived_not_hand_maintained():
    """They must follow the fixture, so implementing one upstream fixes this."""
    module = _load_example()
    expected = {t["tool_id"] for t in _fixture()["tools"] if not t["mcp_tools"]}
    assert module.unimplemented_tool_ids() == expected
    # Sanity: today that is exactly the two with no MCP tool.
    assert expected == {"o365.users.write", "o365.applications.read"}


def test_mcp_tools_carry_both_identifiers_and_the_routing_tuple():
    """The whole point: one object holding the scope AND the route.

    `tool_id` is what the Assembler mints against; `name` is what `params.name`
    carries and the RSV routes on. A tool built with only one of them cannot
    both be authorized and be delivered.
    """
    module = _load_example()
    tools = module.m365_tools(endpoint="https://gw.example/mcp")
    by_name = {t.name: t for t in tools}

    # Not 1:1 — one id backs two names, which is why tools are per MCP name.
    assert by_name["list-groups"].tool_id == "o365.groups.read"
    assert by_name["get-group"].tool_id == "o365.groups.read"
    assert by_name["add-group-member"].tool_id == "o365.groups.members_write"
    assert by_name["remove-group-member"].tool_id == "o365.groups.members_write"

    for t in tools:
        assert t.tool_id and t.name and t.url
        assert t.name != t.tool_id, "the two vocabularies must not be conflated"
        assert t.actions, f"{t.name} has no action; the mint would be unscoped"
        assert t.resource, f"{t.name} has no resource"

    # Every callable fixture tool is present, and nothing else is.
    assert set(by_name) == {n for t in _fixture()["tools"] for n in t["mcp_tools"]}


def test_write_tools_require_their_target_explicitly():
    """A mutation must not have an all-optional signature.

    A write callable with every argument optional can be invoked with none of
    them, which is how an agent issues an unscoped mutation that the ceiling's
    argument predicates then cannot constrain — `member_of_set` resolves Absent
    and denies, so it reads as a permission bug rather than a missing argument.
    """
    module = _load_example()
    writes = {
        name
        for t in _fixture()["tools"]
        if (t.get("routing") or {}).get("action") == "write"
        for name in t["mcp_tools"]
    }
    for name in writes:
        required = [a for a, (_, req, _) in module.ARGUMENT_SCHEMAS[name].items() if req]
        assert required, f"{name} is a write tool with no required argument"


# ── The wire request ─────────────────────────────────────────────────────────


def test_the_built_request_carries_a_json_rpc_body_naming_the_mcp_tool():
    """The defect this rewrite fixes, pinned.

    The previous version called `agent.invoke()` with no `body`, so no JSON-RPC
    document existed and `params.name` was never set — the RSV forwarded an
    empty POST and there was nothing to route on. `Caller.invoke_kwargs` is the
    supported way to build it, so assert against that rather than reimplementing
    the envelope here.
    """
    from hawcx_haap.mcp_caller import Caller

    module = _load_example()
    tool = next(
        t for t in module.m365_tools(endpoint="https://gw.example/mcp")
        if t.name == "add-group-member"
    )
    kwargs = Caller(provider=module.PROVIDER).invoke_kwargs(
        tool, "employee@hawcx.com", {"group_id": "g-1", "user_id": "u-1"}
    )

    # The dotted id goes on `tool=` (the TBAC scope)...
    assert kwargs["tool"] == "o365.groups.members_write"
    # ...and the kebab name goes in the JSON-RPC body (the route).
    body = json.loads(kwargs["body"])
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "add-group-member"
    assert body["params"]["arguments"] == {"group_id": "g-1", "user_id": "u-1"}
    # No stray routing hint smuggled in as an argument — the old `mcp_tool=`
    # kwarg landed here and would have reached Graph as a bogus field.
    assert "mcp_tool" not in body["params"]["arguments"]
    # `provider` set is what selects the /proxy path this demo is pinned to.
    assert kwargs["provider"] == "microsoft-graph"
    assert kwargs["content_type"] == "application/json"


def test_the_agent_never_forges_the_hawcx_meta_envelope():
    """`params._meta` is the Assembler's to write; an agent writing it forges
    the one thing it is supposed to be unable to forge (§45.7.5)."""
    from hawcx_haap.mcp_caller import Caller

    module = _load_example()
    tool = module.m365_tools(endpoint="https://gw.example/mcp")[0]
    body = json.loads(
        Caller(provider=module.PROVIDER).invoke_kwargs(tool, "e@hawcx.com", {})["body"]
    )
    assert "_meta" not in body["params"]


# ── The agent template ───────────────────────────────────────────────────────


def test_the_template_and_the_fixture_account_for_each_other():
    """Every requested id is either callable or declared unimplemented."""
    from hawcx_haap.template import ACTIONS, RISK_ENUM, load_template

    try:
        doc = load_template(_TEMPLATE.read_text(encoding="utf-8"), path_hint=str(_TEMPLATE))
    except Exception as e:  # noqa: BLE001 - PyYAML is a CLI extra, not a test dep
        if "PyYAML" in str(e):
            pytest.skip("PyYAML not installed (CLI extra)")
        raise

    assert doc["framework"]["kind"] == "langchain"
    for tool in doc["tools"]:
        assert set(tool["actions"]) <= ACTIONS
        assert tool["risk"] in RISK_ENUM

    module = _load_example()
    template_ids = {t["id"] for t in doc["tools"]}
    callable_ids = {t.tool_id for t in module.m365_tools(endpoint="https://gw.example/mcp")}
    accounted = callable_ids | module.unimplemented_tool_ids()
    assert accounted == template_ids, (
        f"unaccounted={template_ids - accounted}, unknown={accounted - template_ids}"
    )
    assert not (callable_ids & module.unimplemented_tool_ids())
