"""`hawcx wrap` generator + CLI. Auto-wrap plan U1."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import textwrap

import pytest

from hawcx_haap.template import TemplateError, load_template
from hawcx_haap.wrap import GenerationError, class_name_for, generate_module

UKG_O365 = {
    "template": "hawcx/agent-template/v1",
    "name": "o365-group-assistant",
    "version": "0.1.0",
    "framework": {"kind": "langchain", "min": "0.3"},
    "tools": [
        {"id": "o365.group.add_member", "actions": ["write"], "risk": "write_internal"},
        {"id": "o365.mail.read", "actions": ["read"], "risk": "read_internal"},
    ],
    "constraints": {"o365.group.add_member": {"resource_prefix": "group:ukg-poc-"}},
    "suggested_levels": {
        "L0": {"tools": ["o365.mail.read"]},
        "L1": {"tools": ["o365.mail.read", "o365.group.add_member"]},
    },
}


def _string_literals(source: str) -> set[str]:
    """Every string constant in the generated module, docstrings EXCLUDED.

    A `grep` for leaked template data matches the generator's own prose about
    what it excludes — measured, that is exactly what happened first. Comparing
    AST string constants while skipping docstrings tests the code, not the
    commentary.
    """
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            d = ast.get_docstring(node, clean=False)
            if d is not None:
                docstrings.add(d)
    return {
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value not in docstrings
    }


def test_generated_module_is_valid_python_and_deterministic():
    a = generate_module(UKG_O365)
    b = generate_module(UKG_O365)
    ast.parse(a)
    assert a == b, "regeneration must be byte-identical (no timestamp by default)"


def test_stamp_time_is_opt_in():
    assert "Generated at" not in generate_module(UKG_O365)
    assert "Generated at" in generate_module(UKG_O365, stamp_time=True)


def test_suggestions_never_reach_generated_code():
    """Plan §1: generate from tools[].{id,actions} ONLY.

    `constraints` and `suggested_levels` are suggestions. Compiled into a shipped
    artifact they would start behaving like controls, which is the exact
    confusion the authority fence exists to prevent.
    """
    literals = _string_literals(generate_module(UKG_O365))
    for leaked in ("group:ukg-poc-", "resource_prefix", "L0", "L1", "write_internal",
                   "read_internal"):
        assert leaked not in literals, f"{leaked!r} leaked into generated code"
    # ...while the two things it IS allowed to carry are present.
    assert "o365.group.add_member" in literals
    assert "write" in literals


def test_risk_is_not_emitted_even_though_the_schema_requires_it():
    """`risk` is required by the schema but is not in the generator's projection.
    Worth its own test: it is the field most likely to be added 'for context'."""
    assert "read_internal" not in _string_literals(generate_module(UKG_O365))


@pytest.mark.parametrize("tool_id,expected", [
    ("o365.mail.read", "O365MailReadTool"),
    ("o365.group.add_member", "O365GroupAddMemberTool"),
    ("salesforce.opportunity.update", "SalesforceOpportunityUpdateTool"),
    ("a.b", "ABTool"),
    ("9lives.cat.read", "Tool9livesCatReadTool"),   # ids may start with a digit
])
def test_class_names(tool_id, expected):
    assert class_name_for(tool_id) == expected


def test_colliding_class_names_fail_closed():
    """`a.b_c` and `a.b.c` both normalise to `ABCTool`. Emitting one class for two
    tool ids would make the second tool's calls carry the first tool's identity."""
    doc = {**UKG_O365, "tools": [
        {"id": "a.b_c", "actions": ["read"], "risk": "read_internal"},
        {"id": "a.b.c", "actions": ["read"], "risk": "read_internal"},
    ], "constraints": {}}
    with pytest.raises(GenerationError, match="both generate class"):
        generate_module(doc)


def test_generated_tools_are_importable_and_wired(tmp_path):
    mod = tmp_path / "gen.py"
    mod.write_text(generate_module(UKG_O365))
    sys.path.insert(0, str(tmp_path))
    try:
        import importlib
        gen = importlib.import_module("gen")
        assert set(gen.TOOLS) == {"o365.group.add_member", "o365.mail.read"}
        assert gen.TOOLS["o365.mail.read"].ACTIONS == ("read",)

        # endpoint is required — fail closed rather than reaching the Assembler
        # with an empty target.
        with pytest.raises(ValueError, match="endpoint is required"):
            gen.TOOLS["o365.mail.read"](object(), "")
        # the base class is abstract
        with pytest.raises(ValueError, match="abstract"):
            gen._HawcxGeneratedTool(object(), "https://x")

        # build_tools fails closed in BOTH directions
        with pytest.raises(ValueError, match="no endpoint supplied"):
            gen.build_tools(object(), {"o365.mail.read": "https://x"})
        with pytest.raises(ValueError, match="undeclared tool"):
            gen.build_tools(object(), {
                "o365.mail.read": "https://x",
                "o365.group.add_member": "https://y",
                "o365.calendar.write": "https://z",
            })
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("gen", None)


def test_invoke_is_called_with_the_template_identity(tmp_path):
    """The point of the whole generator: tool identity and actions on the wire
    come from the template, and no credential is handled here."""
    mod = tmp_path / "gen2.py"
    mod.write_text(generate_module(UKG_O365))
    sys.path.insert(0, str(tmp_path))
    try:
        import importlib
        gen = importlib.import_module("gen2")

        seen = {}

        class FakeAgent:
            def invoke(self, **kw):
                seen.update(kw)
                return "ok"

        tool = gen.TOOLS["o365.group.add_member"](FakeAgent(), "https://graph/x", provider="graph")
        assert tool(groupId="g", userId="u") == "ok"
        assert seen["tool"] == "o365.group.add_member"
        assert seen["action"] == ("write",)
        assert seen["target_rs_url"] == "https://graph/x"
        assert seen["tool_arguments"] == {"groupId": "g", "userId": "u"}
        assert "headers" not in seen or not seen.get("headers")
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("gen2", None)


# ── CLI ──────────────────────────────────────────────────────────────────────

def _cli(*args, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "hawcx_haap.cli", *args],
        capture_output=True, text=True, input=stdin,
    )


def test_cli_validate_accepts_and_rejects(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(UKG_O365))
    assert _cli("validate", str(good)).returncode == 0

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**UKG_O365, "granted_scopes": ["everything"]}))
    r = _cli("validate", str(bad))
    assert r.returncode == 1
    assert "E_AUTHORITY_CLAIM" in r.stderr
    # The fence must be EXPLAINED, not just coded — a bare error code invites
    # someone to "fix" it by stripping the key in their own tooling.
    assert "rejected rather than stripped" in r.stderr


def test_cli_wrap_refuses_to_clobber(tmp_path):
    t = tmp_path / "t.json"
    t.write_text(json.dumps(UKG_O365))
    out = tmp_path / "out.py"
    assert _cli("wrap", str(t), "-o", str(out)).returncode == 0
    edited = out.read_text() + "\n# a developer edited this\n"
    out.write_text(edited)
    r = _cli("wrap", str(t), "-o", str(out))
    assert r.returncode == 1 and "--force" in r.stderr
    assert out.read_text() == edited, "must not overwrite without --force"
    assert _cli("wrap", str(t), "-o", str(out), "--force").returncode == 0
    assert "a developer edited this" not in out.read_text()


def test_cli_has_no_submit_subcommand_yet():
    """Plan U2 pairs validate with `submit --org`, but the console endpoint it
    pushes to is U3 and does not exist. An unknown-subcommand error is honest; a
    subcommand that parsed the flags and failed at the network would read as an
    outage rather than an unbuilt feature."""
    r = _cli("submit", "--org", "ukg", "x.yaml")
    assert r.returncode != 0
    assert "invalid choice" in r.stderr or "submit" in r.stderr


def test_yaml_path_needs_no_pyyaml_for_json():
    """`dependencies = []` is deliberate. A JSON template must work with zero
    extras installed, which is why the yaml import is lazy."""
    doc = load_template(json.dumps(UKG_O365), path_hint="j.json")
    assert doc["name"] == "o365-group-assistant"


def test_yaml_template_loads_when_pyyaml_present():
    yaml = pytest.importorskip("yaml")  # noqa: F841
    doc = load_template(textwrap.dedent("""
        template: hawcx/agent-template/v1
        name: sf-lead
        version: 0.1.0
        framework: {kind: langchain}
        tools:
          - id: salesforce.lead.read
            actions: [read]
            risk: read_internal
    """), path_hint="t.yaml")
    assert doc["tools"][0]["id"] == "salesforce.lead.read"


def test_unsafe_yaml_tag_is_refused():
    """Templates arrive from developers and, post-submit, from other orgs.
    `yaml.load` would construct arbitrary Python objects; the canonical fuzz
    corpus has an `unsafe_tag` category for exactly this."""
    pytest.importorskip("yaml")
    with pytest.raises(TemplateError):
        load_template(
            "template: hawcx/agent-template/v1\n"
            "name: !!python/object/apply:os.system ['echo pwned']\n",
            path_hint="evil.yaml",
        )
