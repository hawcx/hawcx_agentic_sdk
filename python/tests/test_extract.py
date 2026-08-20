"""`hawcx extract` — auto-wrap plan U8.

Most of these are tests that the extractor DOES NOT do things. That is the point:
extraction is inference feeding a document an admin later publishes into real
authority, so the valuable assertions are about what it refuses to invent.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from hawcx_haap.cli import main
from hawcx_haap.extract import (
    ExtractError,
    build_template,
    extract_from_mcp_tools_list,
    extract_from_names,
)
from hawcx_haap.template import validate_v1

# ── what it must never invent ────────────────────────────────────────────────

def test_output_contains_no_endpoint_provider_or_constraint_keys():
    """Plan U8: "never guess RS URLs". Their absence is the schema, not a blank
    field — a URL guessed from a description is a plausible WRONG destination
    that survives review because it looks filled in."""
    rep = extract_from_names(["get_user", "create_group"], namespace="o365")
    doc = build_template(rep, name="a", version="0.1.0", framework="langchain")
    blob = json.dumps(doc)
    for forbidden in ("endpoint", "url", "http", "provider", "bearer", "token",
                      "constraints", "suggested_levels"):
        assert forbidden not in blob.lower(), f"{forbidden!r} leaked into the draft"
    assert set(doc) == {"template", "name", "version", "framework", "tools"}


def test_every_tool_carries_only_id_actions_risk():
    rep = extract_from_names(["get_user"], namespace="o365")
    assert set(rep.tools[0]) == {"id", "actions", "risk"}


def test_privileged_verbs_are_refused_not_downgraded():
    """`refund` must be `move_money` (V14), which then requires max_*/ciba_*
    constraints (V15) that only a human can set. Emitting it anyway would produce
    a template that cannot validate; renaming it to dodge the rule would be
    worse."""
    rep = extract_from_names(
        ["get_user", "issue_refund", "wire_funds", "run_payment"], namespace="billing"
    )
    assert [t["id"] for t in rep.tools] == ["billing.get_user"]
    refused = {src for src, _ in rep.refused}
    assert refused == {"issue_refund", "wire_funds", "run_payment"}
    for _src, why in rep.refused:
        assert "move_money" in why and "by hand" in why


def test_risk_never_contradicts_the_action():
    """The first version emitted `write` + `read_public` — the mildest risk that
    validates, and internally contradictory. A reviewer who spots one such line
    rightly stops trusting the whole file."""
    rep = extract_from_names(
        ["get_thing", "create_thing", "run_thing"], namespace="ns"
    )
    by_id = {t["id"]: t for t in rep.tools}
    assert by_id["ns.get_thing"]["risk"] == "read_public"
    assert by_id["ns.create_thing"]["risk"] == "write_internal"
    assert by_id["ns.run_thing"]["risk"] == "write_internal"
    for t in rep.tools:
        if "write" in t["actions"] or "execute" in t["actions"]:
            assert t["risk"] != "read_public", t


def test_never_emits_admin_or_move_money():
    rep = extract_from_names(
        ["delete_everything", "grant_admin", "escalate_privileges"], namespace="ns"
    )
    for t in rep.tools:
        assert t["risk"] not in ("admin", "move_money"), t


# ── id grammar ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("listMailFolders", "o365.list_mail_folders"),
    ("add-group-member", "o365.add_group_member"),
    ("GetUser", "o365.get_user"),
    ("query_leads", "o365.query_leads"),
])
def test_names_are_normalised_to_the_id_grammar(raw, expected):
    rep = extract_from_names([raw], namespace="o365")
    assert rep.tools[0]["id"] == expected


def test_a_namespace_is_required_and_not_synthesised():
    """A bare name cannot satisfy the dotted id grammar. Inventing a namespace
    would mint a HAAP tool identity out of nothing, and identity is what policy
    binds to."""
    with pytest.raises(ExtractError, match="normalises to nothing"):
        extract_from_names(["get_user"], namespace="!!!")


def test_collisions_after_normalisation_are_refused():
    """`getUser` and `get_user` both normalise to `ns.get_user`. Emitting one
    entry for two source tools would silently drop a tool from the draft."""
    rep = extract_from_names(["getUser", "get_user"], namespace="ns")
    assert len(rep.tools) == 1
    assert any("duplicate" in why for _s, why in rep.refused)


def test_unknown_verbs_are_reported_not_silently_bucketed():
    rep = extract_from_names(["frobnicate", "get_user"], namespace="ns")
    assert rep.unknown_verbs == ["frobnicate"]
    assert rep.inferred_actions == ["get_user"]
    assert rep.needs_review


# ── MCP input shapes ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("payload", [
    {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "get_user"}]}},
    {"tools": [{"name": "get_user"}]},
    [{"name": "get_user"}],
    ["get_user"],
])
def test_accepts_the_shapes_people_actually_have_on_disk(payload):
    rep = extract_from_mcp_tools_list(payload, namespace="ns")
    assert [t["id"] for t in rep.tools] == ["ns.get_user"]


def test_entries_without_a_name_are_reported():
    rep = extract_from_mcp_tools_list(
        {"tools": [{"name": "get_user"}, {"description": "no name here"}]}, namespace="ns"
    )
    assert len(rep.tools) == 1
    assert any("no string `name`" in why for _s, why in rep.refused)


def test_a_non_tools_payload_is_a_clear_error():
    with pytest.raises(ExtractError, match="could not find a tools array"):
        extract_from_mcp_tools_list({"result": {"prompts": []}}, namespace="ns")


# ── the output is submittable ────────────────────────────────────────────────

def test_the_draft_validates_against_the_v1_rules():
    """An extractor that emits an invalid template has only moved the failure to
    the reviewer's `hawcx validate` run, or to `submit`."""
    rep = extract_from_names(
        ["get_user", "listMailFolders", "create_group", "runReport"], namespace="o365"
    )
    doc = build_template(rep, name="o365-assistant", version="1.2.3", framework="langchain")
    assert validate_v1(doc) == []


def test_a_framework_the_schema_rejects_fails_loudly():
    """The plan calls the MCP lane `mcp-native`, but the SCHEMA's enum is the
    authority and does not contain it. Substituting a framework the agent does
    not use would be a lie in a published record."""
    rep = extract_from_names(["get_user"], namespace="ns")
    with pytest.raises(ExtractError, match="not accepted by"):
        build_template(rep, name="a", framework="mcp-native")


def test_all_refused_is_an_error_not_an_empty_template():
    rep = extract_from_names(["issue_refund"], namespace="billing")
    with pytest.raises(ExtractError, match="nothing extractable"):
        build_template(rep, name="a", framework="langchain")


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_stdout_is_clean_json_and_the_report_goes_to_stderr(tmp_path):
    """`hawcx extract ... > template.json` must produce a usable file. If the
    report went to stdout it would be a draft that looks finished and a file that
    does not parse."""
    r = subprocess.run(
        [sys.executable, "-m", "hawcx_haap.cli", "extract",
         "--names", "get_user", "issue_refund", "frobnicate",
         "--namespace", "billing", "--name", "b"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    doc = json.loads(r.stdout)               # clean JSON, nothing else
    assert validate_v1(doc) == []
    assert "REFUSED" in r.stderr and "issue_refund" in r.stderr
    assert "frobnicate" in r.stderr
    assert "DRAFT" in r.stderr


def test_user_facing_output_is_cp1252_encodable():
    """Windows consoles use the legacy codepage, and a non-ASCII character in a
    printed string raises UnicodeEncodeError there. An em-dash in generated
    source already cost a full Windows CI failure on this repo (#79); the same
    trap applies to anything we print.
    """
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    old = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = buf
    try:
        rc = main(["extract", "--names", "get_user", "issue_refund", "frobnicate",
                   "--namespace", "ns", "--name", "a"])
    finally:
        sys.stdout, sys.stderr = old
    assert rc == 0


def test_submit_failure_output_is_cp1252_encodable(tmp_path):
    """Same check for `submit`'s printed strings. Two of them carried em-dashes
    when U2 landed on main; caught while rebasing this branch onto it. Covering
    the sibling subcommand here rather than only `extract` is the point -- the
    trap is per-string, not per-feature."""
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "template": "hawcx/agent-template/v1", "name": "a", "version": "0.1.0",
        "framework": {"kind": "langchain"},
        "tools": [{"id": "a.b", "actions": ["read"], "risk": "read_internal"}],
        "granted_scopes": ["everything"],
    }))
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    old = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = buf
    try:
        rc = main(["submit", str(bad), "--org", "nowhere"])
    finally:
        sys.stdout, sys.stderr = old
    assert rc == 1   # invalid template, refused locally -- no network reached
