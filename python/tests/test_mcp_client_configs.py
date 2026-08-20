"""The shipped MCP client configs must be valid and must not drift.

Auto-wrap plan U4b. These files get copied into a real
`claude_desktop_config.json` by a human following the docs, so a typo here is a
support ticket, and a stale flag is worse: the proxy would refuse to start and the
client would report only "server failed", with nothing pointing at the config.

Deliberately NOT asserted here: that the flags exist in the Rust parser. That
lives in `hx_agent_client_auth_service` and this repo cannot see it, so the check
would be an unverifiable comment pretending to be a test. The flags were read off
`AttachOpts::parse` when these were written and the docs cite the file; a
cross-repo flag check belongs in that repo's CI, not in a green test here.
"""

from __future__ import annotations

import json
import pathlib

import pytest

CONFIG_DIR = pathlib.Path(__file__).resolve().parents[2] / "examples" / "mcp-clients"
CONFIGS = sorted(CONFIG_DIR.glob("*.json"))


def test_configs_are_present():
    """A glob that silently matches nothing would make every test below vacuous."""
    assert len(CONFIGS) >= 2, f"expected the client configs in {CONFIG_DIR}"


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_is_valid_json(path):
    json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_spawns_hawcx_manager_mcp_with_an_agent_class(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    servers = doc["mcpServers"]
    assert servers, "at least one server entry"
    for name, entry in servers.items():
        assert entry["command"] == "hawcx-manager", name
        args = entry["args"]
        assert args[0] == "mcp", f"{name}: first arg must select the attach-proxy role"
        # --agent is the one genuinely required flag; without it the proxy has no
        # identity to mint under and refuses to start.
        assert "--agent" in args, name


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_no_config_ships_the_dev_only_routes_flag(path):
    """`--routes` is an UNSIGNED local allow-list, honoured only behind a dev
    escape. The route table decides which tool names the proxy will mint for at
    all, so shipping a config that uses it would move that boundary into an
    attacker-editable file. Production configs use `--manifest`.
    """
    blob = path.read_text(encoding="utf-8")
    doc = json.loads(blob)
    for name, entry in doc["mcpServers"].items():
        assert "--routes" not in entry["args"], (
            f"{name}: --routes is dev-only; use --manifest"
        )
    assert "HAAP_DEV_ALLOW_UNSIGNED_CLASS_MANIFEST" not in blob


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_placeholders_are_obviously_placeholders(path):
    """Every value a human must replace is `<...>`-wrapped. A plausible-looking
    real path is the one people forget to change."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    for name, entry in doc["mcpServers"].items():
        args = entry["args"]
        for flag in ("--agent", "--manifest", "--socket"):
            if flag in args:
                value = args[args.index(flag) + 1]
                assert value.startswith("<") and value.endswith(">"), (
                    f"{name}: {flag} value {value!r} should be a <placeholder>"
                )


@pytest.mark.parametrize("path", CONFIGS, ids=lambda p: p.name)
def test_carries_an_explanatory_comment(path):
    """These files are read by humans before they are read by a client. An
    uncommented config invites cargo-culting the flags without the caveats."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert "_comment" in doc or any("_comment" in e for e in doc["mcpServers"].values())


def test_docs_page_exists_and_states_the_windows_gap():
    """U4b's acceptance is 'off-the-shelf binary talks MCP through Lane B with no
    SDK'. That is met on macOS/Linux and OPEN on Windows, because the attach path
    is cfg(unix). A docs page that omitted that would read as a completed
    workstream."""
    docs = CONFIG_DIR.parents[1] / "docs" / "MCP_NO_WRAP_CLIENTS.md"
    text = docs.read_text(encoding="utf-8")
    assert "Windows" in text
    assert "Unix-only" in text
    assert "--manifest" in text and "--routes" in text
