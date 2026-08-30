"""The chat demo agent, driven over a real socketpair.

This exists because the demo agent's whole value is that it REFUSES something.
An echo agent passes any "did the chat window light up" check, so the check has
to be "did the ceiling probe come back refused, and does the agent say so".

The three cases that matter:

* probe refused  -> the turn reports the ceiling was enforced (the demo working)
* probe allowed  -> the turn reports FAILURE (a ceiling that does not refuse is
                    the finding; the agent must not present it as success)
* in-ceiling call refused -> the turn says the run proves nothing, rather than
                    silently continuing to a probe whose result is meaningless

Loaded by path, like `test_langchain_m365_example.py` does, because `examples/`
is not an importable package. `HawcxAgent` is never constructed -- the fake
below stands in for the Assembler, so no socket, no supervisor, no daemon.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import socket
import sys
import threading

import pytest

from hawcx_haap.errors import RequestRejected
from hawcx_haap.ipc import read_frame, write_frame

_EXAMPLE = (
    pathlib.Path(__file__).resolve().parents[1] / "examples" / "chat_demo_agent.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("chat_demo_agent", _EXAMPLE)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["chat_demo_agent"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()


class FakeResponse:
    http_status = 200
    body = b"{}"


class FakeAgent:
    """Stands in for the Assembler. `refuse` names the actions it rejects,
    exactly as the JIT-TQS mint gate would via `ScopeExceedsCeiling`."""

    def __init__(self, refuse: set[str]):
        self.refuse = refuse
        self.calls: list[tuple[str, ...]] = []

    def invoke(self, *, action, tool, **_kw):
        actions = tuple(action)
        self.calls.append(actions)
        for a in actions:
            if a in self.refuse:
                raise RequestRejected("req-1", f"ScopeExceedsCeiling: {a}")
        return FakeResponse()


def _drive_one_turn(agent, prompt: str = "what can you reach?") -> list[tuple[int, dict]]:
    """Send one Prompt into the agent's fd-3 end, collect frames until the
    turn terminates. Returns [(msg_type, payload_json), ...]."""
    manager_end, agent_end = socket.socketpair()
    frames: list[tuple[int, dict]] = []

    def run():
        mod.run_gated_tool_calls(agent_end, agent, prompt)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()

    write_frame(manager_end, mod.MSG_CHAT_PROMPT, json.dumps({"text": prompt}).encode())
    manager_end.settimeout(5)
    while True:
        msg_type, payload = read_frame(manager_end)
        frames.append((msg_type, json.loads(payload)))
        # Exactly one Final or Error ends the turn (ADR-0052 D-52-2).
        if msg_type in (mod.MSG_CHAT_FINAL, mod.MSG_CHAT_ERROR):
            break

    worker.join(timeout=5)
    assert not worker.is_alive(), "the turn never returned"
    manager_end.close()
    agent_end.close()
    return frames


def _final_text(frames) -> str:
    """The Final's text, whitespace-normalized: these messages are hard-wrapped
    for the chat pane, so asserting on a phrase must not depend on where the
    line breaks fall."""
    finals = [p["text"] for t, p in frames if t == mod.MSG_CHAT_FINAL]
    assert len(finals) == 1, f"expected exactly one Final, got {len(finals)}"
    return " ".join(finals[0].split())


def test_refused_probe_is_reported_as_the_ceiling_working():
    """THE case. The refusal is the only observation that proves a gate ran."""
    agent = FakeAgent(refuse={"write"})
    frames = _drive_one_turn(agent)

    assert agent.calls == [("read",), ("write",)], "both calls must be attempted"

    final = _final_text(frames)
    assert "Ceiling enforced" in final
    # The reason must survive to the user, not be flattened to "denied".
    body = " ".join(json.dumps(p) for _t, p in frames)
    assert "ScopeExceedsCeiling: write" in body


def test_allowed_probe_is_reported_as_a_failed_demo():
    """A ceiling that does not refuse is the finding. The agent must say so
    rather than render two green ticks."""
    agent = FakeAgent(refuse=set())
    frames = _drive_one_turn(agent)

    final = _final_text(frames)
    assert "FAILED" in final
    assert "should have been refused" in final


def test_refused_in_ceiling_call_does_not_pretend_the_probe_means_anything():
    agent = FakeAgent(refuse={"read", "write"})
    frames = _drive_one_turn(agent)

    assert agent.calls == [("read",)], "the probe must not run after setup failed"
    final = _final_text(frames)
    assert "proves nothing" in final


def test_every_turn_terminates_exactly_once():
    """A turn that never terminates hangs the Manager until its frame timeout,
    so this is checked for all three outcomes, not just the happy one."""
    for refuse in ({"write"}, set(), {"read", "write"}):
        frames = _drive_one_turn(FakeAgent(refuse=refuse))
        terminals = [t for t, _ in frames if t in (mod.MSG_CHAT_FINAL, mod.MSG_CHAT_ERROR)]
        assert terminals == [mod.MSG_CHAT_FINAL], f"refuse={refuse}: {terminals}"


def test_prompt_allowlist_refuses_any_opcode_but_0x62():
    """The supervisor's `parse_manager_to_agent` accepts only 0x62. An agent
    that accepted more would be the permissive side of a boundary the rest of
    the fleet fails closed at."""
    manager_end, agent_end = socket.socketpair()
    write_frame(manager_end, mod.MSG_CHAT_DELTA, json.dumps({"text": "nope"}).encode())
    with pytest.raises(ValueError, match="expected MSG_CHAT_PROMPT"):
        mod.recv_prompt(agent_end)
    manager_end.close()
    agent_end.close()


def test_opcodes_match_the_supervisor_wire_contract():
    """Pinned literals, because a silent drift here is a hang, not an error."""
    assert (mod.MSG_CHAT_PROMPT, mod.MSG_CHAT_DELTA, mod.MSG_CHAT_FINAL, mod.MSG_CHAT_ERROR) == (
        0x62,
        0x63,
        0x64,
        0x65,
    )
    assert mod.CHAT_FD == 3
