#!/usr/bin/env python3
"""A demo agent that is talkable AND provably gated.

This is the program a tester talks to in the Hawcx Manager chat window. It is
meant to be set as ``agent_bin`` in the supervisor's agent config, so the
supervisor spawns it as the agent process.

Why it is not an echo agent
---------------------------

An agent that reads a prompt and writes text back would make the chat window
look alive while demonstrating nothing: no tool call, no token, no ceiling.
That is worse than the chat window visibly not working, because it invites the
conclusion that authorization was exercised when it was not.

So every prompt here drives TWO real tool calls through the Assembler:

1. ``read`` on the demo resource -- inside the class ceiling, expected to be
   ALLOWED.
2. ``ACEILING_PROBE_ACTION`` (default ``write``) -- expected to be REFUSED.

The second call is the one that matters. A single successful call is
indistinguishable from a gate that permits everything; the refusal is the only
observation that proves a gate ran. It arrives as ``0x54 RequestRejected``
from the Assembler, originating at the JIT-TQS mint gate as
``ScopeExceedsCeiling: <action>`` -- the token is never minted and the partial
is not consumed.

If the probe is ALLOWED, that is reported as a FAILED demo, loudly. A ceiling
that does not refuse is the finding, not a detail to bury.

Two surfaces, one process
-------------------------

The chat channel and the tool-authorization channel are separate integrations
that happen to meet here:

* **Chat** -- inherited **fd 3**, a socketpair the supervisor creates at spawn
  (ADR-0052 P2-1, ``chat_unix::wire_chat_fd``). Nothing is dialed; there is no
  path. Frames are ``0x62`` Prompt in, ``0x63/0x64/0x65`` Delta/Final/Error
  out. The SDK does not implement this -- the ~60 lines below are the only new
  protocol code in this file.
* **Tool calls** -- ``$HAAP_AGENT_SOCKET_DIR/agent-assembler-N.sock``, which is
  entirely ``HawcxAgent``'s job. No env var carries that path; the SDK derives
  it.

Never print to stdout for user-visible output: the supervisor redirects it to
``agent-stdout.log`` precisely so a stray ``print()`` cannot inject frames into
the chat channel. stderr is the log.

CIBA is deliberately not exercised here. It needs ``HAAP_ENABLE_CIBA`` at the
JIT plus ``require_ciba`` in policy -- a policy change, not agent code.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import traceback

from hawcx_haap import HawcxAgent
from hawcx_haap.errors import HawcxError, RequestRejected
from hawcx_haap.ipc import read_frame, write_frame

# ADR-0052 D-52-3 wire opcodes. Mirrors
# `crates/haap-supervisor/src/chat.rs`; four messages, no others.
MSG_CHAT_PROMPT = 0x62
MSG_CHAT_DELTA = 0x63
MSG_CHAT_FINAL = 0x64
MSG_CHAT_ERROR = 0x65

# The supervisor dup2's the chat socketpair onto fd 3 before exec.
CHAT_FD = 3

TARGET_RS = os.environ.get("HAAP_DEMO_RS_URL", "https://rs.demo.local/v1/documents/quarterly")
DEMO_TOOL = os.environ.get("HAAP_DEMO_TOOL", "demo.documents")
# The action expected to sit OUTSIDE the class ceiling. Configurable because
# the ceiling is per-class policy, not a property of this program.
PROBE_ACTION = os.environ.get("HAAP_DEMO_PROBE_ACTION", "write")


def log(msg: str) -> None:
    """stderr only -- stdout is a frame-injection vector on this channel."""
    print(f"[chat-demo-agent] {msg}", file=sys.stderr, flush=True)


# ── fd-3 chat channel ──────────────────────────────────────────────────


def recv_prompt(sock: socket.socket) -> str:
    """Block for one Prompt frame and return its text.

    Enforces the same allowlist the supervisor's own parser does
    (`parse_manager_to_agent`): ``0x62`` and nothing else. An agent that
    accepted other opcodes would be a hole on the permissive side of a
    boundary the rest of the fleet fails closed at.
    """
    msg_type, payload = read_frame(sock)
    if msg_type != MSG_CHAT_PROMPT:
        raise ValueError(f"expected MSG_CHAT_PROMPT (0x62), got {msg_type:#04x}")
    return json.loads(payload)["text"]


def send_delta(sock: socket.socket, text: str) -> None:
    write_frame(sock, MSG_CHAT_DELTA, json.dumps({"text": text}).encode())


def send_final(sock: socket.socket, text: str = "") -> None:
    """End the turn. Exactly one Final or Error per prompt -- the relay
    returns to Idle on it and drops anything sent afterwards."""
    write_frame(sock, MSG_CHAT_FINAL, json.dumps({"text": text}).encode())


def send_error(sock: socket.socket, message: str) -> None:
    write_frame(sock, MSG_CHAT_ERROR, json.dumps({"message": message}).encode())


# ── the part that proves something ─────────────────────────────────────


def run_gated_tool_calls(sock: socket.socket, agent: HawcxAgent, prompt: str) -> None:
    """Two calls: one that should pass the ceiling, one that should not."""

    send_delta(sock, f'Prompt: "{prompt}"\n\n')

    # ── Call 1: inside the ceiling ─────────────────────────────────────
    send_delta(sock, f"[1/2] {DEMO_TOOL} action=read -> ")
    try:
        response = agent.invoke(
            target_rs_url=TARGET_RS,
            http_method="GET",
            headers={"Accept": "application/json"},
            tool=DEMO_TOOL,
            action=["read"],
            acting_for_user=None,
        )
        send_delta(sock, f"ALLOWED (HTTP {response.http_status})\n")
        send_delta(
            sock,
            "      A 184-byte Schnorr TBAC token was minted for this exact\n"
            "      (tool, action, resource) and spent on one request.\n\n",
        )
    except RequestRejected as rej:
        # Not the happy path, and not something to paper over: if the
        # in-ceiling call is refused the demo cannot say anything about the
        # out-of-ceiling one.
        send_delta(sock, f"REFUSED -- {rej.reason}\n\n")
        send_final(
            sock,
            "Setup problem: the in-ceiling call was refused, so this run proves\n"
            "nothing about the ceiling. Check that the class policy grants 'read'\n"
            f"on {DEMO_TOOL}.",
        )
        return

    # ── Call 2: the probe. This is the demo. ───────────────────────────
    send_delta(sock, f"[2/2] {DEMO_TOOL} action={PROBE_ACTION} -> ")
    try:
        agent.invoke(
            target_rs_url=TARGET_RS,
            http_method="POST",
            headers={"Content-Type": "application/json"},
            tool=DEMO_TOOL,
            action=[PROBE_ACTION],
            body=b'{"demo": "ceiling probe"}',
            acting_for_user=None,
        )
    except RequestRejected as rej:
        # The expected, and only useful, outcome.
        send_delta(sock, f"REFUSED\n      {rej.reason}\n\n")
        send_final(
            sock,
            "Ceiling enforced.\n\n"
            f"The '{PROBE_ACTION}' request never became a token. The JIT-TQS mint\n"
            "gate compared the requested scope against the ceiling from this\n"
            "agent's class policy, refused, and left the partial token unspent.\n"
            "No credential this agent holds could have widened it -- the agent\n"
            "never holds one.",
        )
        return

    # Reached only if the probe was ALLOWED, which means no ceiling applied.
    log(f"CEILING NOT ENFORCED: action={PROBE_ACTION!r} was allowed on {DEMO_TOOL}")
    send_delta(sock, "ALLOWED -- and that is a FAILURE\n\n")
    send_final(
        sock,
        f"Demo FAILED: '{PROBE_ACTION}' should have been refused and was not.\n\n"
        "Either this action is inside the class ceiling (pick one that is not,\n"
        "via HAAP_DEMO_PROBE_ACTION) or the ceiling is not being enforced. Do\n"
        "not present this run as a successful demo.",
    )


def main() -> int:
    agent_id = os.environ.get("HAAP_AGENT_INSTANCE_ID")
    if not agent_id:
        log("HAAP_AGENT_INSTANCE_ID is unset -- the supervisor always sets it")
        return 2

    # fd 3 is already an open, connected socketpair end. Wrap it; do not
    # create or dial anything.
    #
    # AF_UNIX/SOCK_STREAM are passed EXPLICITLY rather than letting Python
    # auto-detect from the fd. Auto-detection needs SO_DOMAIN/SO_PROTOCOL,
    # which Linux has and macOS does not -- so a bare
    # `socket.socket(fileno=3)` silently assumes AF_INET on macOS and every
    # read on this socketpair misbehaves. macOS is a demo target, so this is
    # the difference between working and a baffling failure there.
    try:
        chat = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=CHAT_FD)
    except OSError as e:
        log(f"no chat channel on fd {CHAT_FD} ({e}) -- was this spawned by the supervisor?")
        return 2

    log(f"chat channel up on fd {CHAT_FD}; connecting to the Assembler for {agent_id}")

    with HawcxAgent.connect_by_agent_id(agent_id, principal_allowlist=[]) as agent:
        log("Assembler connected; waiting for prompts")
        # One turn at a time, for the connection's life. ADR-0052 D-52-2
        # allows exactly one turn in flight and there is no turn id on the
        # wire, so a serial loop IS the protocol, not a simplification.
        while True:
            try:
                prompt = recv_prompt(chat)
            except Exception as e:  # noqa: BLE001 -- EOF included
                log(f"chat channel closed ({e}); exiting")
                return 0

            try:
                run_gated_tool_calls(chat, agent, prompt)
            except HawcxError as e:
                log(f"tool call failed: {e}")
                send_error(chat, f"tool call failed: {e}")
            except Exception as e:  # noqa: BLE001
                # A turn must always terminate. Leaving one open hangs the
                # Manager until its frame timeout.
                log(f"unexpected error: {e}\n{traceback.format_exc()}")
                send_error(chat, f"agent error: {e}")


if __name__ == "__main__":
    raise SystemExit(main())
