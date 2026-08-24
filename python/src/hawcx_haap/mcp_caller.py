"""One tested path from an MCP tool call to a HAAP allow/deny decision.

Every agent that reaches an MCP server through HAAP needs the same four
things, and until this module existed each one wrote them again:

1. Get a process-wide :class:`~hawcx_haap.agent.HawcxAgent` from the
   environment the supervisor prepared, and close it on the way out.
2. Build the MCP JSON-RPC 2.0 ``tools/call`` document for one tool.
3. Hand it to ``agent.invoke()`` — the only egress path an agent has.
4. Read the answer back and say whether the call was allowed or denied.

Step 4 is the one that had to be written once. A HAAP refusal arrives in three
shapes and only the first of them looks like a failure:

* :class:`~hawcx_haap.errors.RequestRejected` (msg_type 0x54) — refused at
  token mint, before egress.
* A JSON-RPC error carrying code ``-32005``…``-32000`` and
  ``data.hawcx_reason_code`` per HAAP v7.2.5 §45.7.5 — refused at the RSV MCP
  gateway, and delivered inside an HTTP **200**.
* That same JSON-RPC error wrapped in a Server-Sent Events frame, because
  Streamable HTTP lets the server answer with either a JSON body or an event
  stream and the client does not get to pick.

The third shape is why this belongs in the SDK rather than in each consumer.
An implementation that detects a stream by testing whether the body starts
with ``data:`` misses a real frame — a real one opens with ``event: message``
— and then reads the denial it carries as an allow. That is the one
misclassification that matters, and :func:`_json_documents` is now the single
place it can be got wrong. ``python/tests/test_mcp_caller.py`` pins it.

Fail-closed, in both directions:

* ``principal_allowlist`` stays a required argument the whole way down, so a
  model-influenced principal string can never switch the effective user.
* A response this module cannot classify is a DENY. An unreadable body does
  not say the call was permitted, and "cannot tell" must never read as "yes".

Nothing here knows what tools exist. :class:`McpTool` is data the caller
supplies; the tool vocabulary, the endpoints and the principals stay in the
consumer's own deployment config. ``hawcx init`` scaffolds that config, and
:data:`FILL_ME` / :func:`require_filled` at the bottom of this module are what
make an unfilled value in it fail at import instead of looking configured.

Quick start::

    from hawcx_haap import Caller, McpTool, close_agent, get_agent

    MAILBOX = McpTool(
        tool_id="mail.read",
        url="https://mcp.example.com/servers/mail",
        name="list_messages",
        actions=("read",),
        resource="mailbox",
        arguments={"top": 5},
    )

    caller = Caller(agent=get_agent(["alice@example.com"]), provider="microsoft")
    try:
        print(caller.call(MAILBOX, "alice@example.com").summary())
    finally:
        close_agent()
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field, is_dataclass
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import Any

from hawcx_haap.agent import HawcxAgent
from hawcx_haap.errors import RequestRejected
from hawcx_haap.ipc import TokenTransport

#: HAAP v7.2.5 §45.7.5 JSON-RPC rejection codes: -32005 … -32000 inclusive.
#: An ``error.code`` inside this range is a HAAP policy denial. One outside it
#: (``-32601`` "method not found", say) is a downstream fault, and reporting
#: that as a policy denial would manufacture evidence of a decision nobody made.
HAWCX_REJECT_CODES = range(-32005, -31999)


@dataclass
class Decision:
    """What happened to one tool call — the caller's unit of evidence.

    A refusal is an outcome, not an exception: both an Assembler rejection and
    a gateway rejection come back as ``allowed=False`` so a caller can report
    a denial without having to catch anything.
    """

    tool: str
    principal: str
    allowed: bool
    reason: str | None = None
    reason_code: str | None = None
    http_status: int | None = None
    body: str = ""
    request_id: str = ""

    def summary(self) -> str:
        """One line, aligned for a column of them."""
        verdict = "ALLOW" if self.allowed else "DENY "
        tail = f" — {self.reason}" if self.reason else ""
        code = f" [{self.reason_code}]" if self.reason_code else ""
        status = f" http={self.http_status}" if self.http_status is not None else ""
        return f"{verdict} {self.tool:<28} as {self.principal}{status}{code}{tail}"


@dataclass(frozen=True)
class McpTool:
    """One MCP tool a caller may invoke, as the HAAP boundary sees it.

    ``tool_id``, ``actions`` and ``resource`` become the requested scope the
    Assembler mints a token for — they are what policy is written against, so
    they belong in deployment config rather than in code. ``name`` is the
    downstream MCP tool name that goes into the JSON-RPC body, and it is the
    field most likely to change when a real ``tools/list`` is finally captured.
    """

    tool_id: str
    url: str
    name: str
    actions: tuple[str, ...] = ()
    resource: str = "*"
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Caller:
    """Routes every tool call through ``agent.invoke()``. There is no second path.

    A consumer built around this class holds no HTTP client for the
    destination and no credential for it: it hands a request to the Assembler,
    which mints the HAAP token, attaches it and makes the outbound call. Two
    consequences worth stating plainly:

    * Credentials never enter the agent process. Nothing there can log or leak
      a token, because nothing there ever holds one.
    * A refusal happens BEFORE any request is issued. "It never left" is not a
      property the agent has to prove by restraint — it has no route to
      restrain.

    ``agent`` may be left unset to build and inspect wire requests without a
    running Assembler (see :meth:`invoke_kwargs`); only :meth:`call` needs a
    live handle.
    """

    agent: Any = None
    #: Optional OAuth provider id (ASS-4) naming the bridging bearer the
    #: Assembler should attach for this destination, e.g. ``"microsoft"``.
    provider: str | None = None
    _seq: int = 0

    def envelope(
        self,
        tool: McpTool,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """The MCP JSON-RPC 2.0 ``tools/call`` document for one call.

        ``params._meta`` is deliberately ABSENT. The Assembler injects the HAAP
        token at ``params._meta.hawcx`` per §45.7.5 and the RSV strips that
        envelope on egress; an agent that wrote the field itself would be
        forging the one thing it is supposed to be unable to forge.
        """
        self._seq += 1
        return {
            "jsonrpc": "2.0",
            "id": self._seq,
            "method": "tools/call",
            "params": {
                "name": tool.name,
                "arguments": dict(tool.arguments if arguments is None else arguments),
            },
        }

    def invoke_kwargs(
        self,
        tool: McpTool,
        principal: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Exactly the kwargs :meth:`call` hands to :meth:`HawcxAgent.invoke`.

        Split out so a consumer can print the request it *would* send — for a
        scope review, say — and have what it prints be the request that would
        actually go, rather than a hand-written approximation of it. Feed the
        result to :class:`~hawcx_haap.ipc.ToolCallRequest` (moving ``body`` to
        ``plaintext_request_body``) to see the serialization too.
        """
        return {
            "target_rs_url": tool.url,
            "http_method": "POST",
            # Streamable HTTP: the server may answer with a JSON body or an SSE
            # stream, and the spec requires the client to declare it takes both.
            # Saying so is what makes the SSE branch below reachable.
            "headers": {"Accept": "application/json, text/event-stream"},
            "tool": tool.tool_id,
            "action": list(tool.actions),
            "resource": tool.resource,
            "acting_for_user": principal,
            "body": json.dumps(self.envelope(tool, arguments)).encode("utf-8"),
            "content_type": "application/json",
            "transport": TokenTransport.MCP_META_V7_2_5,
            "provider": self.provider,
        }

    def call(
        self,
        tool: McpTool,
        principal: str,
        arguments: dict[str, Any] | None = None,
    ) -> Decision:
        """Route one tool call through HAAP and classify the answer."""
        kwargs = self.invoke_kwargs(tool, principal, arguments)
        try:
            resp = self.agent.invoke(**kwargs)
        except RequestRejected as exc:
            # Refused at token mint. The Assembler never reached egress, so
            # nothing was sent to the destination at all.
            return Decision(
                tool=tool.tool_id,
                principal=principal,
                allowed=False,
                reason=exc.reason,
                request_id=getattr(exc, "request_id", ""),
            )
        return _classify(tool.tool_id, principal, resp)


# ── Classification ───────────────────────────────────────────────────


def _classify(tool_id: str, principal: str, resp: Any) -> Decision:
    """Allow or deny, from an Assembler response that did not raise.

    Ordered by how specific the evidence is: a JSON-RPC HAAP rejection names
    its own reason code, an HTTP 401/403 names only a status, and a body that
    yields no JSON-RPC document at all names nothing — which is why that last
    case denies instead of allowing.
    """
    body_text = _text(getattr(resp, "body", b""))
    status = getattr(resp, "http_status", None)
    request_id = getattr(resp, "request_id", "") or ""
    documents = list(_json_documents(body_text))

    for doc in documents:
        err = doc.get("error")
        if isinstance(err, dict) and err.get("code") in HAWCX_REJECT_CODES:
            data = err.get("data")
            return Decision(
                tool=tool_id,
                principal=principal,
                allowed=False,
                reason=str(err.get("message") or "rejected by the HAAP MCP gateway"),
                reason_code=(
                    str(data["hawcx_reason_code"])
                    if isinstance(data, dict) and data.get("hawcx_reason_code")
                    else None
                ),
                http_status=status,
                body=body_text,
                request_id=request_id,
            )

    # An HTTP-level 401/403 is a refusal too, not a transport fault.
    if isinstance(status, int) and status in (401, 403):
        return Decision(
            tool=tool_id,
            principal=principal,
            allowed=False,
            reason=f"destination refused with HTTP {status}",
            http_status=status,
            body=body_text,
            request_id=request_id,
        )

    if not documents:
        # Fail closed. An empty, truncated or non-JSON body does not tell us
        # the call was permitted, and a denial we could not parse must never
        # come back as an allow. A JSON-RPC batch (a top-level array) lands
        # here too; denying it is the safe half of that trade, and `tools/call`
        # is not a batched method.
        return Decision(
            tool=tool_id,
            principal=principal,
            allowed=False,
            reason="unclassifiable response body: no JSON-RPC document found",
            http_status=status,
            body=body_text,
            request_id=request_id,
        )

    return Decision(
        tool=tool_id,
        principal=principal,
        allowed=True,
        http_status=status,
        body=body_text,
        request_id=request_id,
    )


def _text(body: Any) -> str:
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    return "" if body is None else str(body)


def _json_documents(body_text: str) -> Iterator[dict[str, Any]]:
    """Every JSON object in a body, whether it is one document or an SSE stream.

    Try the whole body as JSON first; failing that, scan every ``data:`` line.

    Deciding which shape it is by a prefix check does not work, and getting
    that wrong is the bug this module exists to stop shipping: an SSE frame
    legitimately opens with ``event: message``, so ``body.startswith("data:")``
    reads False for a perfectly ordinary stream, and the denial inside it is
    dropped. Scanning the lines unconditionally costs nothing and cannot make
    that mistake.
    """
    text = body_text.strip()
    if not text:
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        # Parsed as one document. Non-objects (arrays, bare scalars) yield
        # nothing, and _classify denies on an empty yield.
        if isinstance(obj, dict):
            yield obj
        return
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        try:
            obj = json.loads(line[len("data:") :].strip())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


# ── Connecting ───────────────────────────────────────────────────────
#
# This is the SDK's glue layer, and it is the one place in the package that
# reads the HAWCX_* connection variables. `HawcxAgent` itself takes explicit
# arguments and always will: env reading belongs in glue, so it is fenced into
# the three functions below rather than spread through the transport.

_AGENT: HawcxAgent | None = None
_AGENT_LOCK = threading.Lock()


def get_agent(principal_allowlist: list[str]) -> HawcxAgent:
    """Connect once per process to this agent's Assembler socket.

    Reads ``HAWCX_ASSEMBLER_SOCK`` (an explicit socket path) or, failing that,
    ``HAWCX_AGENT_ID`` with an optional ``HAWCX_IPC_DIR``. A supervisor sets
    these when it spawns the agent.

    ``principal_allowlist`` is required and is a fail-closed gate: an
    ``acting_for_user`` outside it raises before a single IPC byte is written,
    so a model-influenced principal string cannot switch the effective user.
    Source it from operator config — never from model output.

    Raises :class:`RuntimeError` when neither variable is set. That is a
    deliberate departure from :class:`~hawcx_haap.errors.HawcxError`: an
    unconfigured pipeline is an operator problem, and callers catch
    ``RuntimeError`` around startup to print one line instead of a traceback
    that reads like a code fault.
    """
    global _AGENT
    if _AGENT is not None:
        return _AGENT
    with _AGENT_LOCK:
        if _AGENT is None:
            sock = os.environ.get("HAWCX_ASSEMBLER_SOCK", "").strip()
            if sock:
                _AGENT = HawcxAgent.connect(
                    sock, principal_allowlist=principal_allowlist
                )
            else:
                agent_id = os.environ.get("HAWCX_AGENT_ID", "").strip()
                if not agent_id:
                    raise RuntimeError(
                        "No Assembler connection configured. Set "
                        "HAWCX_ASSEMBLER_SOCK (explicit socket path) or "
                        "HAWCX_AGENT_ID (enrolled agent id, optionally with "
                        "HAWCX_IPC_DIR). The supervisor sets these when it "
                        "spawns the agent."
                    )
                ipc_dir = os.environ.get("HAWCX_IPC_DIR", "").strip()
                _AGENT = HawcxAgent.connect_by_agent_id(
                    agent_id,
                    principal_allowlist=principal_allowlist,
                    ipc_dir=Path(ipc_dir) if ipc_dir else None,
                )
    return _AGENT


def close_agent() -> None:
    """Close the process-wide handle. A no-op when there is none."""
    global _AGENT
    with _AGENT_LOCK:
        if _AGENT is not None:
            try:
                _AGENT.close()
            finally:
                _AGENT = None


def env_principal_allowlist() -> list[str] | None:
    """``HAWCX_PRINCIPAL_ALLOWLIST`` as a list, or ``None`` if it is unset.

    Unset means "the caller's configured default applies". Set-but-empty means
    "forbid runtime principal switching entirely", which the SDK honours — so
    an empty value is a real answer here, not a missing one, and the two cases
    must not be collapsed.
    """
    raw = os.environ.get("HAWCX_PRINCIPAL_ALLOWLIST")
    if raw is None:
        return None
    return [p.strip() for p in raw.split(",") if p.strip()]


# ── Scaffolded config ────────────────────────────────────────────────
#
# `hawcx init` emits a customer-owned `config.py` whose every deployment-
# specific value starts as FILL_ME. The requirement that made this live in the
# SDK rather than in the generated file: an unfilled value must FAIL LOUDLY
# rather than look configured. A placeholder that merely reads as a comment
# ("# TODO: your RS URL") survives review and reaches the Assembler as a real
# target; a value that stops the module importing cannot.
#
# The check is here, not inlined into every generated config, for the same
# reason `_json_documents` is here: it is logic with one correct answer, and a
# copy per customer is a copy that drifts.

#: The scaffolder's placeholder. Deliberately a string that is not a plausible
#: URL, tool name or resource, and deliberately ugly — it is meant to be
#: noticed in a diff, not to blend in.
FILL_ME = "<FILL ME -- scaffolded by `hawcx init`>"


def require_filled(**values: Any) -> None:
    """Raise unless every scaffolded placeholder in *values* has been replaced.

    Called at the bottom of a generated ``config.py`` with that module's
    top-level names, so an unfilled deployment fails at **import** — before an
    agent connects, and long before a FILL_ME could be sent somewhere as a URL
    or a principal.

    Reports **every** unfilled field in one message rather than the first.
    Fixing one placeholder per traceback is the slowest possible way to stand a
    config up, and the same reasoning is why ``hawcx validate`` prints every
    template error at once.

    Recurses through dataclasses (:class:`McpTool`), dicts, lists and tuples,
    so ``TOOLS["mail.read"].url`` is named by its path rather than reported as
    an opaque "something in TOOLS".
    """
    unfilled: list[str] = []
    for name, value in values.items():
        _scan_unfilled(value, name, unfilled)
    if unfilled:
        raise ValueError(
            f"{len(unfilled)} unfilled config value(s): " + ", ".join(unfilled)
            + ". Replace every FILL_ME with the value for this deployment. "
            "`principal_allowlist` has no default on purpose: it is the "
            "fail-closed gate on `acting_for_user`, so pass the explicit set of "
            "permitted principals, or [] to forbid runtime principal switching "
            "entirely."
        )


def _scan_unfilled(node: Any, path: str, out: list[str]) -> None:
    if isinstance(node, str):
        # `==`, not `is`: the generated config imports the constant, but a
        # developer who pasted the literal string around still gets caught.
        if node == FILL_ME:
            out.append(path)
    elif is_dataclass(node) and not isinstance(node, type):
        for f in dc_fields(node):
            _scan_unfilled(getattr(node, f.name), f"{path}.{f.name}", out)
    elif isinstance(node, dict):
        for k, v in node.items():
            _scan_unfilled(v, f"{path}[{k!r}]", out)
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            _scan_unfilled(v, f"{path}[{i}]", out)
