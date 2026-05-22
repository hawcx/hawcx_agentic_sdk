"""HawcxTool — CrewAI ``BaseTool`` subclass that proxies through a HAAP agent.

Design notes
------------

1.  **No credential material crosses this boundary.** ``HawcxTool._run``
    forwards the call to ``HawcxAgent.invoke`` (or ``invoke_for`` when a
    runtime principal is set). The Assembler process performs the §47
    Pattern Y sidecar fetch (HAAP token + provider bearer credential) and
    constructs the outbound HTTP request itself. The credential value is
    never returned to the Python process; this class only sees the
    response body and headers.

2.  **CrewAI BaseTool is a Pydantic v2 model.** ``HawcxAgent`` is not a
    Pydantic-friendly type, so it lives on a ``PrivateAttr`` rather than
    as a model field. The previous factory-closure pattern in
    ``examples/crewai_integration.py`` avoided this issue by capturing
    the agent in lexical scope; ``PrivateAttr`` is the modern equivalent
    that still lets us expose ``HawcxTool`` as a regular constructible
    class.

3.  **Runtime principal is per-call, not per-tool.** ``HawcxTool`` can
    be constructed with or without a default ``user_principal_id``.
    Callers that fan out across users should construct a fresh tool
    instance per user (cheap — no IPC at construction time) via
    :meth:`HawcxTool.for_user`, OR include ``user_principal_id`` in the
    ``args_schema`` and pass it per call. The latter is what the
    existing factory closures do and is the recommended shape for
    multi-tenant CrewAI flows; see the README example.

4.  **Provider routing.** ``provider`` is forwarded to the Assembler in
    ``constraints["provider"]``. The Assembler uses ``tool_id`` (mapped
    to the IPC ``tool`` field) as the §47.4 tool-identity binding and
    ``provider`` to route the §47.8 ``GetExternalCredential`` request to
    the correct sidecar (``haap-nim-provider``, ``haap-anthropic-provider``,
    etc.).
"""

from __future__ import annotations

import json
from typing import Any

from crewai.tools import BaseTool
from hawcx_haap import HawcxAgent, RequestRejected
from hawcx_haap.errors import HawcxError
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


# ── Generic adapter ──────────────────────────────────────────────────────────


class HawcxTool(BaseTool):
    """CrewAI ``BaseTool`` that proxies tool calls through a HAAP agent.

    Parameters
    ----------
    name:
        Tool name surfaced to the CrewAI agent and the LLM. CrewAI uses
        this verbatim in its tool-selection prompt.
    description:
        Tool description surfaced to the LLM. Should describe *what* the
        tool does in user-facing terms, not the HAAP plumbing.
    hawcx_agent:
        A connected :class:`hawcx_haap.HawcxAgent`. The same agent
        instance may be shared across many ``HawcxTool`` instances (one
        Assembler connection per process is the recommended deployment).
    provider:
        Provider class identifier per HAAP CS v7.2.6 §47.2 (e.g.
        ``"nim"``, ``"anthropic"``, ``"generic-bearer"``). The
        Assembler uses this to route the §47.8 ``GetExternalCredential``
        IPC to the correct sidecar.
    tool_id:
        Tool identity per §47.4. The sidecar checks this against the
        per-tool credential binding before disclosing the credential
        value. Two tools with distinct ``tool_id`` values cannot share
        credentials even when running in the same agent runtime.
    endpoint:
        Destination URL the upstream tool calls. Passed to the
        Assembler as ``target_rs_url``.
    method:
        HTTP method (default ``"POST"``).
    args_schema:
        Pydantic model describing the tool's arguments. CrewAI uses this
        for argument validation and for prompting the LLM. If omitted,
        defaults to :class:`_FreeFormArgs` (a permissive model with one
        optional ``input`` field) — fine for ad-hoc tools, but a
        properly-typed schema is strongly recommended for production
        flows.
    action:
        TBAC action list (e.g. ``["read"]``, ``["write"]``). Default
        ``["invoke"]``.
    resource:
        TBAC resource selector. Default ``"*"``. Set to a narrower
        selector when the Cedar policy template's authorization is
        resource-scoped.
    headers:
        Static request headers merged into the outbound request.
        ``Content-Type`` is added automatically when ``body`` is JSON
        and the caller has not set one.
    default_user_principal_id:
        Optional default principal that ``_run`` will use as
        ``acting_for_user`` when the per-call args do not supply one.
        Must already be in the agent's ``principal_allowlist``; the SDK
        validates this at IPC time. Prefer per-call injection via the
        ``args_schema`` for multi-tenant flows; see README.
    """

    # CrewAI BaseTool fields (declared by the parent class). We re-declare
    # them here only so the constructor signature is clear.
    name: str
    description: str

    # Pydantic v2 — allow arbitrary types so the Pydantic schema-args
    # type can be a regular Type[BaseModel] reference.
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Hawcx routing knobs. These are model fields (and so part of the
    # Pydantic schema) because they are pure data and benefit from
    # validator hooks.
    provider: str = Field(..., description="HAAP §47 provider class identifier.")
    tool_id: str = Field(..., description="HAAP §47.4 tool identity for credential binding.")
    endpoint: str = Field(..., description="Destination URL the tool calls.")
    method: str = Field(default="POST")
    action: list[str] = Field(default_factory=lambda: ["invoke"])
    resource: str = Field(default="*")
    headers: dict[str, str] = Field(default_factory=dict)
    default_user_principal_id: str | None = Field(default=None)

    # The HawcxAgent is NOT a Pydantic-friendly type — it owns a socket
    # and is constructed via a factory. Stash it on a PrivateAttr.
    _hawcx_agent: HawcxAgent = PrivateAttr()

    def __init__(self, **data: Any) -> None:
        agent = data.pop("hawcx_agent", None)
        if agent is None:
            raise TypeError(
                "HawcxTool requires keyword argument `hawcx_agent`: pass "
                "a connected hawcx_haap.HawcxAgent instance."
            )
        if not isinstance(agent, HawcxAgent):
            raise TypeError(
                f"hawcx_agent must be a hawcx_haap.HawcxAgent; got "
                f"{type(agent).__name__}"
            )
        super().__init__(**data)
        self._hawcx_agent = agent

    # ── CrewAI surface ────────────────────────────────────────────────

    def _run(self, **kwargs: Any) -> str:
        """Execute the HAAP-authenticated tool call.

        Pulls ``user_principal_id`` from ``kwargs`` if present (so a
        per-call principal in the ``args_schema`` is honoured),
        otherwise falls back to :attr:`default_user_principal_id`.

        The Assembler is responsible for:
        1. Fetching the HAAP token via the per-agent TQS-jit and AS flow.
        2. Fetching the provider bearer credential via the §47.8
           ``GetExternalCredential`` IPC against the appropriate sidecar.
        3. Constructing the outbound HTTPS request to :attr:`endpoint`
           with the HAAP token in ``Authorization: HAAP`` and the
           provider credential attached per §45.7.1 carriage rules.
        4. Decrypting the response and returning it as a
           :class:`hawcx_haap.ToolCallResponse`.

        Returns the response body decoded as UTF-8 (CrewAI tools
        contract). Non-2xx HTTP statuses are returned as a structured
        string rather than raised; this matches the existing factory
        pattern and keeps the LLM in the loop for retries.
        """
        principal = kwargs.pop("user_principal_id", None) or self.default_user_principal_id

        body = self._encode_body(kwargs)
        headers = dict(self.headers)
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        # The Assembler reads `tool` (= our tool_id) for §47.4 binding
        # and the provider for sidecar routing per §47.8.
        constraints = {"provider": self.provider}

        invoke_kwargs: dict[str, Any] = {
            "target_rs_url": self.endpoint,
            "http_method": self.method,
            "headers": headers,
            "tool": self.tool_id,
            "action": list(self.action),
            "resource": self.resource,
            "constraints": constraints,
            "body": body,
            "tool_arguments": kwargs or None,
        }

        try:
            if principal:
                resp = self._hawcx_agent.invoke_for(principal, **invoke_kwargs)
            else:
                resp = self._hawcx_agent.invoke(**invoke_kwargs)
        except RequestRejected as exc:
            # The Assembler rejected synchronously (e.g. credential not
            # bound to this tool_id per §47.9 0x002D). Surface a short
            # diagnostic to the LLM without echoing internal token state.
            return f"[hawcx rejected: {exc.reason}]"
        except HawcxError as exc:
            # Includes principal-allowlist violations from the SDK's
            # H-3 guard. The exception text already redacts the
            # rejected principal to a SHA-256 fingerprint.
            return f"[hawcx error: {exc}]"

        if resp.http_status >= 400:
            return f"[hawcx HTTP {resp.http_status}] {self._safe_decode(resp.body)}"
        return self._safe_decode(resp.body)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _encode_body(kwargs: dict[str, Any]) -> bytes | None:
        """JSON-encode the args dict, or return None for GET-style calls.

        We treat an empty kwargs dict as "no body" so that GET requests
        don't get a stray ``"{}"`` body that some servers reject.
        """
        if not kwargs:
            return None
        return json.dumps(kwargs, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _safe_decode(body: bytes) -> str:
        return body.decode("utf-8", errors="replace")

    def for_user(self, user_principal_id: str) -> HawcxTool:
        """Return a sibling tool bound to ``user_principal_id``.

        Useful in CrewAI flows that materialize one tool per end-user
        and pass them to a per-user Crew. The new instance shares the
        underlying ``HawcxAgent`` (one Assembler connection per
        process), so this is cheap.
        """
        # model_dump() + override; re-passes through __init__ which
        # re-injects the agent via the kwarg path.
        data = self.model_dump()
        data["default_user_principal_id"] = user_principal_id
        return type(self)(hawcx_agent=self._hawcx_agent, **data)


# ── Legacy factory functions (backward compat with the previous example) ─────


class _SearchInput(BaseModel):
    query: str = Field(description="Search query string.")
    user_principal_id: str = Field(
        description=(
            "ID of the end-user on whose behalf the search is performed. "
            "Must be one of the principals registered for this agent."
        )
    )


class _DocumentInput(BaseModel):
    document_id: str = Field(description="Opaque document identifier to retrieve.")
    user_principal_id: str = Field(
        description="ID of the end-user on whose behalf the document is fetched."
    )


def make_search_tool(
    agent: HawcxAgent,
    *,
    rs_base_url: str = "https://api.example.com",
    tool_id: str = "search",
    provider: str = "generic-bearer",
) -> HawcxTool:
    """Build a CrewAI tool that searches via HAAP for a given user principal.

    Preserved for backward compatibility with the pre-v0.1.0a11 example.
    New code should construct :class:`HawcxTool` directly.
    """
    return HawcxTool(
        name="hawcx_search",
        description=(
            "Search the organisation's protected knowledge base via Hawcx HAAP. "
            "Always pass the user_principal_id you were given for this task."
        ),
        hawcx_agent=agent,
        provider=provider,
        tool_id=tool_id,
        endpoint=f"{rs_base_url}/search",
        method="POST",
        action=["read"],
        args_schema=_SearchInput,
    )


def make_document_tool(
    agent: HawcxAgent,
    *,
    rs_base_url: str = "https://api.example.com",
    tool_id: str = "documents",
    provider: str = "generic-bearer",
) -> HawcxTool:
    """Build a CrewAI tool that fetches a single document via HAAP.

    Preserved for backward compatibility with the pre-v0.1.0a11 example.
    New code should construct :class:`HawcxTool` directly. Note this
    tool's endpoint is a template — the per-call ``document_id`` is
    appended at run time via a custom subclass; for that reason the
    backward-compat shim returns a thin subclass that rewrites the URL.
    """

    class _DocumentTool(HawcxTool):
        def _run(self, document_id: str, **kwargs: Any) -> str:  # type: ignore[override]
            # Per-call URL composition; the rest of the flow is identical.
            principal = (
                kwargs.pop("user_principal_id", None)
                or self.default_user_principal_id
            )
            invoke_kwargs: dict[str, Any] = {
                "target_rs_url": f"{rs_base_url}/documents/{document_id}",
                "http_method": "GET",
                "headers": dict(self.headers),
                "tool": self.tool_id,
                "action": list(self.action),
                "resource": document_id,
                "constraints": {"provider": self.provider},
                "tool_arguments": {"document_id": document_id},
            }
            try:
                if principal:
                    resp = self._hawcx_agent.invoke_for(principal, **invoke_kwargs)
                else:
                    resp = self._hawcx_agent.invoke(**invoke_kwargs)
            except RequestRejected as exc:
                return f"[hawcx rejected: {exc.reason}]"
            except HawcxError as exc:
                return f"[hawcx error: {exc}]"

            if resp.http_status == 404:
                return f"[document {document_id!r} not found or not accessible]"
            if resp.http_status >= 400:
                return f"[hawcx HTTP {resp.http_status}]"
            return resp.body.decode("utf-8", errors="replace")

    return _DocumentTool(
        name="hawcx_get_document",
        description=(
            "Retrieve a specific document by ID from the protected document store. "
            "Always pass the user_principal_id you were given for this task."
        ),
        hawcx_agent=agent,
        provider=provider,
        tool_id=tool_id,
        endpoint=f"{rs_base_url}/documents",
        method="GET",
        action=["read"],
        args_schema=_DocumentInput,
    )
