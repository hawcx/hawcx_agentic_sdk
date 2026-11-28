"""HawcxTool — CrewAI ``BaseTool`` subclass that proxies through a HAAP agent.

Design notes
------------

1.  **No credential material crosses this boundary.** ``HawcxTool._run``
    forwards the call to ``HawcxAgent.invoke`` (or ``invoke_for`` when a
    host-bound runtime principal is set). The Assembler process performs the
    §47 Pattern Y sidecar fetch (HAAP token + provider bearer credential) and
    constructs the outbound HTTP request itself. The credential value is
    never returned to the Python process; this class only sees the
    response body and headers.

2.  **CrewAI BaseTool is a Pydantic v2 model.** ``HawcxAgent`` is not a
    Pydantic-friendly type, so it lives on a ``PrivateAttr`` rather than
    as a model field. When ``crewai`` is not installed, ``HawcxTool``
    falls back cleanly to a minimal Pydantic v2 ``BaseTool`` base so bare
    SDK environments can construct, validate, and test tools identically.

3.  **Runtime principal is strictly host-bound (CS v7.21.4 §9.1).**
    ``HawcxTool`` binds its optional ``default_user_principal_id`` on the
    host at construction time or per end-user via :meth:`HawcxTool.for_user`.
    Untrusted LLM tool-call ``kwargs`` and ``args_schema`` models MUST NEVER
    supply or override ``user_principal_id``, ``acting_for_user``,
    ``ciba_approved``, or ``user_subject``; any such attempt is rejected
    fail-closed with ``E_AUTHORITY_CLAIM (0x0058)`` before a single IPC byte
    is written.

4.  **Provider routing.** ``provider`` is forwarded to the Assembler as the
    top-level ``ToolCallRequest.provider`` wire field (never nested inside
    ``constraints``). The Assembler uses ``tool_id`` (mapped to the IPC
    ``tool`` field) as the §47.4 tool-identity binding and top-level
    ``provider`` to route the §47.8 ``GetExternalCredential`` request / RSV
    OAuth proxy selection.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

from hawcx_haap import HawcxAgent, RequestRejected
from hawcx_haap.agent import _validate_headers_i2
from hawcx_haap.errors import HawcxError
from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, Field, PrivateAttr


class _FreeFormArgs(BaseModel):
    """Permissive default argument schema when no explicit ``args_schema`` is set."""

    model_config = ConfigDict(extra="allow")
    input: str | None = Field(default=None, description="Optional tool input.")


try:
    from crewai.tools import BaseTool
except ImportError:
    class BaseTool(BaseModel):  # type: ignore[no-redef]
        """Minimal Pydantic v2 ``BaseTool`` shim when ``crewai`` is not installed."""

        model_config = ConfigDict(arbitrary_types_allowed=True)

        name: str
        description: str
        args_schema: type[BaseModel] = Field(default=_FreeFormArgs)

        def _validate_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
            if self.args_schema is not None and self.args_schema.model_fields:
                validated = self.args_schema.model_validate(kwargs)
                return validated.model_dump(exclude_unset=True)
            return kwargs

        def run(self, *args: Any, **kwargs: Any) -> Any:
            if not args:
                kwargs = self._validate_kwargs(kwargs)
            return self._run(*args, **kwargs)

        async def arun(self, *args: Any, **kwargs: Any) -> Any:
            if not args:
                kwargs = self._validate_kwargs(kwargs)
            return await self._arun(*args, **kwargs)

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError


_FORBIDDEN_LLM_KWARGS: frozenset[str] = frozenset(
    {
        "user_principal_id",
        "acting_for_user",
        "ciba_approved",
        "user_subject",
    }
)
_MAX_ARG_SCAN_DEPTH: int = 64


def _normalize_authority_key(key: str) -> str:
    nfkc = unicodedata.normalize("NFKC", key)
    cleaned = "".join(
        ch
        for ch in nfkc
        if not ch.isspace()
        and ord(ch) > 0x20
        and ord(ch) != 0x7F
        and not unicodedata.category(ch).startswith("C")
    )
    return cleaned.casefold()


def _validate_clean_str(val: Any, field_name: str) -> str:
    if not isinstance(val, str):
        raise TypeError(f"{field_name} must be str; got {type(val).__name__}")
    if (
        not val
        or val != val.strip()
        or any(
            ord(ch) < 0x20 or ord(ch) == 0x7F or unicodedata.category(ch).startswith("C")
            for ch in val
        )
    ):
        raise ValueError(
            f"{field_name} must be a non-empty string without leading/trailing whitespace "
            "or control characters"
        )
    return val


def _extract_alias_candidates(alias_val: Any) -> list[str]:
    if isinstance(alias_val, str):
        return [alias_val]
    if isinstance(alias_val, AliasPath):
        return [seg for seg in alias_val.convert_to_aliases() if isinstance(seg, str)]
    if isinstance(alias_val, AliasChoices):
        out: list[str] = []
        for choice in alias_val.choices:
            out.extend(_extract_alias_candidates(choice))
        return out
    return []


def _collect_json_schema_properties(node: Any, out: set[str], _depth: int = 0) -> None:
    if _depth > _MAX_ARG_SCAN_DEPTH:
        return
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            for prop_name in props:
                if isinstance(prop_name, str):
                    out.add(prop_name)
        for v in node.values():
            _collect_json_schema_properties(v, out, _depth + 1)
    elif isinstance(node, list):
        for item in node:
            _collect_json_schema_properties(item, out, _depth + 1)


def _validate_args_schema_no_authority_fields(schema: Any) -> None:
    if isinstance(schema, type) and issubclass(schema, BaseModel):
        candidates: set[str] = set()
        for field_name, field_info in schema.model_fields.items():
            candidates.add(field_name)
            candidates.update(_extract_alias_candidates(field_info.alias))
            candidates.update(_extract_alias_candidates(field_info.serialization_alias))
            candidates.update(_extract_alias_candidates(field_info.validation_alias))
        try:
            json_schema = schema.model_json_schema()
        except Exception:
            json_schema = {}
        _collect_json_schema_properties(json_schema, candidates)
        exposed = sorted(
            cand for cand in candidates if _normalize_authority_key(cand) in _FORBIDDEN_LLM_KWARGS
        )
        if exposed:
            raise ValueError(
                f"E_AUTHORITY_CLAIM (0x0058): args_schema must not expose principal/authority "
                f"fields {exposed!r} across the LLM boundary (HAAP CS v7.21.4 §9.1); "
                "bind default_user_principal_id on HawcxTool or via .for_user()"
            )


def _scan_authority_payload(
    node: Any,
    found: set[str],
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
    max_depth: int = _MAX_ARG_SCAN_DEPTH,
) -> None:
    if _depth > max_depth:
        raise HawcxError(
            f"E_AUTHORITY_CLAIM (0x0058): tool-call arguments exceed maximum nesting depth "
            f"({max_depth})"
        )
    if isinstance(node, dict):
        seen = _seen if _seen is not None else set()
        obj_id = id(node)
        if obj_id in seen:
            raise HawcxError(
                "E_AUTHORITY_CLAIM (0x0058): cyclic tool-call argument container refused"
            )
        seen.add(obj_id)
        try:
            for k, v in node.items():
                if isinstance(k, str):
                    norm_k = _normalize_authority_key(k)
                    if norm_k in _FORBIDDEN_LLM_KWARGS:
                        found.add(k)
                    if (
                        norm_k == "tool_input"
                        and isinstance(v, str)
                        and v.strip().startswith(("{", "["))
                    ):
                        try:
                            parsed_ti = json.loads(v)
                        except (json.JSONDecodeError, RecursionError):
                            parsed_ti = None
                        if isinstance(parsed_ti, (dict, list)):
                            _scan_authority_payload(
                                parsed_ti,
                                found,
                                _depth=_depth + 1,
                                _seen=seen,
                                max_depth=max_depth,
                            )
                _scan_authority_payload(
                    v, found, _depth=_depth + 1, _seen=seen, max_depth=max_depth
                )
        finally:
            seen.discard(obj_id)
    elif isinstance(node, (list, tuple, set, frozenset)):
        seen = _seen if _seen is not None else set()
        obj_id = id(node)
        if obj_id in seen:
            raise HawcxError(
                "E_AUTHORITY_CLAIM (0x0058): cyclic tool-call argument container refused"
            )
        seen.add(obj_id)
        try:
            for item in node:
                _scan_authority_payload(
                    item, found, _depth=_depth + 1, _seen=seen, max_depth=max_depth
                )
        finally:
            seen.discard(obj_id)


def _reject_untrusted_authority_kwargs(payload: Any) -> None:
    found: set[str] = set()
    _scan_authority_payload(payload, found)
    if found:
        smuggled = sorted(found)
        raise HawcxError(
            f"E_AUTHORITY_CLAIM (0x0058): untrusted tool-call kwargs must not supply "
            f"authority fields {smuggled!r} (HAAP CS v7.21.4 §9.1); bind "
            "default_user_principal_id on the host or via .for_user()"
        )


def _validate_document_id(document_id: Any) -> str:
    if not isinstance(document_id, str):
        raise HawcxError(
            "E_INVALID_DOCUMENT_ID (0x002B): document_id must be a non-empty string"
        )
    if (
        not document_id
        or document_id != document_id.strip()
        or document_id in (".", "..")
        or ".." in document_id
        or any(
            ch in document_id
            for ch in ("/", "\\", "?", "#", "%", " ", "\t", "\r", "\n")
        )
        or any(
            ord(ch) < 0x20 or ord(ch) == 0x7F or unicodedata.category(ch).startswith("C")
            for ch in document_id
        )
    ):
        raise HawcxError(
            "E_INVALID_DOCUMENT_ID (0x002B): document_id must be a single URL-safe path "
            "segment without '/', '\\', '..', '?', '#', '%', whitespace, or control characters"
        )
    return document_id


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
        ``"nim"``, ``"anthropic"``, ``"generic-bearer"``). Forwarded as
        top-level ``ToolCallRequest.provider`` so the Assembler can route
        the §47.8 ``GetExternalCredential`` IPC / OAuth proxy call.
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
        for argument validation and for prompting the LLM. Must never
        expose ``user_principal_id`` or other authority claims.
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
        Optional host-bound principal that ``_run`` uses via
        :meth:`hawcx_haap.HawcxAgent.invoke_for`. Must already be in the
        agent's ``principal_allowlist``; for multi-user flows, materialize
        per-user tools on the host via :meth:`for_user`.
    """

    name: str
    description: str

    model_config = ConfigDict(arbitrary_types_allowed=True)

    provider: str = Field(..., description="HAAP §47 provider class identifier.")
    tool_id: str = Field(..., description="HAAP §47.4 tool identity for credential binding.")
    endpoint: str = Field(..., description="Destination URL the tool calls.")
    method: str = Field(default="POST")
    action: list[str] = Field(default_factory=lambda: ["invoke"])
    resource: str = Field(default="*")
    headers: dict[str, str] = Field(default_factory=dict)
    default_user_principal_id: str | None = Field(default=None)

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
        if "args_schema" in data:
            _validate_args_schema_no_authority_fields(data["args_schema"])
        if "headers" in data:
            if data["headers"] is None:
                raise TypeError("headers must be dict[str, str]; got NoneType")
            data["headers"] = _validate_headers_i2(data["headers"])
        for req_field in ("provider", "tool_id", "endpoint"):
            if req_field in data:
                _validate_clean_str(data[req_field], req_field)
        for opt_str_field in ("method", "resource"):
            if opt_str_field in data:
                _validate_clean_str(data[opt_str_field], opt_str_field)
        if data.get("default_user_principal_id") is not None:
            _validate_clean_str(
                data["default_user_principal_id"], "default_user_principal_id"
            )
        super().__init__(**data)
        _validate_args_schema_no_authority_fields(getattr(self, "args_schema", None))
        _validate_headers_i2(self.headers)
        _validate_clean_str(self.provider, "provider")
        _validate_clean_str(self.tool_id, "tool_id")
        _validate_clean_str(self.endpoint, "endpoint")
        _validate_clean_str(self.method, "method")
        _validate_clean_str(self.resource, "resource")
        if self.default_user_principal_id is not None:
            _validate_clean_str(
                self.default_user_principal_id, "default_user_principal_id"
            )
        self._hawcx_agent = agent

    # ── CrewAI surface ────────────────────────────────────────────────

    def _normalize_run_call(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        """Screen positional & keyword ``tool_input`` before Pydantic validation."""
        _reject_untrusted_authority_kwargs(kwargs)
        for arg in args:
            if isinstance(arg, (dict, list, tuple, set, frozenset)):
                _reject_untrusted_authority_kwargs(arg)
            elif isinstance(arg, str) and arg.strip().startswith(("{", "[")):
                try:
                    parsed_arg = json.loads(arg)
                except (json.JSONDecodeError, RecursionError):
                    parsed_arg = None
                if isinstance(parsed_arg, (dict, list)):
                    _reject_untrusted_authority_kwargs(parsed_arg)

        if len(args) == 1 and isinstance(args[0], dict):
            if not all(isinstance(k, str) for k in args[0]):
                raise TypeError("tool_input dict keys must be strings")
            return (), {**args[0], **kwargs}

        if len(args) == 1 and not kwargs and isinstance(args[0], str):
            stripped = args[0].strip()
            if stripped.startswith("{"):
                try:
                    parsed_dict = json.loads(stripped)
                except (json.JSONDecodeError, RecursionError):
                    parsed_dict = None
                if isinstance(parsed_dict, dict) and all(
                    isinstance(k, str) for k in parsed_dict
                ):
                    return (), parsed_dict

        if not args and "tool_input" in kwargs:
            schema_fields = (
                self.args_schema.model_fields
                if (self.args_schema is not None and hasattr(self.args_schema, "model_fields"))
                else {}
            )
            if "tool_input" not in schema_fields:
                raw_ti = kwargs["tool_input"]
                if isinstance(raw_ti, dict):
                    if not all(isinstance(k, str) for k in raw_ti):
                        raise TypeError("tool_input dict keys must be strings")
                    rest = {k: v for k, v in kwargs.items() if k != "tool_input"}
                    return (), {**raw_ti, **rest}
                if isinstance(raw_ti, str) and raw_ti.strip().startswith("{"):
                    try:
                        parsed_kw = json.loads(raw_ti)
                    except (json.JSONDecodeError, RecursionError):
                        parsed_kw = None
                    if isinstance(parsed_kw, dict) and all(
                        isinstance(k, str) for k in parsed_kw
                    ):
                        rest = {k: v for k, v in kwargs.items() if k != "tool_input"}
                        return (), {**parsed_kw, **rest}

        return args, kwargs

    def run(self, *args: Any, **kwargs: Any) -> Any:
        norm_args, norm_kwargs = self._normalize_run_call(args, kwargs)
        return super().run(*norm_args, **norm_kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        norm_args, norm_kwargs = self._normalize_run_call(args, kwargs)
        return await super().arun(*norm_args, **norm_kwargs)

    def to_structured_tool(self) -> Any:
        if not hasattr(super(), "to_structured_tool"):
            raise AttributeError("to_structured_tool requires crewai to be installed")
        structured = super().to_structured_tool()  # type: ignore[misc]
        orig_parse = structured._parse_args

        def _guarded_parse_args(raw_args: Any) -> dict[str, Any]:
            if isinstance(raw_args, str) and raw_args.strip().startswith(("{", "[")):
                try:
                    decoded = json.loads(raw_args)
                except (json.JSONDecodeError, RecursionError):
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    _reject_untrusted_authority_kwargs(decoded)
            elif isinstance(raw_args, (dict, list, tuple, set, frozenset)):
                _reject_untrusted_authority_kwargs(raw_args)
            return dict(orig_parse(raw_args))

        object.__setattr__(structured, "_parse_args", _guarded_parse_args)
        return structured

    def _validate_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Reject smuggled authority claims BEFORE Pydantic schema stripping."""
        _reject_untrusted_authority_kwargs(kwargs)
        return super()._validate_kwargs(kwargs)

    def _run(self, **kwargs: Any) -> str:
        """Execute the HAAP-authenticated tool call.

        Uses the host-bound :attr:`default_user_principal_id` (if set) via
        :meth:`HawcxAgent.invoke_for`, or passes ``acting_for_user=None`` to
        :meth:`HawcxAgent.invoke` for unprincipled calls. Any attempt to pass
        authority claims in ``kwargs`` raises :class:`HawcxError`
        (``E_AUTHORITY_CLAIM (0x0058)``) fail-closed before encoding or IPC.
        """
        _reject_untrusted_authority_kwargs(kwargs)

        principal = self.default_user_principal_id
        body = self._encode_body(kwargs)
        headers = dict(self.headers)
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        invoke_kwargs: dict[str, Any] = {
            "target_rs_url": self.endpoint,
            "http_method": self.method,
            "headers": headers,
            "tool": self.tool_id,
            "action": list(self.action),
            "resource": self.resource,
            "provider": self.provider,
            "body": body,
            "tool_arguments": dict(kwargs) if kwargs else None,
        }

        try:
            if principal is not None:
                resp = self._hawcx_agent.invoke_for(principal, **invoke_kwargs)
            else:
                resp = self._hawcx_agent.invoke(acting_for_user=None, **invoke_kwargs)
        except RequestRejected as exc:
            return f"[hawcx rejected: {exc.reason}]"
        except HawcxError as exc:
            return f"[hawcx error: {exc}]"

        if resp.http_status >= 400:
            return f"[hawcx HTTP {resp.http_status}] {self._safe_decode(resp.body)}"
        return self._safe_decode(resp.body)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _encode_body(kwargs: dict[str, Any]) -> bytes | None:
        """JSON-encode the args dict, or return None for GET-style calls."""
        if not kwargs:
            return None
        return json.dumps(kwargs, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _safe_decode(body: bytes) -> str:
        return body.decode("utf-8", errors="replace")

    def for_user(self, user_principal_id: str) -> HawcxTool:
        """Return a sibling tool bound on the host to ``user_principal_id``.

        Preserves the concrete tool subclass (including ``make_document_tool``)
        and shares the underlying ``HawcxAgent`` connection.
        """
        validated_principal = _validate_clean_str(
            user_principal_id, "user_principal_id"
        )
        validated_headers = _validate_headers_i2(self.headers)
        init_kwargs: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "args_schema": self.args_schema,
            "provider": self.provider,
            "tool_id": self.tool_id,
            "endpoint": self.endpoint,
            "method": self.method,
            "action": list(self.action),
            "resource": self.resource,
            "headers": validated_headers,
            "default_user_principal_id": validated_principal,
        }
        for optional_attr in (
            "env_vars",
            "result_schema",
            "cache_function",
            "result_as_answer",
            "max_usage_count",
            "tool_failure_policy",
        ):
            if optional_attr in type(self).model_fields:
                val = getattr(self, optional_attr)
                init_kwargs[optional_attr] = list(val) if isinstance(val, list) else val
        return type(self)(hawcx_agent=self._hawcx_agent, **init_kwargs)


# ── Factory functions ────────────────────────────────────────────────────────


class _SearchInput(BaseModel):
    query: str = Field(description="Search query string.")


class _DocumentInput(BaseModel):
    document_id: str = Field(description="Opaque document identifier to retrieve.")


def make_search_tool(
    agent: HawcxAgent,
    *,
    rs_base_url: str = "https://api.example.com",
    tool_id: str = "search",
    provider: str = "generic-bearer",
    default_user_principal_id: str | None = None,
) -> HawcxTool:
    """Build a CrewAI tool that searches via HAAP with optional host-bound principal."""
    base_url = _validate_clean_str(rs_base_url, "rs_base_url").rstrip("/")
    return HawcxTool(
        name="hawcx_search",
        description="Search the organisation's protected knowledge base via Hawcx HAAP.",
        hawcx_agent=agent,
        provider=provider,
        tool_id=tool_id,
        endpoint=f"{base_url}/search",
        method="POST",
        action=["read"],
        args_schema=_SearchInput,
        default_user_principal_id=default_user_principal_id,
    )


def make_document_tool(
    agent: HawcxAgent,
    *,
    rs_base_url: str = "https://api.example.com",
    tool_id: str = "documents",
    provider: str = "generic-bearer",
    default_user_principal_id: str | None = None,
) -> HawcxTool:
    """Build a CrewAI tool that fetches a single document via HAAP."""
    base_url = _validate_clean_str(rs_base_url, "rs_base_url").rstrip("/")

    class _DocumentTool(HawcxTool):
        def __init__(self, **data: Any) -> None:
            super().__init__(**data)

        def _run(self, document_id: str, **kwargs: Any) -> str:  # type: ignore[override]
            _reject_untrusted_authority_kwargs(kwargs)
            clean_doc_id = _validate_document_id(document_id)
            principal = self.default_user_principal_id
            invoke_kwargs: dict[str, Any] = {
                "target_rs_url": f"{base_url}/documents/{clean_doc_id}",
                "http_method": "GET",
                "headers": dict(self.headers),
                "tool": self.tool_id,
                "action": list(self.action),
                "resource": clean_doc_id,
                "provider": self.provider,
                "tool_arguments": {"document_id": clean_doc_id},
            }
            try:
                if principal is not None:
                    resp = self._hawcx_agent.invoke_for(principal, **invoke_kwargs)
                else:
                    resp = self._hawcx_agent.invoke(acting_for_user=None, **invoke_kwargs)
            except RequestRejected as exc:
                return f"[hawcx rejected: {exc.reason}]"
            except HawcxError as exc:
                return f"[hawcx error: {exc}]"

            if resp.http_status == 404:
                return f"[document {clean_doc_id!r} not found or not accessible]"
            if resp.http_status >= 400:
                return f"[hawcx HTTP {resp.http_status}]"
            return resp.body.decode("utf-8", errors="replace")

    return _DocumentTool(
        name="hawcx_get_document",
        description="Retrieve a specific document by ID from the protected document store.",
        hawcx_agent=agent,
        provider=provider,
        tool_id=tool_id,
        endpoint=f"{base_url}/documents",
        method="GET",
        action=["read"],
        args_schema=_DocumentInput,
        default_user_principal_id=default_user_principal_id,
    )
