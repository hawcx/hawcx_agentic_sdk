"""HawcxAgent — Profile E entry point.

The SDK does not spawn the supervisor (that's an operational concern handled
by the ``hx_agentic_sdk`` release tarball or Docker image); it connects to the
Assembler's already-running agent socket and proxies tool calls.

The Python process never holds session keys (``response_key``, ``K_req``,
``K_resp``). All cryptographic operations happen inside the Assembler process;
the SDK exchanges only plaintext request bodies and decrypted response bodies
over the local IPC socket.
"""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from hawcx_haap.errors import HawcxError
from hawcx_haap.ipc import (
    AssemblerClient,
    TokenTransport,
    ToolCallRequest,
    ToolCallResponse,
)


def _default_ipc_dir() -> Path:
    """Match ``crates/haap-supervisor/src/paths.rs`` default base directory."""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "hawcx"
    return Path("/tmp/hawcx")


def default_endpoint_for(
    agent_id: str,
    *,
    index: int = 0,
    ipc_dir: Path | None = None,
) -> str:
    """Compute the conventional Assembler agent-socket path for an agent id.

    - Unix:    ``{ipc_dir}/{agent_id}/agent-assembler-{index}.sock``
    - Windows: ``\\\\.\\pipe\\haap-{agent_id}-agent-assembler-{index}``
    """
    if sys.platform == "win32":
        return rf"\\.\pipe\haap-{agent_id}-agent-assembler-{index}"
    base = ipc_dir or _default_ipc_dir()
    return str(base / agent_id / f"agent-assembler-{index}.sock")


class HawcxAgent:
    """Customer-facing handle for HAAP Profile E tool calls.

    Construct via :meth:`connect` (explicit socket path) or
    :meth:`connect_by_agent_id` (path-by-convention from an agent id). All
    cryptography happens in the Assembler; this class is a thin transport for
    :class:`ToolCallRequest` / :class:`ToolCallResponse`.
    """

    def __init__(self, client: AssemblerClient) -> None:
        self._client = client

    @classmethod
    def connect(
        cls,
        endpoint: str,
        *,
        timeout_secs: float | None = 5.0,
    ) -> HawcxAgent:
        """Open the agent IPC socket at ``endpoint`` and complete the handshake."""
        client = AssemblerClient.connect(endpoint, timeout_secs=timeout_secs)
        return cls(client)

    @classmethod
    def connect_by_agent_id(
        cls,
        agent_id: str,
        *,
        index: int = 0,
        ipc_dir: Path | None = None,
        timeout_secs: float | None = 5.0,
    ) -> HawcxAgent:
        """Resolve the conventional agent-Assembler endpoint, then ``connect``."""
        return cls.connect(
            default_endpoint_for(agent_id, index=index, ipc_dir=ipc_dir),
            timeout_secs=timeout_secs,
        )

    def invoke(
        self,
        *,
        target_rs_url: str,
        http_method: str = "POST",
        headers: dict[str, str] | None = None,
        tool: str = "",
        action: Iterable[str] | None = None,
        resource: str = "*",
        constraints: dict[str, Any] | None = None,
        body: bytes | None = None,
        claimed_intent_hash: str | None = None,
        tool_arguments: Any = None,
        content_type: str | None = None,
        transport: TokenTransport | None = None,
        request_id: str | None = None,
        acting_for_user: str | None = None,
    ) -> ToolCallResponse:
        """Profile E tool call.

        Forwards a :class:`ToolCallRequest` to the Assembler and returns the
        decrypted :class:`ToolCallResponse`. Raises
        :class:`hawcx_haap.errors.RequestRejected` if the Assembler rejects.

        Parameters mirror the fields of ``haap_ipc::messages::assembler::
        ToolCallRequest``. ``body`` maps to the wire field
        ``plaintext_request_body``.

        Runtime principal switching
        ---------------------------
        ``acting_for_user`` (optional) declares the human principal on whose
        behalf this single tool call is made. When set, the Assembler is
        expected to project the value into ``scope_json.user_principal_id``
        on the minted token (CS v6.9.0 line 163 explicitly allows arbitrary
        identity / correlation fields inside the AEAD-encrypted scope_json).
        The agent's pinned ``subject_user_id`` (set at enrollment) is NOT
        modified — only the per-call scope_json carries the runtime principal.

        The gateway's Cedar policy (e.g., ``config/policies/user_ownership.cedar``
        in the hx_labs admin-console policy set) can then enforce
        ``context.user_principal_id == resource.owner_user_id``, so one
        agent can serve Alice and Bob from the same supervisor pipeline
        with per-call ownership gating.

        When ``acting_for_user`` is ``None`` (the default), no
        ``user_principal_id`` field is added to scope_json — the agent
        acts on its own pinned ``subject_user_id``. Existing callers
        observe identical wire output.

        See :meth:`invoke_for` for the sugar form when the principal is the
        single most-important axis of a call.
        """
        if self._client is None:
            raise HawcxError("agent already closed")
        req = ToolCallRequest(
            request_id=request_id or f"req-{uuid.uuid4().hex[:16]}",
            target_rs_url=target_rs_url,
            http_method=http_method.upper(),
            headers=dict(headers or {}),
            tool=tool,
            action=list(action or []),
            resource=resource,
            constraints=dict(constraints or {}),
            plaintext_request_body=body,
            claimed_intent_hash=claimed_intent_hash,
            tool_arguments=tool_arguments,
            content_type=content_type,
            transport=transport,
            acting_for_user=acting_for_user,
        )
        return self._client.invoke(req)

    def invoke_for(
        self,
        user_principal_id: str,
        *,
        target_rs_url: str,
        http_method: str = "POST",
        headers: dict[str, str] | None = None,
        tool: str = "",
        action: Iterable[str] | None = None,
        resource: str = "*",
        constraints: dict[str, Any] | None = None,
        body: bytes | None = None,
        claimed_intent_hash: str | None = None,
        tool_arguments: Any = None,
        content_type: str | None = None,
        transport: TokenTransport | None = None,
        request_id: str | None = None,
    ) -> ToolCallResponse:
        """Sugar for :meth:`invoke` with a required ``acting_for_user``.

        ``agent.invoke_for("alice", target_rs_url=...)`` is equivalent to
        ``agent.invoke(acting_for_user="alice", target_rs_url=...)`` —
        the positional principal makes the per-call identity axis
        visually load-bearing at call sites that fan out to many users.

        Raises :class:`ValueError` if ``user_principal_id`` is empty
        (a missing principal is most likely a caller bug; use
        :meth:`invoke` directly if "no principal" is the intended
        semantic).
        """
        if not user_principal_id:
            raise ValueError(
                "invoke_for requires a non-empty user_principal_id; "
                "use invoke(...) without acting_for_user for unprincipled calls"
            )
        return self.invoke(
            target_rs_url=target_rs_url,
            http_method=http_method,
            headers=headers,
            tool=tool,
            action=action,
            resource=resource,
            constraints=constraints,
            body=body,
            claimed_intent_hash=claimed_intent_hash,
            tool_arguments=tool_arguments,
            content_type=content_type,
            transport=transport,
            request_id=request_id,
            acting_for_user=user_principal_id,
        )

    def send_clarification_answer(
        self,
        *,
        pending_id: str,
        session_id: int,
        answer_index: int | None = None,
        answer_text: str | None = None,
    ) -> None:
        """Profile E first hop: forward a clarification answer to the Assembler."""
        if self._client is None:
            raise HawcxError("agent already closed")
        self._client.send_clarification_answer(
            pending_id=pending_id,
            session_id=session_id,
            answer_index=answer_index,
            answer_text=answer_text,
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None  # type: ignore[assignment]

    def __enter__(self) -> HawcxAgent:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
