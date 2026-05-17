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
    ) -> ToolCallResponse:
        """Profile E tool call.

        Forwards a :class:`ToolCallRequest` to the Assembler and returns the
        decrypted :class:`ToolCallResponse`. Raises
        :class:`hawcx_haap.errors.RequestRejected` if the Assembler rejects.

        Parameters mirror the fields of ``haap_ipc::messages::assembler::
        ToolCallRequest``. ``body`` maps to the wire field
        ``plaintext_request_body``.
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
        )
        return self._client.invoke(req)

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
