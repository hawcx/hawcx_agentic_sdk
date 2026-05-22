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

import hashlib
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
    """Resolve the per-user IPC base dir.

    Resolution order (H-4 2026-05-20):

    1. ``$XDG_RUNTIME_DIR/hawcx/`` (preferred — systemd creates this
       0o700 per UID and tears it down at logout).
    2. ``$TMPDIR/hawcx/`` (macOS where ``XDG_RUNTIME_DIR`` is unset by
       default but ``TMPDIR`` is per-UID).
    3. ``/tmp/hawcx/`` — requires explicit ``HAAP_SDK_ALLOW_TMP_IPC=1``
       opt-in. The previous code silently fell back here; that
       fallback let an attacker on the same host symlink-race the
       socket parent dir. Now the SDK refuses to use ``/tmp/hawcx/``
       unless the operator opts in.

    Matches the Rust resolver in
    ``haap-sdk-ipc::paths::ipc_socket_dir``.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "hawcx"
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        return Path(tmpdir) / "hawcx"
    if os.environ.get("HAAP_SDK_ALLOW_TMP_IPC") == "1":
        return Path("/tmp/hawcx")
    raise HawcxError(
        "no IPC base dir found: set XDG_RUNTIME_DIR (preferred) or "
        "TMPDIR, or set HAAP_SDK_ALLOW_TMP_IPC=1 to opt into the "
        "legacy /tmp/hawcx/ path (not recommended — see README "
        "'Threat model - IPC socket placement')."
    )


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

    Runtime principal allowlist (H-3 hardening 2026-05-20)
    ------------------------------------------------------
    ``principal_allowlist`` is a required keyword argument on every
    factory. It is the closed set of user principal IDs this agent
    instance may emit via :meth:`invoke` ``acting_for_user`` /
    :meth:`invoke_for`. Out-of-list principals raise :class:`HawcxError`
    synchronously before any IPC bytes are written — an LLM-derived
    principal string can never silently switch the effective user.

    Pass ``[]`` to forbid runtime principal switching entirely (any
    non-empty ``acting_for_user`` will raise). The allowlist MUST be
    a static set sourced from operator config; never derive from LLM
    output, request bodies, or any input the model can influence.
    """

    def __init__(
        self,
        client: AssemblerClient,
        principal_allowlist: frozenset[str],
    ) -> None:
        self._client: AssemblerClient | None = client
        self._principal_allowlist = principal_allowlist

    @classmethod
    def connect(
        cls,
        endpoint: str,
        *,
        principal_allowlist: list[str],
        timeout_secs: float | None = 5.0,
    ) -> HawcxAgent:
        """Open the agent IPC socket at ``endpoint`` and complete the handshake.

        ``principal_allowlist`` is required (H-3 2026-05-20). Pass ``[]``
        to forbid runtime principal switching entirely.
        """
        allowlist = _validate_principal_allowlist(principal_allowlist)
        client = AssemblerClient.connect(endpoint, timeout_secs=timeout_secs)
        return cls(client, allowlist)

    @classmethod
    def connect_by_agent_id(
        cls,
        agent_id: str,
        *,
        principal_allowlist: list[str],
        index: int = 0,
        ipc_dir: Path | None = None,
        timeout_secs: float | None = 5.0,
    ) -> HawcxAgent:
        """Resolve the conventional agent-Assembler endpoint, then ``connect``."""
        return cls.connect(
            default_endpoint_for(agent_id, index=index, ipc_dir=ipc_dir),
            principal_allowlist=principal_allowlist,
            timeout_secs=timeout_secs,
        )

    @classmethod
    def enroll(
        cls,
        *,
        name: str,
        org_token: str,
        principal_allowlist: list[str],
        agent_class: str = "default",
        authenticator_socket: str | None = None,
        ipc_dir: Path | None = None,
        index: int = 0,
        connect_timeout_secs: float | None = 5.0,
        enroll_timeout_secs: float | None = 30.0,
    ) -> HawcxAgent:
        """Acquire an agent identity at runtime and connect to its Assembler.

        Per HAAP CS v7.2.6 §4.2 (Tier-2 Agent Enrollment) and §5.2 (X3DH
        Mode B), this drives the per-agent Authenticator process to:

        1. Generate ``IK_i`` (Ristretto255) — or load the supervisor-prepared
           IK_i if the runtime was pre-staged via ``MSG_REGISTER_PREPARE_REQ``
           (CS v7.1.1 §4.6.3).
        2. Perform the X3DH ceremony against the configured AS using the
           supplied ``org_token``.
        3. Return the resulting ``agent_instance_id`` / ``session_id``.

        After enrollment succeeds, this method opens the agent-Assembler
        IPC socket for the new ``agent_instance_id`` and returns a fully
        connected :class:`HawcxAgent`.

        Parameters
        ----------
        name
            Agent name used to address the Authenticator control socket
            (default-path resolution: ``{ipc_dir}/{name}/auth-control.sock``).
            For a supervisor-prepared deployment this MUST equal the
            ``agent_id`` the supervisor passed to ``MSG_REGISTER_PREPARE_REQ``;
            in greenfield demos it is any operator-chosen identifier.
        org_token
            The §4.2 org-issued enrollment token. Forwarded to the
            Authenticator on the wire; the Authenticator validates it
            against the AS during X3DH. Treat as a credential — never log.
        principal_allowlist
            Same semantics as :meth:`connect`. Required keyword arg.
        agent_class
            Optional agent class string (default ``"default"``); the AS
            uses this for policy bundle selection.
        authenticator_socket
            Override for the Authenticator control-socket path. Defaults
            to the canonical convention. ``HAAP_AUTH_CONTROL_SOCK`` env
            var also overrides (matches the Rust supervisor).
        ipc_dir, index, connect_timeout_secs, enroll_timeout_secs
            Plumbing. ``enroll_timeout_secs`` is longer than the
            assembler-connect timeout because §4.2 enrollment includes
            a full X3DH round-trip to the AS.

        Raises
        ------
        EnrollmentRejected
            The Authenticator returned ``Degraded`` or an error envelope.
        IpcError, HawcxError
            Transport / shape failures.

        Security notes
        --------------
        ``org_token`` is a single-use bearer credential per §4.2. Do not
        persist it on disk or include it in log messages. The SDK forwards
        it directly to the local Authenticator over the per-UID-restricted
        control socket (UDS owner-uid check + 0o700 parent-dir mode
        enforced by :func:`hawcx_haap.ipc._validate_ipc_socket_path`).

        Examples
        --------
        ::

            agent = HawcxAgent.enroll(
                name="researcher",
                org_token=os.environ["HAAP_ORG_TOKEN"],
                principal_allowlist=["alice@example.com"],
            )
        """
        from hawcx_haap.auth_ipc import (
            AuthenticatorClient,
            default_auth_control_socket_for,
        )

        allowlist = _validate_principal_allowlist(principal_allowlist)
        if not name:
            raise HawcxError("HawcxAgent.enroll requires a non-empty `name`")
        if not org_token:
            raise HawcxError(
                "HawcxAgent.enroll requires a non-empty `org_token`; "
                "obtain one from the Hawcx Admin Console (CS v7.2.6 §4.2)"
            )
        auth_endpoint = authenticator_socket or default_auth_control_socket_for(
            name, ipc_dir=ipc_dir
        )

        # Phase 1 — Authenticator-driven enrollment ceremony.
        with AuthenticatorClient.connect(
            auth_endpoint, timeout_secs=enroll_timeout_secs
        ) as auth:
            result = auth.register_agent(
                agent_class=agent_class,
                subject_user_id=name,
                org_token=org_token,
                prepared_agent_id=name,
            )

        # Phase 2 — connect to the Assembler agent socket for the
        # newly-enrolled identity. The supervisor wires the Assembler
        # against the same agent_id so the default-endpoint convention
        # resolves correctly.
        client = AssemblerClient.connect(
            default_endpoint_for(
                result.agent_instance_id, index=index, ipc_dir=ipc_dir
            ),
            timeout_secs=connect_timeout_secs,
        )
        agent = cls(client, allowlist)
        # Attach enrollment metadata so callers can introspect the
        # acquired identity (useful for logging + correlation, but the
        # session keys remain inside the Assembler process).
        agent._enrollment = result  # type: ignore[attr-defined]
        return agent

    @property
    def enrollment(self) -> Any:  # type: ignore[no-untyped-def]
        """The :class:`EnrollmentResult` set by :meth:`enroll`, or ``None``.

        Returns ``None`` for agents constructed via :meth:`connect` /
        :meth:`connect_by_agent_id` (the SDK has no enrollment context
        for pre-provisioned identities).
        """
        return getattr(self, "_enrollment", None)

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

        Allowlist enforcement: when ``acting_for_user`` is provided it
        MUST be a member of the ``principal_allowlist`` passed at
        construction. Out-of-list values raise :class:`HawcxError`
        before any IPC bytes are written.
        """
        if self._client is None:
            raise HawcxError("agent already closed")
        if acting_for_user is not None:
            self._assert_principal_allowed(acting_for_user)
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
        # Pre-check here so the stack trace points at the invoke_for
        # call site rather than the inner invoke() forward.
        self._assert_principal_allowed(user_principal_id)
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

    def _assert_principal_allowed(self, principal: str) -> None:
        """Validate ``principal`` against the construction-time allowlist.

        Raises :class:`HawcxError` for empty strings and out-of-list
        values. The error message redacts the rejected principal to a
        12-hex-char SHA-256 fingerprint so an attacker fuzzing
        principal IDs cannot use the exception text as an enumeration
        oracle.
        """
        if principal == "":
            raise HawcxError(
                "acting_for_user must be a non-empty string; omit the "
                "field to opt out of runtime principal switching"
            )
        if principal not in self._principal_allowlist:
            fp = _principal_fingerprint(principal)
            raise HawcxError(
                f"acting_for_user principal not in principal_allowlist "
                f"(fingerprint={fp}); add the principal to the allowlist "
                "at HawcxAgent.connect() time or omit acting_for_user. "
                "See README 'Threat model - runtime principal'."
            )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None  # type: ignore[assignment]

    def __enter__(self) -> HawcxAgent:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ── Module-level helpers ────────────────────────────────────────────


def _validate_principal_allowlist(list_arg: list[str]) -> frozenset[str]:
    """Validate the shape of ``principal_allowlist`` at construction.

    The keyword-arg type annotation already declares ``list[str]`` so
    static checkers catch the obvious shape errors, but Python isn't
    enforced at runtime — a JS-style ``None`` slip-through (e.g., a
    caller refactor that drops the kwarg) must hit a clear guard
    rather than silently producing a verifier with no allowlist.
    """
    if not isinstance(list_arg, (list, tuple, set, frozenset)):
        raise TypeError(
            "HawcxAgent.connect requires keyword argument "
            "`principal_allowlist`: pass a list of permitted user "
            "principal IDs, or [] to forbid runtime principal switching. "
            "See README 'Threat model - runtime principal'."
        )
    for p in list_arg:
        if not isinstance(p, str):
            raise TypeError(
                f"principal_allowlist entries must be str; got {type(p).__name__}"
            )
        if p == "":
            raise TypeError(
                "principal_allowlist entries must be non-empty strings"
            )
    return frozenset(list_arg)


def _principal_fingerprint(principal: str) -> str:
    """12-hex-char SHA-256 prefix of the principal string.

    Used in error messages so the SDK does not echo rejected principal
    IDs verbatim. SHA-256 only - never SHA-1 / MD5 (Hawcx posture).
    """
    return hashlib.sha256(principal.encode("utf-8")).hexdigest()[:12]
