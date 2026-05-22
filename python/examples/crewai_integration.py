"""CrewAI × HAAP integration example.

Shows how to wrap HawcxAgent as CrewAI tools so that every tool call is
authenticated through the Hawcx pipeline with per-user principal tracking.

Architecture
------------
- One HawcxAgent shared for the lifetime of the process (single Assembler
  connection, single set of session keys held inside the Assembler binary).
- Each tool call carries the end-user's ID via ``invoke_for()`` so the
  Hawcx gateway can enforce Cedar policy:
  ``context.user_principal_id == resource.owner_user_id``.
- ``principal_allowlist`` is sourced from operator-controlled config
  (``HAAP_ALLOWED_PRINCIPALS``). The LLM is told which user ID to use in
  the task description; even if the model were to hallucinate a different ID,
  the SDK rejects any principal not already on the allowlist before a single
  IPC byte is written.

Prerequisites
-------------
- The customer-side pipeline must be running (``haap-supervisor`` installed
  via the hx_agentic_sdk release tarball or Docker image).
- ``HAAP_AGENT_ID`` — pre-provisioned agent identity (Hawcx Admin Console
  → CAA → Authenticator flow per CS v7.2.5 §4.6.3).
- ``HAAP_ALLOWED_PRINCIPALS`` — comma-separated list of end-user IDs that
  this agent instance is permitted to act on behalf of.  Example::

      export HAAP_ALLOWED_PRINCIPALS="alice@example.com,bob@example.com"

- ``HAAP_RS_BASE_URL`` (optional) — base URL of the protected resource
  server; defaults to ``https://api.example.com``.

Install
-------
::

    pip install "hawcx-crewai"

(The ``hawcx-crewai`` package depends on ``hawcx-haap`` and ``crewai``, so
no other installs are required.)
"""

from __future__ import annotations

import os
import sys

from crewai import Agent, Crew, Process, Task
from hawcx_crewai import make_document_tool, make_search_tool
from hawcx_haap import HawcxAgent


# ── Operator config ──────────────────────────────────────────────────────────
# All values here come from the operator environment, never from LLM output
# or user-supplied request bodies. See README "Threat model - runtime principal".


def _require_env(var: str) -> str:
    val = os.environ.get(var)
    if not val:
        print(f"error: {var} is not set", file=sys.stderr)
        sys.exit(2)
    return val


AGENT_ID: str = _require_env("HAAP_AGENT_ID")

# The allowlist is the closed set of principals this agent may act on behalf of.
# Populate from an operator-controlled source (env var, secrets manager, etc.).
# Never derive from LLM output or request bodies.
ALLOWED_PRINCIPALS: list[str] = [
    p.strip()
    for p in _require_env("HAAP_ALLOWED_PRINCIPALS").split(",")
    if p.strip()
]

RS_BASE_URL: str = os.environ.get("HAAP_RS_BASE_URL", "https://api.example.com")


# ── Crew builder ──────────────────────────────────────────────────────────────


def build_research_crew(
    haap_agent: HawcxAgent,
    user_principal_id: str,
    research_question: str,
) -> Crew:
    """Build a two-agent research crew scoped to a single end-user.

    Both tools receive ``user_principal_id`` from the task description so
    every HAAP token minted during this crew's run carries
    ``scope_json.user_principal_id``. The gateway's Cedar policy can then
    restrict results to data that belongs to that user.

    ``user_principal_id`` must already be in the ``principal_allowlist``
    passed when constructing ``haap_agent`` — the SDK enforces this
    synchronously at ``invoke_for`` call time.
    """
    # hawcx_crewai provides the CrewAI BaseTool adapter. The factory
    # helpers preserve the pre-v0.1.0a11 ergonomic surface; new code can
    # instead construct ``HawcxTool`` directly for finer control over
    # provider class, tool_id (§47.4 binding), and endpoint.
    search_tool = make_search_tool(haap_agent, rs_base_url=RS_BASE_URL)
    doc_tool = make_document_tool(haap_agent, rs_base_url=RS_BASE_URL)

    researcher = Agent(
        role="Research Analyst",
        goal="Find accurate answers from the protected knowledge base",
        backstory=(
            "You are a meticulous analyst with access to a protected document store. "
            "You always cite the document IDs you retrieved and never invent facts."
        ),
        tools=[search_tool, doc_tool],
        verbose=True,
    )

    writer = Agent(
        role="Technical Writer",
        goal="Distil research findings into a clear, concise summary",
        backstory=(
            "You turn raw research into crisp, actionable paragraphs. "
            "You only summarise what the Analyst provided — no invented content."
        ),
        verbose=True,
    )

    # The user principal ID is embedded in the task description so the LLM
    # forwards the correct value to every tool call. The SDK's allowlist is
    # the enforcement boundary — the task description is just the instruction.
    research_task = Task(
        description=(
            f"Research the following question on behalf of user '{user_principal_id}':\n\n"
            f"{research_question}\n\n"
            f"Pass user_principal_id='{user_principal_id}' to every tool call. "
            "Use hawcx_search to find relevant documents, then hawcx_get_document "
            "to retrieve the most promising ones. Cite every document ID you use."
        ),
        expected_output=(
            "A list of findings with document IDs cited, covering the research question."
        ),
        agent=researcher,
    )

    summary_task = Task(
        description=(
            "Summarise the Analyst's findings into a single paragraph suitable for "
            "a non-technical end-user. Focus on actionable insights. "
            "Do not add information not present in the research output."
        ),
        expected_output="A concise paragraph summarising the research findings.",
        agent=writer,
        context=[research_task],
    )

    return Crew(
        agents=[researcher, writer],
        tasks=[research_task, summary_task],
        process=Process.sequential,
        verbose=True,
    )


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> int:
    # One HawcxAgent for the lifetime of this process — one Assembler connection,
    # all session keys held inside the Assembler binary, never in this process.
    with HawcxAgent.connect_by_agent_id(
        AGENT_ID,
        # principal_allowlist is sourced from operator config above.
        # The SDK rejects any acting_for_user value not in this set
        # before a single IPC byte is written.
        principal_allowlist=ALLOWED_PRINCIPALS,
    ) as haap_agent:
        for user_id in ALLOWED_PRINCIPALS:
            print(f"\n{'=' * 60}")
            print(f"Running research crew for: {user_id}")
            print("=" * 60)

            crew = build_research_crew(
                haap_agent=haap_agent,
                user_principal_id=user_id,
                research_question="What are the latest updates to the data retention policy?",
            )
            result = crew.kickoff()

            print(f"\n--- Summary for {user_id} ---\n{result}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
