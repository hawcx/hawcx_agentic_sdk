"""hawcx-crewai — CrewAI BaseTool adapter for the Hawcx Agent Authentication Protocol.

This package exposes :class:`HawcxTool`, a thin subclass of
``crewai.tools.BaseTool`` whose ``_run`` invokes a HAAP Profile E tool call
through a connected :class:`hawcx_haap.HawcxAgent`.

The architectural property of interest (HAAP CS v7.2.6 §47 Pattern Y, §45.7
Pattern Z): the LLM process never holds bearer credentials or HAAP session
keys. ``HawcxTool._run`` asks the Assembler — over local UDS only — to
construct, sign, and ship the outbound HTTP request. The credential value is
attached inside the Assembler process and never reaches the Python
``HawcxTool`` instance, the CrewAI runtime, or the model context.

Quick start::

    from hawcx_haap import HawcxAgent
    from hawcx_crewai import HawcxTool

    with HawcxAgent.connect_by_agent_id(
        "research-u1",
        principal_allowlist=["alice@example.com"],
    ) as agent:
        tool = HawcxTool(
            name="nim_search",
            description="Search via NVIDIA NIM.",
            hawcx_agent=agent,
            provider="nim",
            tool_id="nim-search-v1",
            endpoint="https://api.nim.nvidia.com/v1/search",
        )
        # Hand `tool` to a CrewAI Agent's tools=[...] list.

See README.md for the full example, including the per-user-principal
sugar exposed via :meth:`HawcxTool.for_user`.
"""

from hawcx_crewai.tool import (
    HawcxTool,
    make_document_tool,
    make_search_tool,
)

__version__ = "0.1.0a1"
__all__ = [
    "HawcxTool",
    "make_search_tool",
    "make_document_tool",
    "__version__",
]
