"""The blue_cell investigation agent — AutoBot's own graph export.

Adapted from Decepticon's ``agents/standard/blue_cell.py``: same read-only
tool set and prompt, but the framework dependencies are replaced by AutoBot's
own runtime — the thin LiteLLM-direct model factory (``agent.models``) and
the directly-assembled middleware list (no slot registry):

    UNTRUSTED_OUTPUT → PROMPT_INJECTION_SHIELD → BUDGET(thin) →
    SUMMARIZATION(deepagents) → PROMPT_CACHING(anthropic, conditional) →
    PATCH_TOOL_CALLS(deepagents)

Dropped per the agent-runtime design (§slot decisions): ROE_GUARDRAIL
(audit-only for blue; structural read-only safety comes from the tool set),
MODEL_OVERRIDE and PROXY_KEY_OVERRIDE (multi-tenant features).

The module-level ``graph`` factory is the LangGraph Platform export
served by ``langgraph serve`` (see the repo-root ``langgraph.json``) —
a callable so the model env is read at serve time, not import time.
"""

from __future__ import annotations

from importlib import resources
from typing import Any

from deepagents.backends import StateBackend
from deepagents.middleware.patch_tool_calls import PatchToolCallsMiddleware
from deepagents.middleware.summarization import create_summarization_middleware
from langchain.agents import create_agent
from langchain_anthropic.middleware import AnthropicPromptCachingMiddleware

from autobot.agent.middleware.budget import TokenBudgetMiddleware
from autobot.agent.middleware.prompt_injection_shield import PromptInjectionShieldMiddleware
from autobot.agent.middleware.untrusted_output import UntrustedOutputMiddleware
from autobot.agent.models import build_model
from autobot.agent.tools.blue_sensor import (
    blue_sensor_body,
    blue_sensor_events,
    blue_sensor_scan,
    blue_sensor_search,
    blue_sensor_timeline,
)

_ROLE = "blue_cell"
_RECURSION_LIMIT = 120

_STANDARD_TOOLS: list[Any] = [
    blue_sensor_scan,
    blue_sensor_events,
    blue_sensor_search,
    blue_sensor_timeline,
    blue_sensor_body,
]


def load_system_prompt() -> str:
    """Load the blue_cell system prompt from the packaged prompts dir."""
    resource = resources.files("autobot.agent").joinpath("prompts/blue_cell.md")
    return resource.read_text(encoding="utf-8")


def default_tools() -> list[Any]:
    """The five read-only sensor tools (structural read-only guarantee)."""
    return list(_STANDARD_TOOLS)


def default_middleware(model: Any) -> list[Any]:
    """The design's canonical middleware order (agent-runtime design §middleware)."""
    return [
        UntrustedOutputMiddleware(),
        PromptInjectionShieldMiddleware(append_policy_to_system=False),
        TokenBudgetMiddleware(),
        # blue_cell has no sandbox: summaries land in graph state, not on
        # a filesystem (the deepagents StateBackend is the in-memory one).
        create_summarization_middleware(model=model, backend=StateBackend()),
        AnthropicPromptCachingMiddleware(),
        PatchToolCallsMiddleware(),
    ]


def create_blue_cell_agent(
    *,
    model: Any = None,
    tools: list[Any] | None = None,
    middleware: list[Any] | None = None,
    system_prompt: str | None = None,
    recursion_limit: int | None = None,
):
    """Build the sensor-grounded defensive agent with read-only tools.

    Every dependency is injectable for testing; defaults assemble AutoBot's
    own runtime.
    """
    if model is None:
        model = build_model()
    if tools is None:
        tools = default_tools()
    if system_prompt is None:
        system_prompt = load_system_prompt()
    if middleware is None:
        middleware = default_middleware(model)
    return create_agent(
        model,
        system_prompt=system_prompt,
        tools=tools,
        middleware=middleware,
        name=_ROLE,
    ).with_config({"recursion_limit": recursion_limit or _RECURSION_LIMIT})


def graph():
    """LangGraph Platform export: called by the server at startup."""
    return create_blue_cell_agent()
