"""The AutoBot investigation agent — the graph export.

Adapted from the Decepticon in-tree prototype: same read-only
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
from autobot.agent.middleware.step_budget import StepBudgetMiddleware
from autobot.agent.middleware.untrusted_output import UntrustedOutputMiddleware
from autobot.agent.models import build_model
from autobot.agent.tools.blue_sensor import (  # noqa: F401 — re-exported for the spec
    blue_sensor_body,
    blue_sensor_events,
    blue_sensor_scan,
    blue_sensor_search,
    blue_sensor_timeline,
)
from decepticon_core.plugin_loader import SubAgentSpec

_ROLE = "autobot"
_RECURSION_LIMIT = 400

_STANDARD_TOOLS: list[Any] = [
    blue_sensor_scan,
    blue_sensor_events,
    blue_sensor_search,
    blue_sensor_timeline,
    blue_sensor_body,
]


def load_system_prompt() -> str:
    """Load the AutoBot system prompt from the packaged prompts dir."""
    resource = resources.files("autobot.agent").joinpath("prompts/autobot.md")
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
        # AutoBot has no sandbox: summaries land in graph state, not on
        # a filesystem (the deepagents StateBackend is the in-memory one).
        create_summarization_middleware(model=model, backend=StateBackend()),
        AnthropicPromptCachingMiddleware(),
        PatchToolCallsMiddleware(),
    ]


def create_autobot_agent(
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
        # StepBudgetMiddleware(total_steps) mirrors the with_config recursion
        # limit — the agent knows its budget and wraps up before the hard stop.
        middleware = [
            *default_middleware(model),
            StepBudgetMiddleware(total_steps=recursion_limit or _RECURSION_LIMIT),
        ]
    return create_agent(
        model,
        system_prompt=system_prompt,
        tools=tools,
        middleware=middleware,
        name=_ROLE,
    ).with_config({"recursion_limit": recursion_limit or _RECURSION_LIMIT})


# The red orchestrator dispatches AutoBot as a subagent (the purple loop):
# discovered via the ``decepticon.subagents`` entry-point declared in this
# package's metadata. parent_agents pins it to the ``decepticon`` main agent.
SUBAGENT_SPEC = SubAgentSpec(
    name="autobot",
    description=(
        "AutoBot — independent read-only defender. Investigates live local "
        "target telemetry and the always-on monitor's incidents, then reports "
        "evidence and uncertainty. No bash or containment tools."
    ),
    factory=create_autobot_agent,
    parent_agents=("decepticon",),
    bundle="standard",
    priority=90,
    # The purple loop dispatches AutoBot for bounded investigations — the
    # orchestrator hands out a tighter step budget than the standalone
    # server run (400) so a dispatched investigation converges.
    recursion_limit=200,
)


def __getattr__(name: str):
    # Module-level lazy graph attribute — the Decepticon graph registry's
    # ``decepticon.agents`` discovery contract requires a module-level
    # ``graph`` attribute ("module:graph"); PEP 562 defers the model env
    # read from import time to attribute resolution time.
    if name == "graph":
        return create_autobot_agent()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
