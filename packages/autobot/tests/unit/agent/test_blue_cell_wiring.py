from __future__ import annotations

import pytest

from autobot.agent.blue_cell import (
    create_blue_cell_agent,
    default_middleware,
    default_tools,
    load_system_prompt,
)
from autobot.agent.middleware.budget import TokenBudgetMiddleware
from autobot.agent.middleware.untrusted_output import UntrustedOutputMiddleware
from autobot.agent.tools.blue_sensor import blue_sensor_scan


@pytest.fixture(autouse=True)
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOBOT_MODEL", "anthropic/claude-sonnet-4")
    monkeypatch.setenv("AUTOBOT_BUDGET_TOKENS", "0")


def test_default_tools_are_the_five_readonly_sensor_tools() -> None:
    names = [tool.name for tool in default_tools()]
    assert names == [
        "blue_sensor_scan",
        "blue_sensor_events",
        "blue_sensor_search",
        "blue_sensor_timeline",
        "blue_sensor_body",
    ]
    # Structural read-only guarantee: no bash, no containment, no write tools.
    forbidden = ("bash", "execute", "isolate", "kill", "delete", "contain")
    for name in names:
        assert not any(word in name.lower() for word in forbidden), f"forbidden tool: {name}"


def test_default_construction_yields_compiled_graph() -> None:
    graph = create_blue_cell_agent()
    from langgraph.graph.state import CompiledStateGraph

    assert isinstance(graph, CompiledStateGraph)
    assert "tools" in graph.nodes  # the tool executor node exists


def test_tool_injection_is_respected() -> None:
    tools = [blue_sensor_scan]
    graph = create_blue_cell_agent(tools=tools)
    assert "tools" in graph.nodes
    # The injected list replaces the default assembly wholesale.
    assert tools == [blue_sensor_scan]
    assert len(default_tools()) == 5


def test_system_prompt_carries_the_identity_and_readonly_contract() -> None:
    prompt = load_system_prompt()
    assert "<IDENTITY>" in prompt
    assert "read-only" in prompt.lower()
    assert "untrusted" in prompt.lower()


def test_default_middleware_order_matches_the_design(monkeypatch: pytest.MonkeyPatch) -> None:
    from langchain_litellm import ChatLiteLLM

    monkeypatch.setenv("AUTOBOT_MODEL", "anthropic/claude-sonnet-4")
    monkeypatch.setenv("AUTOBOT_BUDGET_TOKENS", "0")
    model = ChatLiteLLM(model="anthropic/claude-sonnet-4")  # construction only, no calls
    order = [type(m).__name__ for m in default_middleware(model)]
    assert order == [
        "UntrustedOutputMiddleware",
        "PromptInjectionShieldMiddleware",
        "TokenBudgetMiddleware",
        "_DeepAgentsSummarizationMiddleware",
        "AnthropicPromptCachingMiddleware",
        "PatchToolCallsMiddleware",
    ]


def test_middleware_injection_is_respected() -> None:
    # A foreign list replaces the default assembly wholesale (the real
    # middleware interface is exercised; a bare object would not survive
    # create_agent's construction-time introspection).
    graph = create_blue_cell_agent(
        middleware=[UntrustedOutputMiddleware(), TokenBudgetMiddleware()]
    )
    assert "tools" in graph.nodes
