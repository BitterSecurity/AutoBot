from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from langgraph.constants import END
from langgraph.types import Command

from autobot.agent.middleware.budget import TokenBudgetMiddleware, _budget_tokens


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTOBOT_BUDGET_TOKENS", raising=False)


def _state(*token_totals: int) -> SimpleNamespace:
    messages = [
        AIMessage(
            content=f"m{i}",
            usage_metadata={"input_tokens": t // 2, "output_tokens": t - t // 2, "total_tokens": t},
        )
        for i, t in enumerate(token_totals, start=1)
    ]
    return SimpleNamespace(messages=messages)


def test_default_budget_is_400k(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _budget_tokens() == 400_000
    monkeypatch.setenv("AUTOBOT_BUDGET_TOKENS", "0")
    assert _budget_tokens() == 0  # 0 disables the cap


def test_garbage_budget_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOBOT_BUDGET_TOKENS", "many")
    with pytest.raises(ValueError, match="must be an integer"):
        _budget_tokens()


def test_under_cap_returns_none() -> None:
    mw = TokenBudgetMiddleware(cap_tokens=1000)
    assert mw.after_model(_state(300, 300), None) is None


def test_over_cap_terminates_with_note_and_end() -> None:
    mw = TokenBudgetMiddleware(cap_tokens=1000)
    result = mw.after_model(_state(600, 600), None)
    assert isinstance(result, Command)
    assert result.goto == END
    text = result.update["messages"][0].content
    assert "Token cap reached" in text
    assert "1,200" in text  # cumulative usage rendered


def test_cap_zero_disables_even_over_budget() -> None:
    mw = TokenBudgetMiddleware(cap_tokens=0)
    assert mw.after_model(_state(10_000_000), None) is None
