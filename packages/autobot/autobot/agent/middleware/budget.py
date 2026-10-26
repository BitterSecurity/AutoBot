"""Thin per-run token budget — AutoBot's own implementation.

Decepticon's BudgetEnforcementMiddleware (450 lines) enforces engagement USD
caps through the LiteLLM proxy ``/spend/tags`` API with pause/resume
semantics. AutoBot v1 has no proxy and no engagement budgeting — it needs a
hard token ceiling per run so a runaway investigation cannot burn unbounded
tokens (the design doc's BUDGET slot, thin form).

Behavior: after every model call, sum the ``usage_metadata`` tokens across
all messages in state; when the cumulative total exceeds ``AUTOBOT_BUDGET_TOKENS``
(default 400,000), the run terminates with an explicit budget-exhausted
assistant note (a `Command` jump to END, not a raised exception — the
conversation stays inspectable). Set the env to ``0`` to disable.
"""

from __future__ import annotations

import os
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage
from langgraph.constants import END
from langgraph.types import Command
from typing_extensions import override

_BUDGET_ENV = "AUTOBOT_BUDGET_TOKENS"
_DEFAULT_BUDGET = 400_000


def _budget_tokens() -> int:
    raw = os.environ.get(_BUDGET_ENV, "").strip()
    if not raw:
        return _DEFAULT_BUDGET
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{_BUDGET_ENV} must be an integer: {error}") from error
    if value < 0:
        raise ValueError(f"{_BUDGET_ENV} must be >= 0 (0 disables the cap)")
    return value


def _usage_tokens(message: AIMessage) -> int:
    usage = getattr(message, "usage_metadata", None)
    if not usage:
        return 0
    return int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))


class TokenBudgetMiddleware(AgentMiddleware):
    """Terminate the run when cumulative token usage exceeds the cap."""

    def __init__(self, *, cap_tokens: int | None = None) -> None:
        super().__init__()
        self._cap_override = cap_tokens

    @override
    def after_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        cap = self._cap_override if self._cap_override is not None else _budget_tokens()
        if cap <= 0:
            return None
        messages = state.get("messages", []) if isinstance(state, dict) else state.messages
        total = sum(
            _usage_tokens(message) for message in messages if isinstance(message, AIMessage)
        )
        if total < cap:
            return None
        note = (
            f"[AutoBot budget] Token cap reached ({total:,} >= {cap:,} tokens, "
            f"AUTOBOT_BUDGET_TOKENS). The run stopped here; findings so far stand "
            f"as reported. Raise AUTOBOT_BUDGET_TOKENS or run focused follow-ups."
        )
        return Command(goto=END, update={"messages": [AIMessage(content=note)]})


__all__ = ["TokenBudgetMiddleware", "_budget_tokens", "_usage_tokens"]
