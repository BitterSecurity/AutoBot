"""Resource-awareness middleware — the agent knows its step budget.

LangGraph enforces ``recursion_limit`` by raising GraphRecursionError at the
hard cap, which reads to the operator as "Recursion limit of N reached" and
discards the run's momentum. This middleware makes the budget visible to the
MODEL instead: near the cap it injects a wrap-up reminder, so the agent
consolidates and delivers its findings before exhausting the budget.

The step estimate approximates graph supersteps from the message count
(one model round ≈ one message per step in a linear ReAct loop). It is an
approximation by design — cheap, monotonic, and directionally correct; the
hard cap stays with the runtime.
"""

from __future__ import annotations

from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import SystemMessage
from typing_extensions import override


class StepBudgetMiddleware(AgentMiddleware):
    """Inject wrap-up guidance as the run approaches its step budget."""

    def __init__(self, *, total_steps: int, warn_at_pct: float = 0.8) -> None:
        super().__init__()
        if total_steps <= 0:
            raise ValueError("total_steps must be positive")
        self._total = total_steps
        self._warn_at = warn_at_pct

    @override
    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        messages = getattr(request, "state", {}).get("messages") or []
        steps = len(messages)
        if steps >= self._total:
            note = (
                f"[step budget] HARD STOP REACHED — {steps} of {self._total} steps. "
                "Do not call any more tools. Return your final answer now with the "
                "findings and uncertainty collected so far."
            )
            return handler(
                request.override(messages=[*request.messages, SystemMessage(content=note)])
            )
        if steps >= self._total * self._warn_at:
            note = (
                f"[step budget] {steps} of {self._total} steps used — approaching the "
                "hard stop. Conclude the current line of work and move to delivering "
                "your result."
            )
            return handler(
                request.override(messages=[*request.messages, SystemMessage(content=note)])
            )
        return handler(request)
