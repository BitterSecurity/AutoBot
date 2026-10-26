"""Thin model factory — LiteLLM SDK direct, no proxy gateway.

Decepticon's LLMFactory (1784 lines) routes every model through a LiteLLM
proxy service with a credentials inventory, model profiles and a multi-tenant
virtual-key layer. That is Decepticon's multi-agent/multi-tenant
infrastructure. AutoBot standalone needs one model (plus fallbacks) with
provider keys in the environment — so this factory constructs ChatModels
directly through the LiteLLM SDK via ``ChatLiteLLM``, and attaches provider
fallbacks natively with ``Runnable.with_fallbacks`` (no fallback middleware
needed).

Configuration (fail-closed):
    AUTOBOT_MODEL             primary model, LiteLLM format
                              (e.g. ``anthropic/claude-...``, ``openai/gpt-...``,
                              ``ollama/qwen...``). Required.
    AUTOBOT_FALLBACK_MODELS   ordered fallback models, comma/space separated.
                              Optional (empty = no fallbacks).
    AUTOBOT_TEMPERATURE       sampling temperature. Optional (provider default).

Provider keys go through the provider's standard environment variables
(``ANTHROPIC_API_KEY``, ``OPENAI_API_KEY``, ...) as handled by the LiteLLM SDK.
"""

from __future__ import annotations

import os
import re
from typing import Any

from langchain_litellm import ChatLiteLLM

_MODEL_ENV = "AUTOBOT_MODEL"
_FALLBACK_ENV = "AUTOBOT_FALLBACK_MODELS"
_TEMPERATURE_ENV = "AUTOBOT_TEMPERATURE"
_SPLIT_RE = re.compile(r"[,\s]+")


def _required_model() -> str:
    model = os.environ.get(_MODEL_ENV, "").strip()
    if not model:
        raise ValueError(
            f"{_MODEL_ENV} is required — set the primary model in LiteLLM "
            "format (e.g. anthropic/claude-sonnet-4, openai/gpt-4o, ollama/qwen2.5:14b)"
        )
    return model


def _fallback_models() -> list[str]:
    raw = os.environ.get(_FALLBACK_ENV, "").strip()
    if not raw:
        return []
    return [item for item in _SPLIT_RE.split(raw) if item]


def _temperature() -> float | None:
    raw = os.environ.get(_TEMPERATURE_ENV, "").strip()
    if not raw:
        return None
    value = float(raw)  # ValueError on garbage — fail loudly, not silently
    if not 0.0 <= value <= 2.0:
        raise ValueError(f"{_TEMPERATURE_ENV} must be within [0.0, 2.0], got {value}")
    return value


def _build_chat(model: str, temperature: float | None) -> Any:
    kwargs: dict[str, Any] = {"model": model}
    if temperature is not None:
        kwargs["temperature"] = temperature
    return ChatLiteLLM(**kwargs)


def build_model() -> Any:
    """Build the configured primary ChatModel with native provider fallbacks.

    Fail-closed: a missing ``AUTOBOT_MODEL`` raises with setup guidance;
    malformed ``AUTOBOT_TEMPERATURE`` raises rather than silently defaulting.
    """
    temperature = _temperature()
    primary = _build_chat(_required_model(), temperature)
    fallbacks = [_build_chat(model, temperature) for model in _fallback_models()]
    if fallbacks:
        return primary.with_fallbacks(fallbacks)
    return primary


__all__ = ["build_model", "_fallback_models", "_required_model", "_temperature"]
