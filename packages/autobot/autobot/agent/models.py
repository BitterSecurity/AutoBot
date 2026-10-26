"""Thin model factory — two modes, sharing the operator's LLM configuration.

Decepticon's LLMFactory (1784 lines) routes every model through the LiteLLM
proxy gateway with a credentials inventory and multi-tenant virtual keys.
AutoBot does not duplicate that configuration:

1. **Shared-gateway mode (Decepticon co-deploy)** — when the Decepticon
   stack's LiteLLM proxy is reachable, the agent calls it (OpenAI-compatible
   ``/v1``) with the model the stack stamps for blue. Provider keys and model
   routing live in the proxy — the user's Decepticon LLM settings are reused,
   never configured twice.
2. **Standalone mode** — ``AUTOBOT_MODEL`` builds a ChatModel via langchain's
   ``init_chat_model`` (provider packages as optional extras; the LiteLLM-SDK
   construction was dropped because ``langchain-litellm`` transitively forces
   ``mcp>=2``, conflicting with the Decepticon MCP server's ``mcp<2`` pin).

Resolution order: shared gateway (if fully configured) → standalone
``AUTOBOT_MODEL`` → fail-closed with guidance covering both modes.

Gateway configuration (co-deployed with Decepticon):
    DECEPTICON_LLM__PROXY_URL     the stack's LiteLLM gateway (e.g.
                                  ``http://litellm:4000``)
    DECEPTICON_LLM__PROXY_API_KEY gateway bearer key (may be empty on
                                  internal networks)
    DECEPTICON_BLUE_MODEL         the model slug to route blue through
                                  (stamped by the stack / operator, in the
                                  proxy's provider-slug format)

Standalone configuration:
    AUTOBOT_MODEL             primary model, LiteLLM format. Required in
                              standalone mode.
    AUTOBOT_FALLBACK_MODELS   ordered fallback models, comma/space separated.
    AUTOBOT_TEMPERATURE       sampling temperature. Optional (provider default).
"""

from __future__ import annotations

import os
import re
from typing import Any

from langchain.chat_models import init_chat_model

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
    # langchain's universal constructor. The LiteLLM-style ``provider/model``
    # prefix is split: the provider selects the integration (whose package
    # must be installed — autobot[openai], autobot[anthropic], ...) and the
    # rest is the provider-native model name. Custom gateways (an Elice-served
    # model behind a LiteLLM proxy) go through the shared-gateway mode —
    # provider-agnostic.
    provider, _, name = model.partition("/")
    kwargs: dict[str, Any] = (
        {"model": name, "model_provider": provider} if name else {"model": model}
    )
    if temperature is not None:
        kwargs["temperature"] = temperature
    return init_chat_model(**kwargs)


_GATEWAY_PROXY_ENV = "DECEPTICON_LLM__PROXY_URL"
_GATEWAY_KEY_ENV = "DECEPTICON_LLM__PROXY_API_KEY"
_GATEWAY_MODEL_ENV = "DECEPTICON_BLUE_MODEL"


def _gateway_config() -> tuple[str, str, str] | None:
    """Return (proxy_url, key, model) when the shared gateway is configured."""
    proxy_url = os.environ.get(_GATEWAY_PROXY_ENV, "").strip()
    model = os.environ.get(_GATEWAY_MODEL_ENV, "").strip()
    if not (proxy_url and model):
        return None
    key = os.environ.get(_GATEWAY_KEY_ENV, "").strip()
    return proxy_url, key, model


def _build_gateway_chat(proxy_url: str, key: str, model: str) -> Any:
    from langchain_openai import ChatOpenAI

    # The LiteLLM proxy exposes the OpenAI-compatible /v1 API — the standard
    # client for an OpenAI-compatible gateway.
    return ChatOpenAI(
        model=model,
        base_url=f"{proxy_url.rstrip('/')}/v1",
        api_key=key or "internal-gateway-no-key",
    )


def build_model() -> Any:
    """Build the configured model with native provider fallbacks.

    Resolution: shared gateway (Decepticon co-deploy) → standalone
    ``AUTOBOT_MODEL`` → fail-closed with setup guidance covering both.
    """
    temperature = _temperature()
    gateway = _gateway_config()
    if gateway is not None:
        proxy_url, key, model = gateway
        return _build_gateway_chat(proxy_url, key, model)
    primary = _build_chat(_required_model(), temperature)
    fallbacks = [_build_chat(model, temperature) for model in _fallback_models()]
    if fallbacks:
        return primary.with_fallbacks(fallbacks)
    return primary


__all__ = ["build_model", "_fallback_models", "_required_model", "_temperature"]
