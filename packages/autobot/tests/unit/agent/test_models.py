from __future__ import annotations

import pytest

from autobot.agent.models import _fallback_models, _temperature, build_model


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("AUTOBOT_MODEL", "AUTOBOT_FALLBACK_MODELS", "AUTOBOT_TEMPERATURE"):
        monkeypatch.delenv(key, raising=False)


def test_missing_model_fails_closed_with_guidance() -> None:
    with pytest.raises(ValueError, match="AUTOBOT_MODEL is required"):
        build_model()


def test_primary_only_builds_chatlitellm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOBOT_MODEL", "anthropic/claude-sonnet-4")
    model = build_model()
    assert type(model).__name__ == "ChatLiteLLM"


def test_fallback_models_parse_from_commas_and_spaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "AUTOBOT_FALLBACK_MODELS", "openai/gpt-4o,  ollama/qwen2.5:14b\tgemini/gemini-2"
    )
    assert _fallback_models() == ["openai/gpt-4o", "ollama/qwen2.5:14b", "gemini/gemini-2"]


def test_fallbacks_attach_natively(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOBOT_MODEL", "anthropic/claude-sonnet-4")
    monkeypatch.setenv("AUTOBOT_FALLBACK_MODELS", "openai/gpt-4o")
    model = build_model()
    from langchain_core.runnables import RunnableWithFallbacks

    assert isinstance(model, RunnableWithFallbacks)


def test_temperature_out_of_range_fails_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOBOT_TEMPERATURE", "3.5")
    with pytest.raises(ValueError, match="must be within"):
        _temperature()


def test_temperature_unset_is_provider_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _temperature() is None
    monkeypatch.setenv("AUTOBOT_TEMPERATURE", "0.2")
    assert _temperature() == 0.2
