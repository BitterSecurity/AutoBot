from __future__ import annotations

import pytest

from autobot.agent.models import _gateway_config, build_model


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "AUTOBOT_MODEL",
        "AUTOBOT_FALLBACK_MODELS",
        "AUTOBOT_TEMPERATURE",
        "DECEPTICON_LLM__PROXY_URL",
        "DECEPTICON_LLM__PROXY_API_KEY",
        "DECEPTICON_BLUE_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)


def test_gateway_mode_takes_priority_over_standalone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECEPTICON_LLM__PROXY_URL", "http://litellm:4000")
    monkeypatch.setenv("DECEPTICON_BLUE_MODEL", "anthropic/claude-sonnet-5-5")
    monkeypatch.setenv("AUTOBOT_MODEL", "openai/gpt-4o")  # standalone would win if gateway ignored
    model = build_model()
    # ChatOpenAI against the gateway's OpenAI-compatible /v1 endpoint
    assert type(model).__name__ == "ChatOpenAI"
    assert "litellm:4000" in str(model.openai_api_base)


def test_gateway_without_key_builds_with_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECEPTICON_LLM__PROXY_URL", "http://litellm:4000")
    monkeypatch.setenv("DECEPTICON_BLUE_MODEL", "anthropic/claude-sonnet-5-5")
    model = build_model()
    assert type(model).__name__ == "ChatOpenAI"


def test_incomplete_gateway_falls_through_to_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # proxy URL without the blue model → gateway incomplete → not used
    monkeypatch.setenv("DECEPTICON_LLM__PROXY_URL", "http://litellm:4000")
    with pytest.raises(ValueError, match="AUTOBOT_MODEL is required"):
        build_model()


def test_gateway_config_requires_both_url_and_model(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _gateway_config() is None
    import os

    os.environ["DECEPTICON_LLM__PROXY_URL"] = "http://litellm:4000"
    assert _gateway_config() is None  # model missing
    os.environ["DECEPTICON_BLUE_MODEL"] = "anthropic/claude-sonnet-5-5"
    cfg = _gateway_config()
    assert (
        cfg is not None
        and cfg[0] == "http://litellm:4000"
        and cfg[2] == "anthropic/claude-sonnet-5-5"
    )
