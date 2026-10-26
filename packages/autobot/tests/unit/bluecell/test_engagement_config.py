from __future__ import annotations

import json
from pathlib import Path

import pytest

from autobot.bluecell.engagement_config import (
    blue_workspace,
    compose_env,
    config_path,
    load_blue_config,
    materialize_blue_config,
    resolve_target,
    validate_blue_config,
)


def valid_config(rules_file: str | None = None) -> dict:
    config: dict = {
        "version": 1,
        "targets": [{"id": "shop-web", "upstream": "127.0.0.1:3000", "enabled": True}],
    }
    if rules_file:
        config["rules_file"] = rules_file
    return config


@pytest.fixture(autouse=True)
def blue_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    # DECEPTICON_BLUE_WORKSPACE replaces the whole workspace path (same
    # override semantics as DECEPTICON_ENGAGEMENT_WORKSPACE), so the fixture
    # directory IS the Blue workspace: blue.json sits directly inside it.
    monkeypatch.setenv("DECEPTICON_BLUE_WORKSPACE", str(tmp_path / "blue-root"))
    return tmp_path / "blue-root"


def write_rules(blue_root: Path, content: str) -> None:
    blue_root.mkdir(parents=True, exist_ok=True)
    (blue_root / "web-rules.jsonl").write_text(content)


def test_blue_workspace_rejects_invalid_label(blue_root: Path) -> None:
    for label in ("../etc", "", "a/b", "/abs"):
        with pytest.raises(ValueError):
            blue_workspace(label)


def test_materialize_writes_normalized_config_and_never_overwrites(blue_root: Path) -> None:
    destination = materialize_blue_config("shop", valid_config())
    assert destination == blue_root / "blue.json"
    written = json.loads(destination.read_text())
    # upstream normalized to an origin with scheme
    assert written["targets"][0]["upstream"] == "http://127.0.0.1:3000"
    # a second create with different content must not overwrite the reviewed file
    changed = valid_config()
    changed["targets"][0]["upstream"] = "http://127.0.0.1:9999"
    assert materialize_blue_config("shop", changed) == destination
    assert json.loads(destination.read_text())["targets"][0]["upstream"] == "http://127.0.0.1:3000"


def test_materialize_rejects_symlink_destination(blue_root: Path) -> None:
    destination = config_path("shop")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to("/etc/hostname")
    with pytest.raises(ValueError):
        materialize_blue_config("shop", valid_config())


def test_invalid_rules_file_fails_creation(blue_root: Path) -> None:
    write_rules(blue_root, '{"id": "x", "level": "catastrophic", "match": {"uri": "y"}}\n')
    with pytest.raises(ValueError):
        materialize_blue_config("shop", valid_config(rules_file="web-rules.jsonl"))
    assert not config_path("shop").exists()


def test_unknown_condition_selection_fails_creation(blue_root: Path) -> None:
    write_rules(
        blue_root, '{"id": "r", "selections": {"s": {"uri": "x"}}, "condition": "s and other"}\n'
    )
    with pytest.raises(ValueError):
        materialize_blue_config("shop", valid_config(rules_file="web-rules.jsonl"))


def test_missing_rules_file_fails_creation(blue_root: Path) -> None:
    with pytest.raises(ValueError):
        materialize_blue_config("shop", valid_config(rules_file="web-rules.jsonl"))


def test_rules_file_must_stay_inside_blue_workspace(blue_root: Path) -> None:
    with pytest.raises(ValueError):
        validate_blue_config(valid_config(rules_file="../../etc/passwd"), root=blue_root)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda c: c.update(version=2), "version"),
        (lambda c: c.update(targets=[]), "non-empty"),
        (lambda c: c["targets"].append(dict(c["targets"][0], id="shop-web")), "duplicate"),
        (lambda c: c["targets"].append(dict(c["targets"][0], id="second")), "exactly one enabled"),
        (lambda c: c["targets"][0].update(upstream="http://10.0.0.5:80"), "local service"),
        (lambda c: c["targets"][0].update(upstream="http://127.0.0.1"), "explicit port"),
        (lambda c: c["targets"][0].update(upstream="http://127.0.0.1:3000/app"), "bare origin"),
        (lambda c: c["targets"][0].update(logs=["relative/dir"]), "absolute host paths"),
        (lambda c: c["targets"][0].update(enabled="yes"), "boolean"),
        (lambda c: c.update(rules_file="."), "existing jsonl file"),
        (lambda c: c.update(watch={"interval_seconds": -1}), "positive"),
        (lambda c: c.update(unknown_key=1), "unknown keys"),
    ],
)
def test_validation_failures_are_precise(blue_root: Path, mutate, message: str) -> None:
    config = valid_config()
    mutate(config)
    with pytest.raises(ValueError, match=message):
        validate_blue_config(config, root=blue_root)


def test_upstream_normalizes_all_localhost_forms(blue_root: Path) -> None:
    for raw, origin in (
        ("localhost:3000", "http://localhost:3000"),
        ("[::1]:3000", "http://[::1]:3000"),
        ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
    ):
        config = valid_config()
        config["targets"][0]["upstream"] = raw
        validate_blue_config(config, root=blue_root)
        assert config["targets"][0]["upstream"] == origin


def test_load_and_resolve_target_roundtrip(blue_root: Path) -> None:
    materialize_blue_config("shop", valid_config())
    config, destination = load_blue_config("shop")
    assert destination == config_path("shop")
    assert resolve_target(config)["id"] == "shop-web"
    with pytest.raises(ValueError, match="not found"):
        resolve_target(config, "other")


def test_load_fails_closed_on_hand_broken_file(blue_root: Path) -> None:
    blue_root.mkdir(parents=True, exist_ok=True)
    config_path("shop").write_text('{"version": 1, "targets": []}')
    with pytest.raises(ValueError):
        load_blue_config("shop")


def test_compose_env_maps_target_rules_and_watch(blue_root: Path) -> None:
    write_rules(blue_root, '{"id": "r", "match": {"uri": "x"}}\n')
    config = valid_config(rules_file="web-rules.jsonl")
    config["watch"] = {"interval_seconds": 5, "batch_size": 10}
    config["targets"][0]["logs"] = ["/var/log/target"]
    validate_blue_config(config, root=blue_root)
    env = compose_env(config, resolve_target(config), blue_root)
    assert env["BLUE_TARGET_UPSTREAM"] == "http://127.0.0.1:3000"
    assert env["BLUE_TARGET_ID"] == "shop-web"
    assert env["BLUE_TARGET_LOG_DIR"] == "/var/log/target"
    assert env["BLUE_RULES_FILE"] == "/blue-engagement/web-rules.jsonl"
    assert env["BLUE_ENGAGEMENT_DIR"] == str(blue_root)
    assert env["BLUE_WATCH_INTERVAL_SECONDS"] == "5"
    assert env["BLUE_WATCH_BATCH_SIZE"] == "10"


def test_ad_hoc_workspace_without_override_resolves_under_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DECEPTICON_BLUE_WORKSPACE", raising=False)
    workspace = blue_workspace("eng1")
    assert workspace == Path.home() / ".decepticon" / "blue" / "eng1"
