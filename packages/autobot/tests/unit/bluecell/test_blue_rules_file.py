from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MONITOR_PATH = Path(__file__).resolve().parents[5] / "examples" / "local-sensor" / "blue_monitor.py"


def load_monitor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, rules: str | None = None):
    monkeypatch.setenv("BLUE_MONITOR_DB", str(tmp_path / "module.sqlite3"))
    if rules is None:
        monkeypatch.delenv("BLUE_RULES_FILE", raising=False)
    else:
        rules_path = tmp_path / "rules.jsonl"
        rules_path.write_text(rules)
        monkeypatch.setenv("BLUE_RULES_FILE", str(rules_path))
    spec = importlib.util.spec_from_file_location("resident_blue_monitor", MONITOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def http_event(seq: int, uri: str = "/normal") -> dict:
    return {
        "seq": seq,
        "event_id": f"event-{seq}",
        "event_type": "http_access",
        "target_id": "local-web",
        "request_id": f"request-{seq}",
        "method": "GET",
        "uri": uri,
        "status": 200,
    }


SAMPLE_RULES = (
    '{"id": "traversal_rule", "title": "Traversal", "level": "high", '
    '"selections": {"on_uri": {"uri": "re:(?:\\\\.\\\\./|/etc/passwd)"}}, "condition": "on_uri"}\n'
    '{"id": "body_probe", "level": "medium", "match": {"request_body": "re:admin_login"}}\n'
    '{"id": "log_probe", "level": "low", "match": {"message": "re:segfault"}}\n'
)


def test_rule_file_loads_bootstrap_and_selection_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path, rules=SAMPLE_RULES)
    assert monitor.FILE_RULES is not None
    assert [rule.id for rule in monitor.FILE_RULES] == ["traversal_rule", "body_probe", "log_probe"]
    assert [rule.level for rule in monitor.FILE_RULES] == ["high", "medium", "low"]
    assert monitor.FILE_RULES[0].condition == "on_uri"
    assert monitor.FILE_RULES[1].condition == "match"


@pytest.mark.parametrize(
    "line",
    [
        "not json\n",
        '{"level": "high", "match": {"uri": "x"}}\n',
        '{"id": "bad_level", "level": "catastrophic", "match": {"uri": "x"}}\n',
        '{"id": "both", "match": {"uri": "x"}, "selections": {"s": {"uri": "x"}}}\n',
        '{"id": "bad_condition", "selections": {"s": {"uri": "x"}}, "condition": "s and other"}\n',
    ],
)
def test_invalid_rule_file_fails_loudly_at_startup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, line: str
) -> None:
    with pytest.raises(ValueError):
        load_monitor(monkeypatch, tmp_path, rules=line)


def test_file_rules_drive_detect_and_replace_builtins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path, rules=SAMPLE_RULES)
    traversal = monitor.detect(http_event(1, "/?file=../../../etc/passwd"))
    assert traversal == [("traversal_rule", "high", "uri")]
    encoded = monitor.detect(http_event(2, "/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"))
    assert [hit[0] for hit in encoded] == ["traversal_rule"]
    log_hit = monitor.detect(
        {"seq": 3, "event_id": "e3", "event_type": "process_log", "message": "segfault at ip"}
    )
    assert log_hit == [("log_probe", "low", "message")]
    assert monitor.detect(http_event(4, "/health")) == []
    assert monitor.detect_with_file_rules(http_event(5), "admin_login=1") == [
        ("body_probe", "medium", "request_body")
    ]


def test_builtin_rules_stay_default_without_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path)
    assert monitor.FILE_RULES is None
    hits = monitor.detect(http_event(1, "/?file=../../../etc/passwd"))
    assert [hit[0] for hit in hits] == ["path_traversal"]
    log_hit = monitor.detect(
        {"seq": 2, "event_id": "e2", "event_type": "process_log", "message": "segfault"}
    )
    assert log_hit == []


def test_watch_prompt_names_target_and_loaded_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path, rules=SAMPLE_RULES)
    prompt = monitor.watch_prompt(
        [http_event(7, "/page"), http_event(8, "/page")],
        [{"start_seq": 1, "end_seq": 2, "decision": "no_alert", "summary": "prior"}],
    )
    assert "You are defending target 'local-web'" in prompt
    assert (
        "Loaded detection rules: traversal_rule(high), body_probe(medium), log_probe(low)" in prompt
    )


def test_analysis_prompt_names_target_from_incident_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path, rules=SAMPLE_RULES)
    work = {
        "id": "incident-1",
        "rule_id": "traversal_rule",
        "severity": "high",
        "evidence": {"target_id": "shop-web", "uri": "/?file=../"},
    }
    prompt = monitor.analysis_prompt(work)
    assert "You are defending target 'shop-web'" in prompt
    assert "traversal_rule(high)" in prompt
    assert "shop-web" in json.dumps(work)  # incident payload still carries the evidence
