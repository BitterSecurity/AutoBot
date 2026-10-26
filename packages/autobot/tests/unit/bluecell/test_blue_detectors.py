from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MONITOR_PATH = Path(__file__).resolve().parents[5] / "examples" / "local-sensor" / "blue_monitor.py"


def load_monitor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **env: str):
    monkeypatch.setenv("BLUE_MONITOR_DB", str(tmp_path / "module.sqlite3"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    spec = importlib.util.spec_from_file_location("resident_blue_monitor", MONITOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def event(seq: int, uri: str = "/normal") -> dict:
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


def test_same_rule_within_window_collapses_into_one_incident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path, BLUE_AGENT_URL="http://mock-agent")
    store = monitor.MonitorStore(tmp_path / "dedup.sqlite3")
    hits = [("path_traversal", "high", "uri")]
    store.record_event(event(1, "/?file=../etc/passwd"), hits)
    store.record_event(event(2, "/?file=../etc/passwd"), hits)
    store.record_event(event(3, "/?file=../etc/passwd"), hits)
    incidents = store.incidents()
    assert len(incidents) == 1
    assert incidents[0]["evidence"]["hits"] == 3
    notices = store.notifications(0, 10)["notifications"]
    assert [notice["kind"] for notice in notices] == ["detected"]
    assert store.pending_watch_seqs(25) == [1, 2, 3]
    store.db.close()


def test_different_rules_and_zero_window_stay_separate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(monkeypatch, tmp_path)
    store = monitor.MonitorStore(tmp_path / "dedup2.sqlite3")
    store.record_event(event(1, "/?file=../etc/passwd"), [("path_traversal", "high", "uri")])
    store.record_event(event(2, "/?q=1' or '1'='1"), [("sql_injection", "high", "uri")])
    assert len(store.incidents()) == 2
    store.db.close()

    store2 = monitor.MonitorStore(tmp_path / "dedup3.sqlite3")
    monkeypatch.setattr(monitor, "DEDUP_WINDOW_SECONDS", 0.0)
    hits = [("path_traversal", "high", "uri")]
    store2.record_event(event(1, "/?file=../etc/passwd"), hits)
    store2.record_event(event(2, "/?file=../etc/passwd"), hits)
    assert len(store2.incidents()) == 2
    store2.db.close()


def test_decision_detector_requires_agent_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="requires BLUE_AGENT_URL"):
        load_monitor(monkeypatch, tmp_path, BLUE_DETECTOR="decision")


def test_unknown_detector_kind_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="must be 'rules' or 'decision'"):
        load_monitor(monkeypatch, tmp_path, BLUE_DETECTOR="vibes")


def decision_agent_result(verdicts: list[dict]) -> dict:
    return {"messages": [{"type": "ai", "content": json.dumps(verdicts)}]}


def test_decision_page_classification_and_incidents(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(
        monkeypatch, tmp_path, BLUE_DETECTOR="decision", BLUE_AGENT_URL="http://mock-agent"
    )
    events = [
        event(1, "/?file=../../../etc/passwd"),
        event(2, "/health"),
        event(3, "/?id=1+union+select"),
    ]
    captured = {}

    def fake_post_json(url: str, payload: dict, timeout: float = 10) -> dict:
        captured["url"] = url
        captured["prompt"] = payload["input"]["messages"][0]["content"]
        return decision_agent_result(
            [
                {
                    "seq": 1,
                    "classification": "attack",
                    "severity": "high",
                    "rationale": "traversal",
                },
                {"seq": 2, "classification": "benign", "severity": "low", "rationale": "health"},
                {
                    "seq": 3,
                    "classification": "suspicious",
                    "severity": "medium",
                    "rationale": "sqli",
                },
            ]
        )

    monkeypatch.setattr(monitor, "post_json", fake_post_json)
    hits = monitor.detect_page(events)
    assert captured["url"] == "http://mock-agent/runs/wait"
    assert "untrusted data" in captured["prompt"]
    assert hits[1] == [("decision_attack", "high", "decision_model:traversal")]
    assert hits[3] == [("decision_suspicious", "medium", "decision_model:sqli")]
    assert 2 not in hits  # benign events produce no incident

    store = monitor.MonitorStore(tmp_path / "decision.sqlite3")
    store.record_event(events[0], hits[1])
    store.record_event(events[2], hits[3])
    incidents = store.incidents()
    assert sorted(incident["rule_id"] for incident in incidents) == [
        "decision_attack",
        "decision_suspicious",
    ]
    assert incidents[0]["analysis_state"] == "pending"
    store.db.close()


def test_decision_verdicts_are_dropped_individually(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(
        monkeypatch, tmp_path, BLUE_DETECTOR="decision", BLUE_AGENT_URL="http://mock-agent"
    )
    events = [event(seq) for seq in (1, 2, 3, 4, 5)]
    verdicts = [
        {"seq": 1, "classification": "attack", "severity": "high", "rationale": "ok"},
        {"seq": 99, "classification": "attack", "severity": "high", "rationale": "unknown seq"},
        {"seq": 2, "classification": "exploit", "severity": "high", "rationale": "bad enum"},
        {
            "seq": 3,
            "classification": "attack",
            "severity": "catastrophic",
            "rationale": "bad level",
        },
        {"seq": 4, "classification": "suspicious", "severity": "high", "rationale": "ok"},
        "not-a-dict",
        {"seq": 5, "classification": "benign", "severity": "low", "rationale": "skip"},
    ]

    def fake_post_json(url: str, payload: dict, timeout: float = 10) -> dict:
        return decision_agent_result(verdicts)

    monkeypatch.setattr(monitor, "post_json", fake_post_json)
    hits = monitor.detect_page(events)
    assert set(hits) == {1, 4}
    assert hits[4][0][0] == "decision_suspicious"


def test_decision_non_array_response_fails_the_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(
        monkeypatch, tmp_path, BLUE_DETECTOR="decision", BLUE_AGENT_URL="http://mock-agent"
    )

    def fake_post_json(url: str, payload: dict, timeout: float = 10) -> dict:
        return {
            "messages": [{"type": "ai", "content": "I looked at the events and saw nothing bad."}]
        }

    monkeypatch.setattr(monitor, "post_json", fake_post_json)
    with pytest.raises(ValueError, match="unparseable"):
        monitor.detect_page([event(1)])


def test_decision_code_fenced_response_is_parsed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monitor = load_monitor(
        monkeypatch, tmp_path, BLUE_DETECTOR="decision", BLUE_AGENT_URL="http://mock-agent"
    )
    fenced = (
        "```json\n"
        '[{"seq": 1, "classification": "attack", "severity": "critical", "rationale": "jndi"}]\n'
        "```"
    )

    def fake_post_json(url: str, payload: dict, timeout: float = 10) -> dict:
        return {"messages": [{"type": "ai", "content": fenced}]}

    monkeypatch.setattr(monitor, "post_json", fake_post_json)
    hits = monitor.detect_page([event(1, "/?x=${jndi:ldap}")])
    assert hits[1] == [("decision_attack", "critical", "decision_model:jndi")]
