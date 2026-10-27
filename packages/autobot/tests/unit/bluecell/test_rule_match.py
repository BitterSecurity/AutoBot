"""Behavioral + caching tests for the Blue Cell rule matcher.

These pin the match semantics (so the precompile refactor is provably
behavior-preserving) and assert the per-event hot path no longer recompiles
patterns or reparses conditions.
"""

from __future__ import annotations

from autobot.bluecell import rule_match as rm
from autobot.bluecell.rule_match import (
    DetectionRule,
    RuleMatcher,
    _compile_pattern,
    _evaluate_condition,
)


def _rule(rid: str, selections: dict, condition: str) -> DetectionRule:
    return DetectionRule(id=rid, title=rid, selections=selections, condition=condition)


# ── match semantics ──────────────────────────────────────────────────────────


def test_single_selection_substring_match() -> None:
    rule = _rule("r1", {"selection": {"actor.command_line": "GetUserSPNs"}}, "selection")
    m = RuleMatcher([rule])
    hits = m.match({"actor": {"command_line": "GetUserSPNs -request"}}, now_ts=1.0)
    assert [h.rule.id for h in hits] == ["r1"]
    assert hits[0].matched_fields == {"selection.actor.command_line": "GetUserSPNs"}


def test_no_match_returns_empty() -> None:
    rule = _rule("r1", {"selection": {"actor.command_line": "GetUserSPNs"}}, "selection")
    assert RuleMatcher([rule]).match({"actor": {"command_line": "ls -la"}}, now_ts=1.0) == []


def test_regex_pattern_and_and_condition() -> None:
    rule = _rule(
        "dcsync",
        {
            "tool": {"actor.command_line": "secretsdump"},
            "flag": {"actor.command_line": "re:-just-dc(?:-ntlm)?"},
        },
        "tool and flag",
    )
    m = RuleMatcher([rule])
    assert [h.rule.id for h in m.match({"actor": {"command_line": "secretsdump -just-dc-ntlm x"}}, now_ts=1.0)] == ["dcsync"]
    # tool matches but flag (regex) does not → condition fails.
    assert m.match({"actor": {"command_line": "secretsdump -help"}}, now_ts=1.0) == []


def test_or_not_and_parentheses_conditions() -> None:
    sels = {"a": {"f": "x"}, "b": {"f": "y"}}
    assert RuleMatcher([_rule("r", sels, "a or b")]).match({"f": "x"}, now_ts=1.0)
    assert RuleMatcher([_rule("r", sels, "a and not b")]).match({"f": "x"}, now_ts=1.0)
    assert RuleMatcher([_rule("r", sels, "a and not b")]).match({"f": "xy"}, now_ts=1.0) == []
    # value "xy" matches both a (x) and b (y); (a or b) and not(a and b) → False.
    assert RuleMatcher([_rule("r", sels, "(a or b) and not (a and b)")]).match({"f": "xy"}, now_ts=1.0) == []
    assert RuleMatcher([_rule("r", sels, "(a or b) and not (a and b)")]).match({"f": "x"}, now_ts=1.0)


def test_empty_condition_requires_all_selections() -> None:
    rule = _rule("r", {"a": {"f": "x"}, "b": {"g": "y"}}, "")
    m = RuleMatcher([rule])
    assert m.match({"f": "x", "g": "y"}, now_ts=1.0)  # both match
    assert m.match({"f": "x"}, now_ts=1.0) == []  # only one matches


def test_unknown_selection_name_never_fires() -> None:
    rule = _rule("r", {"a": {"f": "x"}}, "a and missing")
    assert RuleMatcher([rule]).match({"f": "x"}, now_ts=1.0) == []


def test_evaluate_condition_wrapper_preserves_semantics() -> None:
    assert _evaluate_condition("a and b", {"a": True, "b": True}) is True
    assert _evaluate_condition("a and b", {"a": True, "b": False}) is False
    assert _evaluate_condition("a or b", {"a": False, "b": True}) is True
    assert _evaluate_condition("not a", {"a": False}) is True
    assert _evaluate_condition("", {"a": True, "b": True}) is True
    assert _evaluate_condition("", {}) is False
    assert _evaluate_condition("a and nope", {"a": True}) is False


# ── caching / no per-event recompilation ─────────────────────────────────────


def test_compile_pattern_is_memoized() -> None:
    # Same raw string → identical cached Pattern object (proves no per-call recompile).
    assert _compile_pattern("re:-just-dc") is _compile_pattern("re:-just-dc")
    assert _compile_pattern("GetUserSPNs") is _compile_pattern("GetUserSPNs")


def test_match_does_not_recompile_in_hot_loop(monkeypatch) -> None:
    rule = _rule("r", {"a": {"f": "GetUserSPNs"}}, "a")
    m = RuleMatcher([rule])  # compilation happens here, once

    calls = {"n": 0}
    real = rm._compile_pattern

    def counting(raw: str):
        calls["n"] += 1
        return real(raw)

    monkeypatch.setattr(rm, "_compile_pattern", counting)
    for _ in range(50):
        m.match({"f": "GetUserSPNs -request"}, now_ts=1.0)
    assert calls["n"] == 0, "match() must not compile patterns in the per-event path"


def test_sample_rules_load_and_match() -> None:
    from pathlib import Path

    sample = Path(rm.__file__).with_name("sample_rules.jsonl")
    rules = rm.load_rules(sample)
    assert rules, "sample_rules.jsonl should load"
    m = RuleMatcher(rules)
    hits = m.match({"actor": {"command_line": "GetUserSPNs -request"}}, now_ts=1.0)
    assert any(h.rule.id == "DCEP-T1558.003-kerberoast" for h in hits)
