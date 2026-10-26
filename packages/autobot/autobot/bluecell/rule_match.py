"""Detection rule matcher for the Blue Cell agent.

Minimal viable Sigma-flavored rule engine. Accepts:

  - A dict shape (the OSS bootstrap format) where each rule is
    ``{id, title, level, mitre, match: {field: regex_or_substring}}``.
  - A subset of Sigma YAML's ``detection`` block: ``selection_*:``
    field-to-value maps + a ``condition: selection_1 and not
    selection_2`` boolean over those.

Loading a real Sigma rule via ``pysigma`` is out of scope for the OSS
package - operators that want it can install ``pysigma`` and pass
their rules through a converter. The contract this matcher honors is
the same: input event dict → list of (rule_id, matched_fields).

MTTD scoring: ``score_mttd(red_event_ts, blue_match_ts)`` returns the
delta in seconds; the Blue Cell agent persists this on the
``DetectionFired`` node.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """A loaded detection rule.

    ``selections`` is a dict of selection-name → field-pattern dict.
    A field pattern's value is treated as a substring match by default;
    if it starts with ``re:`` the remainder is compiled as a regex.

    ``condition`` is a boolean expression over selection names. The
    only operators understood are ``and``, ``or``, ``not``, and
    parentheses. ``and selection_x`` chains evaluate left-to-right
    (Python eval semantics, with selections substituted as booleans).
    """

    id: str
    title: str
    level: str = "medium"
    mitre: tuple[str, ...] = field(default_factory=tuple)
    selections: dict[str, dict[str, str]] = field(default_factory=dict)
    condition: str = ""


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    """A rule fired against a tap event."""

    rule: DetectionRule
    matched_fields: dict[str, str]
    event_ts: float
    detection_ts: float

    @property
    def mttd_seconds(self) -> float:
        return max(0.0, self.detection_ts - self.event_ts)


def _compile_pattern(raw: str) -> re.Pattern[str]:
    if raw.startswith("re:"):
        return re.compile(raw[3:], re.IGNORECASE)
    return re.compile(re.escape(raw), re.IGNORECASE)


def _event_field(event: dict[str, Any], dotted: str) -> str:
    cur: Any = event
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
    if cur is None:
        return ""
    if isinstance(cur, list):
        return " ".join(str(x) for x in cur)
    return str(cur)


def _selection_matches(
    selection: dict[str, str], event: dict[str, Any]
) -> tuple[bool, dict[str, str]]:
    matched: dict[str, str] = {}
    for field_name, raw_pattern in selection.items():
        pattern = _compile_pattern(raw_pattern)
        value = _event_field(event, field_name)
        m = pattern.search(value)
        if not m:
            return False, {}
        matched[field_name] = m.group(0)
    return True, matched


def _evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    """Boolean evaluation of a selection-name condition.

    Handles ``and``, ``or``, ``not``, parentheses. Unknown selection
    names evaluate to ``False`` (the rule was misauthored).
    """
    if not condition.strip():
        return all(selection_results.values()) if selection_results else False
    tokens = condition.split()
    eval_expr_parts: list[str] = []
    for token in tokens:
        token_clean = token.strip("()")
        if token_clean.lower() in {"and", "or", "not"} and token_clean == token:
            eval_expr_parts.append(token_clean.lower())
        elif token in {"(", ")"}:
            eval_expr_parts.append(token)
        elif token_clean in selection_results:
            wrapped = token.replace(token_clean, str(selection_results[token_clean]))
            eval_expr_parts.append(wrapped)
        else:
            return False
    expr = " ".join(eval_expr_parts)
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))  # nosec B307 - sandboxed: empty __builtins__ + empty locals, only ``True``/``False``/``and``/``or``/``not``/``(``/``)`` reach the eval per the token whitelist above
    except Exception:
        log.warning("rule_match: bad condition %r", condition)
        return False


class RuleMatcher:
    """Evaluate a set of rules against tap events."""

    def __init__(self, rules: Iterable[DetectionRule]) -> None:
        self._rules = list(rules)

    def match(self, event: dict[str, Any], now_ts: float) -> list[DetectionEvent]:
        """Return every rule that fires on ``event``."""
        hits: list[DetectionEvent] = []
        event_ts = float(event.get("ts", now_ts))
        for rule in self._rules:
            selection_results: dict[str, bool] = {}
            matched_fields: dict[str, str] = {}
            for name, sel in rule.selections.items():
                ok, fields = _selection_matches(sel, event)
                selection_results[name] = ok
                if ok:
                    matched_fields.update({f"{name}.{k}": v for k, v in fields.items()})
            if _evaluate_condition(rule.condition, selection_results):
                hits.append(
                    DetectionEvent(
                        rule=rule,
                        matched_fields=matched_fields,
                        event_ts=event_ts,
                        detection_ts=now_ts,
                    )
                )
        return hits


def load_rules(path: str | Path) -> list[DetectionRule]:
    """Load detection rules from a JSONL file or a directory of JSON files."""
    p = Path(path)
    rules: list[DetectionRule] = []
    if p.is_file():
        rules.extend(_load_from_jsonl(p))
    elif p.is_dir():
        for entry in sorted(p.iterdir()):
            if entry.suffix == ".jsonl":
                rules.extend(_load_from_jsonl(entry))
            elif entry.suffix == ".json":
                rules.extend(_load_from_json(entry))
    return rules


def _load_from_jsonl(path: Path) -> list[DetectionRule]:
    out: list[DetectionRule] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = _rule_from_dict(data)
            if rule:
                out.append(rule)
    except OSError as exc:
        log.warning("rule_match: failed to load %s: %s", path, exc)
    return out


def _load_from_json(path: Path) -> list[DetectionRule]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("rule_match: failed to load %s: %s", path, exc)
        return []
    if isinstance(data, list):
        return [r for d in data if (r := _rule_from_dict(d))]
    if isinstance(data, dict):
        rule = _rule_from_dict(data)
        return [rule] if rule else []
    return []


def _rule_from_dict(data: dict[str, Any]) -> DetectionRule | None:
    if not isinstance(data, dict):
        return None
    rid = str(data.get("id") or "").strip()
    if not rid:
        return None
    selections_raw = data.get("selections") or data.get("match") or {}
    if not isinstance(selections_raw, dict):
        return None
    selections: dict[str, dict[str, str]] = {}
    if "match" in data and isinstance(data["match"], dict):
        selections["selection"] = {k: str(v) for k, v in data["match"].items()}
    else:
        for name, sel in selections_raw.items():
            if isinstance(sel, dict):
                selections[name] = {k: str(v) for k, v in sel.items()}
    condition = str(data.get("condition") or ("selection" if "match" in data else ""))
    mitre = tuple(str(t) for t in (data.get("mitre") or []))
    return DetectionRule(
        id=rid,
        title=str(data.get("title", rid)),
        level=str(data.get("level", "medium")),
        mitre=mitre,
        selections=selections,
        condition=condition,
    )


def score_mttd(red_event_ts: float, blue_detection_ts: float) -> float:
    """Time-to-detect in seconds. Negative or zero is reported as 0.0."""
    return max(0.0, blue_detection_ts - red_event_ts)
