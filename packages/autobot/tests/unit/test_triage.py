"""Triage tier tests — read-only boundary, dedup, verdict production.

Uses real OcsfEvent evidence (real data, no mocked system). The key property is
architectural: the triage engine is handed only a frozen TriageContext and
returns an advisory verdict — it has no capability to create/mutate a match or
execute a response.
"""

from __future__ import annotations

import inspect

from autobot.triage import (
    HeuristicTriage,
    TriageContext,
    TriageDisposition,
    TriageEngineProtocol,
    TriageVerdict,
    cluster_findings,
    dedupe_key,
)
from autobot.triage.models import ResponseGrade
from decepticon_core.types.ocsf_event import OcsfEvent, SeverityId


def _ev(eid: str, **kw: object) -> OcsfEvent:
    return OcsfEvent(event_id=eid, event_type="http_access", source="blue-ingress-proxy", **kw)


def _ctx(fid: str, *evs: OcsfEvent, rules: tuple[str, ...] = ("rule-a",)) -> TriageContext:
    return TriageContext(finding_id=fid, rule_names=rules, evidence=tuple(evs))


def test_heuristic_satisfies_protocol() -> None:
    assert isinstance(HeuristicTriage(), TriageEngineProtocol)


def test_assess_produces_advisory_verdict() -> None:
    v = HeuristicTriage().assess(
        _ctx("f1", _ev("e1", src_ip="10.0.0.9", severity_id=SeverityId.HIGH))
    )
    assert isinstance(v, TriageVerdict)
    assert v.finding_id == "f1"
    assert v.disposition is TriageDisposition.TRUE_POSITIVE
    assert v.severity is SeverityId.HIGH
    assert v.evidence_event_ids == ["e1"]
    # Baseline never auto-recommends a destructive/containment grade.
    assert v.recommended_response is ResponseGrade.G0_NOTIFY


def test_no_evidence_is_needs_review() -> None:
    v = HeuristicTriage().assess(_ctx("f2"))
    assert v.disposition is TriageDisposition.NEEDS_REVIEW
    assert v.confidence == 0.0


def test_dedup_clusters_by_rule_and_entity() -> None:
    e1 = _ev("e1", src_ip="10.0.0.9")
    e2 = _ev("e2", src_ip="10.0.0.9")
    e3 = _ev("e3", src_ip="10.0.0.1")
    clusters = cluster_findings([_ctx("f1", e1), _ctx("f2", e2), _ctx("f3", e3)])
    # Same rule + same src_ip collapse; different ip is its own cluster.
    assert dedupe_key(("rule-a",), (e1,)) == dedupe_key(("rule-a",), (e2,))
    sizes = sorted(len(v) for v in clusters.values())
    assert sizes == [1, 2]


def test_boundary_context_is_frozen_and_capability_free() -> None:
    """The triage engine can only see data — no store/detector/executor handle."""
    ctx = _ctx("f1", _ev("e1"))
    # Context is immutable (frozen dataclass).
    try:
        ctx.finding_id = "x"  # type: ignore[misc]
        raise AssertionError("TriageContext must be frozen")
    except AttributeError:
        pass
    # assess() takes ONLY a TriageContext — no store/detector parameter exists,
    # so there is no code path from triage to creating a match or acting.
    params = list(inspect.signature(HeuristicTriage.assess).parameters)
    assert params == ["self", "context"]
    # The verdict is plain data with no write capability.
    v = HeuristicTriage().assess(ctx)
    assert set(type(v).model_fields) >= {"finding_id", "disposition", "recommended_response"}
