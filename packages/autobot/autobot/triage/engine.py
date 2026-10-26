"""Triage engine — read-only annotation of matched findings.

Architectural boundary (redesign §6): the triage tier receives a **read-only**
``TriageContext`` (a finding plus its evidence events) and returns a
``TriageVerdict``. It is handed no event store, no detector, and no response
executor — so it *cannot* create or mutate a match, nor run a response. An LLM
engine is a drop-in that satisfies the same read-only signature; keeping the
boundary in the type signature (not the prompt) is what enforces it.

``HeuristicTriage`` is a deterministic baseline (no LLM) used until the LLM
engine is wired; both implement ``TriageEngineProtocol``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from autobot.triage.models import ResponseGrade, TriageDisposition, TriageVerdict
from decepticon_core.types.ocsf_event import OcsfEvent, SeverityId


@dataclass(frozen=True)
class TriageContext:
    """Immutable view a triage engine is allowed to see.

    ``finding`` is the matched finding (id + rule names + matched doc ids);
    ``evidence`` are the OCSF events behind it. Frozen + plain data: there is no
    handle here to write events, create findings, or execute responses.
    """

    finding_id: str
    rule_names: tuple[str, ...]
    evidence: tuple[OcsfEvent, ...]


@runtime_checkable
class TriageEngineProtocol(Protocol):
    """Read-only triage: context in → advisory verdict out. No side effects."""

    def assess(self, context: TriageContext) -> TriageVerdict: ...


def dedupe_key(rule_names: Iterable[str], evidence: Sequence[OcsfEvent]) -> str:
    """Stable cluster key = rule(s) + primary entity, so repeats collapse."""
    rules = "+".join(sorted(rule_names)) or "unknown"
    entity = ""
    for ev in evidence:
        entity = ev.src_ip or ev.actor_user or ev.device_host or ev.source
        if entity:
            break
    return f"{rules}:{entity}"


def cluster_findings(contexts: Iterable[TriageContext]) -> dict[str, list[str]]:
    """Group finding ids by dedupe key (alert fatigue reduction)."""
    clusters: dict[str, list[str]] = {}
    for ctx in contexts:
        key = dedupe_key(ctx.rule_names, ctx.evidence)
        clusters.setdefault(key, []).append(ctx.finding_id)
    return clusters


class HeuristicTriage:
    """Deterministic baseline triage (no LLM) — a placeholder for the LLM tier.

    It only reads the context and returns a verdict; it holds no store/detector.
    """

    def assess(self, context: TriageContext) -> TriageVerdict:
        key = dedupe_key(context.rule_names, context.evidence)
        severity = max(
            (e.severity_id for e in context.evidence),
            default=SeverityId.UNKNOWN,
        )
        has_evidence = bool(context.evidence)
        return TriageVerdict(
            finding_id=context.finding_id,
            disposition=(
                TriageDisposition.TRUE_POSITIVE if has_evidence else TriageDisposition.NEEDS_REVIEW
            ),
            confidence=0.5 if has_evidence else 0.0,
            severity=severity,
            dedup_cluster=key,
            rationale=(
                f"matched {', '.join(context.rule_names) or 'rule'} on "
                f"{len(context.evidence)} event(s)"
            ),
            # Baseline only ever recommends notify; stronger grades require the
            # LLM/analyst and the response layer's guardrails.
            recommended_response=ResponseGrade.G0_NOTIFY,
            evidence_event_ids=[e.event_id for e in context.evidence],
        )
