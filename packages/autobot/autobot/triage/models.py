"""Triage value types + the graded response taxonomy.

The LLM triage tier only ever *annotates* already-matched findings — it never
makes or mutates a match decision (redesign §6). A triage result is therefore a
``TriageVerdict``: advisory disposition, confidence, dedup cluster, rationale,
and a *recommended* response grade. The recommendation is advice; actually
executing a response is the (future) response layer's job, gated by approval.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, Field

from decepticon_core.types.ocsf_event import SeverityId


class TriageDisposition(StrEnum):
    """What the triage tier concluded about a finding (advisory)."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class ResponseGrade(IntEnum):
    """Graded response taxonomy by reversibility (redesign §8).

    Triage may *recommend* a grade; the response layer *enforces* guardrails.
    Higher = less reversible = stronger guardrail required. Autonomy stops well
    below G4.
    """

    G0_NOTIFY = 0  # ticket / alert / enrich — reversible, auto-allowed
    G1_DEPLOY_DETECTION = 1  # push rule to SIEM — reversible (versioned)
    G2_BLOCK = 2  # FW/proxy/WAF block — reversible (TTL)
    G3_ISOLATE = 3  # host isolation / disable account — needs explicit undo
    G4_DESTROY = 4  # kill/delete/reimage — irreversible; never autonomous


# Whether a grade's action is reversible — drives the guardrail the response
# layer applies. (Data lives with the taxonomy so triage and response agree.)
GRADE_REVERSIBLE: dict[ResponseGrade, bool] = {
    ResponseGrade.G0_NOTIFY: True,
    ResponseGrade.G1_DEPLOY_DETECTION: True,
    ResponseGrade.G2_BLOCK: True,
    ResponseGrade.G3_ISOLATE: True,
    ResponseGrade.G4_DESTROY: False,
}


class TriageVerdict(BaseModel):
    """Advisory annotation of one finding — never a match or an action.

    Produced by a triage engine from a read-only view of a finding and its
    evidence. Carries no capability to create/mutate findings or execute
    responses; ``recommended_response`` is advice only.
    """

    finding_id: str
    disposition: TriageDisposition = TriageDisposition.NEEDS_REVIEW
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: SeverityId = SeverityId.UNKNOWN
    dedup_cluster: str | None = None
    rationale: str = ""
    recommended_response: ResponseGrade = ResponseGrade.G0_NOTIFY
    evidence_event_ids: list[str] = Field(default_factory=list)
