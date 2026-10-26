"""LLM triage tier — read-only annotation of matched findings (redesign §6).

The triage engine sees only a read-only TriageContext and returns an advisory
TriageVerdict; it cannot create/mutate a match or execute a response. The LLM
engine is a drop-in for the deterministic HeuristicTriage baseline.
"""

from __future__ import annotations

from autobot.triage.engine import (
    HeuristicTriage,
    TriageContext,
    TriageEngineProtocol,
    cluster_findings,
    dedupe_key,
)
from autobot.triage.models import (
    GRADE_REVERSIBLE,
    ResponseGrade,
    TriageDisposition,
    TriageVerdict,
)

__all__ = [
    "GRADE_REVERSIBLE",
    "HeuristicTriage",
    "ResponseGrade",
    "TriageContext",
    "TriageDisposition",
    "TriageEngineProtocol",
    "TriageVerdict",
    "cluster_findings",
    "dedupe_key",
]
