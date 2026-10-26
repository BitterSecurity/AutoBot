"""Detection engines for AutoBot (redesign §6).

Default: OpenSearch Security Analytics (native Sigma), driven from AutoBot's
Sigma rule packs over the OCSF event index. Deterministic matching lives in the
engine; the LLM only triages already-matched findings.
"""

from __future__ import annotations

from autobot.detection.security_analytics import SecurityAnalyticsDetector

__all__ = ["SecurityAnalyticsDetector"]
