"""Coverage registry + capability map — "no evidence" vs "no visibility".

A silent source is a first-class coverage gap, not proof of safety (redesign
§7: absence of logs != no attack). This module combines what the store has
actually delivered (``EventStoreProtocol.sources``) with what coverage is
expected (installed adapters) and what each source claims to see
(``coverage_manifest`` → ATT&CK), so the agent can qualify conclusions:
"no lateral-movement events, but no source covers that technique — a blind
spot, not a clean result."
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, Field

from decepticon_core.protocols.coverage import CoverageAdapterProtocol
from decepticon_core.protocols.event_store import EventStoreProtocol


def capability_map(
    adapters: Iterable[CoverageAdapterProtocol],
) -> dict[str, list[str]]:
    """ATT&CK technique id -> source ids that claim visibility into it."""
    out: dict[str, list[str]] = {}
    for adapter in adapters:
        for technique in adapter.coverage_manifest():
            out.setdefault(technique, [])
            if adapter.source_id not in out[technique]:
                out[technique].append(adapter.source_id)
    return out


class SourceCoverage(BaseModel):
    """Delivery status of one expected coverage source."""

    source_id: str
    expected: bool = True
    delivered: bool = False
    events_retained: int = 0
    last_received_at: str | None = None
    status: str = "silent"  # "live" | "silent"


class CoverageReport(BaseModel):
    """What the defense can and cannot see right now."""

    sources: list[SourceCoverage] = Field(default_factory=list)
    silent_sources: list[str] = Field(default_factory=list)
    techniques_visible: list[str] = Field(default_factory=list)
    capability_map: dict[str, list[str]] = Field(default_factory=dict)

    def covers_technique(self, technique_id: str) -> bool:
        """True if any source claims visibility into this ATT&CK technique."""
        return technique_id in self.capability_map


def build_coverage_report(
    store: EventStoreProtocol,
    adapters: Iterable[CoverageAdapterProtocol],
    *,
    source_limit: int = 100,
) -> CoverageReport:
    """Correlate expected adapters with what the store actually delivered."""
    adapters = list(adapters)
    delivered = {s.source: s for s in store.sources(source_limit)}
    report = CoverageReport(capability_map=capability_map(adapters))

    seen: set[str] = set()
    for adapter in adapters:
        sid = adapter.source_id
        seen.add(sid)
        info = delivered.get(sid)
        is_live = info is not None and info.events_retained > 0
        report.sources.append(
            SourceCoverage(
                source_id=sid,
                expected=True,
                delivered=info is not None,
                events_retained=info.events_retained if info else 0,
                last_received_at=info.last_received_at if info else None,
                status="live" if is_live else "silent",
            )
        )
        if not is_live:
            report.silent_sources.append(sid)

    # Sources delivering events that no installed adapter expected (e.g. a
    # passthrough "unknown" or an externally-fed source).
    for source, info in delivered.items():
        if source not in seen:
            report.sources.append(
                SourceCoverage(
                    source_id=source,
                    expected=False,
                    delivered=True,
                    events_retained=info.events_retained,
                    last_received_at=info.last_received_at,
                    status="live" if info.events_retained > 0 else "silent",
                )
            )

    # A technique is "visible" only if at least one covering source is live.
    live = {s.source_id for s in report.sources if s.status == "live"}
    report.techniques_visible = sorted(
        t for t, srcs in report.capability_map.items() if live.intersection(srcs)
    )
    return report
