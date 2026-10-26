"""OpenSearch-backed EventStore — the default AutoBot event store substrate.

A concrete :class:`~decepticon_core.protocols.event_store.EventStoreProtocol`
implementation over a real OpenSearch index of normalized
:class:`~decepticon_core.types.ocsf_event.OcsfEvent` documents (redesign §5).
OpenSearch is the default substrate because it ships Security Analytics
(native Sigma detection) and speaks the ES API the existing SIEM ecosystem
already uses.

Hybrid document shape: the hot, source-agnostic query keys
(``OcsfEvent.PROMOTED_FIELDS``) are mapped to typed fields for fast
source-agnostic queries, and the full normalized record — including
``raw_data`` and ``unmapped`` — is kept so no source detail is lost.

``opensearch-py`` is imported lazily so the framework base install does not
depend on it; deployers that use this store install the ``opensearch`` extra.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from decepticon_core.types.event_store import (
    EventPage,
    IngestResult,
    SourceInfo,
    StoreMetrics,
)
from decepticon_core.types.ocsf_event import OcsfEvent

# Hybrid mapping: promoted keys as typed fields; the rest stored but unindexed.
_INDEX_MAPPING: dict[str, Any] = {
    "mappings": {
        "properties": {
            "seq": {"type": "long"},
            "event_id": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "signal_type": {"type": "keyword"},
            "source": {"type": "keyword"},
            "class_uid": {"type": "long"},
            "category_uid": {"type": "long"},
            "activity_id": {"type": "long"},
            "occurred_at": {"type": "date"},
            "observed_at": {"type": "date"},
            "severity_id": {"type": "integer"},
            "request_id": {"type": "keyword"},
            "trace_id": {"type": "keyword"},
            "span_id": {"type": "keyword"},
            "actor_user": {"type": "keyword"},
            "src_ip": {"type": "keyword"},
            "dst_ip": {"type": "keyword"},
            "device_host": {"type": "keyword"},
            "message": {"type": "text"},
            # Full-fidelity payload — kept, not heavily indexed.
            "raw_data": {"type": "text", "index": False},
            "unmapped": {"type": "object", "enabled": False},
            "attributes": {"type": "object", "enabled": False},
        }
    }
}


class OpenSearchEventStore:
    """EventStore over a real OpenSearch index.

    Satisfies ``EventStoreProtocol`` structurally (sync methods). A monotonic
    ``seq`` is assigned per document so readers page deterministically, matching
    the sensor receiver's sequence semantics.
    """

    def __init__(
        self,
        *,
        hosts: list[dict[str, Any]] | str = "http://127.0.0.1:9200",
        index: str = "autobot-events",
        client: Any = None,
    ) -> None:
        if client is not None:
            self._os = client
        else:
            from opensearchpy import OpenSearch  # noqa: PLC0415 — lazy optional dep

            self._os = OpenSearch(hosts=hosts, http_compress=True)
        self._index = index

    # ── Setup ─────────────────────────────────────────────────────────────
    def ensure_index(self) -> None:
        if not self._os.indices.exists(index=self._index):
            self._os.indices.create(index=self._index, body=_INDEX_MAPPING)

    # ── Writer side ───────────────────────────────────────────────────────
    def append(self, events: Sequence[OcsfEvent]) -> IngestResult:
        if not events:
            return IngestResult(accepted=0, rejected=0)
        seq = self.latest_seq()
        accepted = 0
        rejected = 0
        for ev in events:
            seq += 1
            doc = ev.model_dump(mode="json")
            doc["seq"] = seq
            try:
                # op_type=create + event_id as _id => dedup (reject on existing).
                self._os.index(
                    index=self._index,
                    id=ev.event_id,
                    body=doc,
                    op_type="create",
                    refresh="wait_for",
                )
                accepted += 1
            except Exception:  # noqa: BLE001 — a conflict is a dedup, not a failure
                seq -= 1
                rejected += 1
        return IngestResult(accepted=accepted, rejected=rejected)

    def latest_seq(self) -> int:
        res = self._os.search(
            index=self._index,
            body={"size": 0, "aggs": {"m": {"max": {"field": "seq"}}}},
            ignore=[404],
        )
        value = (res.get("aggregations") or {}).get("m", {}).get("value")
        return int(value) if value else 0

    # ── Reader side (source-agnostic) ─────────────────────────────────────
    def _page(self, query: dict[str, Any], sort: list[Any], limit: int) -> list[OcsfEvent]:
        res = self._os.search(
            index=self._index,
            body={"query": query, "sort": sort, "size": limit},
            ignore=[404],
        )
        hits = (res.get("hits") or {}).get("hits") or []
        return [OcsfEvent.model_validate(h["_source"]) for h in hits]

    def page(self, after: int, limit: int) -> EventPage:
        events = self._page({"range": {"seq": {"gt": after}}}, [{"seq": "asc"}], limit)
        nxt = events[-1].seq if events else None
        return EventPage(events=events, next_cursor=nxt, has_more=len(events) == limit)

    def search(self, field: str, value: str, limit: int, before: int | None = None) -> EventPage:
        must: list[dict[str, Any]] = [{"term": {field: value}}]
        if before is not None:
            must.append({"range": {"seq": {"lt": before}}})
        events = self._page({"bool": {"must": must}}, [{"seq": "desc"}], limit)
        return EventPage(events=events, next_cursor=events[-1].seq if events else None)

    def timeline(
        self,
        start_at: str,
        end_at: str,
        source: str | None = None,
        limit: int = 50,
        before: int | None = None,
    ) -> EventPage:
        must: list[dict[str, Any]] = [{"range": {"observed_at": {"gte": start_at, "lte": end_at}}}]
        if source is not None:
            must.append({"term": {"source": source}})
        if before is not None:
            must.append({"range": {"seq": {"lt": before}}})
        events = self._page({"bool": {"must": must}}, [{"seq": "desc"}], limit)
        return EventPage(events=events, next_cursor=events[-1].seq if events else None)

    def sources(self, limit: int) -> list[SourceInfo]:
        res = self._os.search(
            index=self._index,
            body={
                "size": 0,
                "aggs": {
                    "by_source": {
                        "terms": {"field": "source", "size": limit},
                        "aggs": {"last_seq": {"max": {"field": "seq"}}},
                    }
                },
            },
            ignore=[404],
        )
        buckets = (res.get("aggregations") or {}).get("by_source", {}).get("buckets", [])
        return [
            SourceInfo(
                source=b["key"],
                events_retained=b["doc_count"],
                latest_seq=int(b["last_seq"]["value"]) if b["last_seq"]["value"] else None,
            )
            for b in buckets
        ]

    def metrics(self) -> StoreMetrics:
        res = self._os.search(
            index=self._index,
            body={
                "size": 0,
                "aggs": {
                    "total": {"value_count": {"field": "seq"}},
                    "max_seq": {"max": {"field": "seq"}},
                    "min_seq": {"min": {"field": "seq"}},
                    "by_source": {"terms": {"field": "source", "size": 1000}},
                },
                "track_total_hits": True,
            },
            ignore=[404],
        )
        aggs = res.get("aggregations") or {}
        total = int((aggs.get("total") or {}).get("value") or 0)
        per = {b["key"]: b["doc_count"] for b in (aggs.get("by_source") or {}).get("buckets", [])}
        return StoreMetrics(
            events_total=total,
            latest_seq=int((aggs.get("max_seq") or {}).get("value") or 0),
            oldest_seq=int((aggs.get("min_seq") or {}).get("value") or 0),
            events_ingested_total=total,
            per_source=per,
        )
