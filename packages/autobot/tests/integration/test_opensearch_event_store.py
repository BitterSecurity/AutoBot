"""Integration test — OpenSearchEventStore against a REAL OpenSearch.

Not a mock. Runs only when ``OPENSEARCH_URL`` points at a live OpenSearch
(e.g. ``http://127.0.0.1:9200``); otherwise skipped, so the fast CI lane is
unaffected. Bring one up with::

    docker run -d --name os -p 9200:9200 -e discovery.type=single-node \
      -e DISABLE_SECURITY_PLUGIN=true opensearchproject/opensearch:2.17.1
    OPENSEARCH_URL=http://127.0.0.1:9200 uv run --extra opensearch \
      pytest packages/decepticon/tests/integration/test_opensearch_event_store.py

Verifies the EventStoreProtocol contract end-to-end on the real default
substrate: dedup, cursor paging, source-agnostic search, timeline source
filter, source/metrics aggregation, and raw_data fidelity through a real
index/query roundtrip.
"""

from __future__ import annotations

import os
import uuid

import pytest

from decepticon_core.protocols import EventStoreProtocol
from decepticon_core.types.ocsf_event import OcsfEvent, SignalType

pytestmark = pytest.mark.slow

_URL = os.environ.get("OPENSEARCH_URL")


@pytest.fixture
def store():  # type: ignore[no-untyped-def]
    if not _URL:
        pytest.skip("OPENSEARCH_URL not set — no live OpenSearch")
    pytest.importorskip("opensearchpy")
    from autobot.stores import OpenSearchEventStore

    index = f"autobot-it-{uuid.uuid4().hex[:8]}"
    s = OpenSearchEventStore(hosts=_URL, index=index)
    s.ensure_index()
    try:
        yield s
    finally:
        try:
            s._os.indices.delete(index=index)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass


def _ev(i: int, src: str, **kw: object) -> OcsfEvent:
    return OcsfEvent(
        event_id=f"id-{i}",
        event_type="t",
        source=src,
        observed_at="2026-10-23T05:00:0%d+00:00" % (i % 10),
        **kw,
    )


def test_real_opensearch_event_store_contract(store) -> None:  # type: ignore[no-untyped-def]
    assert isinstance(store, EventStoreProtocol)

    r = store.append(
        [
            _ev(1, "blue-ingress-proxy", signal_type=SignalType.HTTP, src_ip="10.0.0.9"),
            _ev(2, "wazuh", signal_type=SignalType.AUTH, src_ip="10.0.0.9", actor_user="alice"),
            _ev(3, "syslog", src_ip="192.168.0.1"),
            _ev(4, "wazuh", actor_user="bob", raw_data='{"orig":"line"}'),
        ]
    )
    assert (r.accepted, r.rejected) == (4, 0)

    # dedup on event_id through the real index
    assert store.append([_ev(1, "blue-ingress-proxy")]).accepted == 0
    assert store.latest_seq() == 4

    # cursor paging
    page = store.page(after=0, limit=2)
    assert [e.event_id for e in page.events] == ["id-1", "id-2"]
    assert page.next_cursor == 2

    # source-agnostic entity search spans sources
    hits = store.search("src_ip", "10.0.0.9", limit=10)
    assert {e.source for e in hits.events} == {"blue-ingress-proxy", "wazuh"}

    # timeline filters by arbitrary source id
    tl = store.timeline(
        "2026-10-23T00:00:00+00:00", "2026-10-23T23:59:59+00:00", source="wazuh", limit=10
    )
    assert {e.source for e in tl.events} == {"wazuh"}

    # dynamic per-source aggregation
    assert {s.source: s.events_retained for s in store.sources(10)} == {
        "wazuh": 2,
        "blue-ingress-proxy": 1,
        "syslog": 1,
    }
    m = store.metrics()
    assert m.events_total == 4
    assert m.per_source == {"wazuh": 2, "blue-ingress-proxy": 1, "syslog": 1}

    # raw_data survives a real index -> query roundtrip
    got = store.search("actor_user", "bob", limit=1).events[0]
    assert got.raw_data == '{"orig":"line"}'


def test_coverage_report_distinguishes_silent_from_live(store) -> None:  # type: ignore[no-untyped-def]
    """A source that delivered nothing is a gap, not proof of safety."""
    from autobot.coverage import build_coverage_report, load_coverage_adapters

    adapters = load_coverage_adapters()  # expects proxy + target-log
    # Only target-log delivers; proxy stays silent.
    store.append([_ev(1, "target-log-file")])

    report = build_coverage_report(store, adapters)
    by_id = {s.source_id: s for s in report.sources}
    assert by_id["target-log-file"].status == "live"
    assert by_id["blue-ingress-proxy"].status == "silent"
    assert "blue-ingress-proxy" in report.silent_sources

    # Technique visibility reflects only LIVE sources.
    assert "T1059" in report.techniques_visible  # covered by live target-log
    assert "T1190" not in report.techniques_visible  # proxy silent -> blind
    # ...but AutoBot still knows the technique is *coverable* (vs truly blind).
    assert report.covers_technique("T1190")
