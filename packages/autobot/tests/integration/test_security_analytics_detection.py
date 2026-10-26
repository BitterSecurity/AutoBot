"""Integration test — real Sigma detection via OpenSearch Security Analytics.

Not a mock. Reproduces AutoBot's detection path end-to-end against a live
OpenSearch (``OPENSEARCH_URL``): normalize real raw HTTP records with the real
coverage adapter, store them in a real OCSF index, register the shipped Sigma
rule pack, create a Security Analytics detector, run it, and assert a finding
fires on the malicious request and NOT on the benign one.

Deterministic matching is done by Security Analytics (no LLM). Skipped when no
live OpenSearch is configured.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

_URL = os.environ.get("OPENSEARCH_URL")
_RULES = Path(__file__).resolve().parents[2] / "autobot" / "coverage" / "rules" / "proxy"


def _proxy_raw(rid: str, path: str, ip: str) -> dict:
    return {
        "sensor_file": "/sensor-logs/access.log",
        "ts": 1792000000.0,
        "path": path,
        "status": 200,
        "blue_request_id": rid,
        "request": {"client_ip": ip, "method": "GET", "host": "app"},
    }


def test_real_sigma_detection_fires_on_traversal_only() -> None:
    if not _URL:
        pytest.skip("OPENSEARCH_URL not set — no live OpenSearch")
    pytest.importorskip("opensearchpy")
    from autobot.coverage import dispatch_normalize
    from autobot.detection import SecurityAnalyticsDetector
    from autobot.stores import get_event_store

    index = f"autobot-det-{uuid.uuid4().hex[:8]}"
    name = f"autobot-det-{uuid.uuid4().hex[:8]}"
    store = get_event_store("opensearch", hosts=_URL, index=index)
    store.ensure_index()
    det = SecurityAnalyticsDetector(hosts=_URL)

    try:
        # Detector runs continuously; it evaluates documents that arrive AFTER
        # it exists (Security Analytics doc-level monitor semantics). So wire the
        # detector first, then let events arrive — the real operational order.
        det.ensure_log_type()
        rule_ids = det.register_rule_pack(_RULES)
        assert rule_ids, "shipped rule pack should contain at least one rule"
        created = det.create_detector(name, index, rule_ids)
        detector_id = created["_id"]

        # Real raw HTTP records -> real adapter -> real OCSF index.
        store.append(
            [
                dispatch_normalize(_proxy_raw("req-bad", "/static/../../etc/passwd", "10.0.0.66")),
                dispatch_normalize(_proxy_raw("req-ok", "/index.html", "10.0.0.7")),
            ]
        )

        assert det.run_now(name) is True
        findings = det.findings(detector_id)

        assert len(findings) == 1, f"expected exactly one finding, got {len(findings)}"
        fired_docs = findings[0].get("related_doc_ids", [])
        # The fired document is the traversal request, not the benign one.
        got = store.search("request_id", "req-bad", limit=1).events[0]
        assert got.seq is not None
        assert any(
            "../" in store._os.get(index=index, id=d)["_source"]["message"] for d in fired_docs
        )
    finally:
        for rid in locals().get("rule_ids", []) or []:
            try:
                det._transport("DELETE", f"/_plugins/_security_analytics/rules/{rid}?forced=true")
            except Exception:  # noqa: BLE001
                pass
        try:
            det._transport(
                "DELETE",
                f"/_plugins/_security_analytics/detectors/{locals().get('detector_id', '')}",
            )
        except Exception:  # noqa: BLE001
            pass
        try:
            store._os.indices.delete(index=index)
        except Exception:  # noqa: BLE001
            pass
