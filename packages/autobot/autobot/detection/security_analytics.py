"""Detection engine over OpenSearch Security Analytics (Sigma, real).

Drives the OpenSearch Security Analytics plugin — the Sigma detection engine
that ships with the default substrate (redesign §6) — from AutoBot's Sigma rule
packs over an OCSF event index. Deterministic matching is done by Security
Analytics (not an LLM); AutoBot only installs the rules, wires the detector, and
reads findings.

The call sequence (custom log type → register Sigma rules → field mapping →
detector → findings) was validated end-to-end against a real OpenSearch 2.17
Security Analytics instance: an adapter-normalized path-traversal request raised
a finding on the exact document while a benign request did not.

``opensearch-py`` is imported lazily (install ``decepticon[opensearch]``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_SA = "/_plugins/_security_analytics"


class SecurityAnalyticsDetector:
    """Install Sigma rules and read findings via OpenSearch Security Analytics."""

    def __init__(
        self,
        *,
        hosts: list[dict[str, Any]] | str = "http://127.0.0.1:9200",
        log_type: str = "autobot_ocsf",
        client: Any = None,
    ) -> None:
        if client is not None:
            self._os = client
        else:
            from opensearchpy import OpenSearch  # noqa: PLC0415 — lazy optional dep

            self._os = OpenSearch(hosts=hosts, http_compress=True)
        self.log_type = log_type

    def _transport(self, method: str, path: str, body: Any = None) -> Any:
        return self._os.transport.perform_request(method, path, body=body)

    # ── Setup ─────────────────────────────────────────────────────────────
    def ensure_log_type(self, description: str = "AutoBot OCSF-normalized events") -> None:
        """Create the custom log type if absent (idempotent)."""
        existing = self._transport(
            "POST", f"{_SA}/logtype/_search", {"size": 200, "query": {"match_all": {}}}
        )
        names = {h["_source"]["name"] for h in existing["hits"]["hits"]}
        if self.log_type in names:
            return
        self._transport(
            "POST",
            f"{_SA}/logtype",
            {
                "name": self.log_type,
                "description": description,
                "source": "Custom",
                "category": "Other",
            },
        )

    def register_rule(self, sigma_yaml: str) -> str:
        """Register one Sigma rule for this log type; returns its rule id."""
        res = self._transport("POST", f"{_SA}/rules?category={self.log_type}", sigma_yaml)
        return res["_id"]

    def register_rule_pack(self, rules_dir: str | Path) -> list[str]:
        """Register every ``*.yml`` Sigma rule in a directory; returns rule ids."""
        ids: list[str] = []
        for path in sorted(Path(rules_dir).glob("*.yml")):
            ids.append(self.register_rule(path.read_text(encoding="utf-8")))
        return ids

    def create_detector(self, name: str, index: str, rule_ids: list[str]) -> dict[str, Any]:
        """Create an enabled detector binding rules to an OCSF index."""
        body = {
            "type": "detector",
            "name": name,
            "detector_type": self.log_type,
            "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [
                {
                    "detector_input": {
                        "description": "autobot",
                        "indices": [index],
                        "custom_rules": [{"id": rid} for rid in rule_ids],
                        "pre_packaged_rules": [],
                    }
                }
            ],
            "triggers": [
                {
                    "name": "match",
                    "severity": "1",
                    "types": [],
                    "ids": [],
                    "tags": [],
                    "sev_levels": [],
                    "actions": [],
                }
            ],
        }
        return self._transport("POST", f"{_SA}/detectors", body)

    def workflow_id_for(self, detector_name: str) -> str | None:
        """Find the alerting workflow Security Analytics created for a detector.

        The workflow is written to the alerting config index asynchronously on
        detector creation, so refresh it before searching to avoid a race.
        """
        try:
            self._os.indices.refresh(index=".opendistro-alerting-config")
        except Exception:  # noqa: BLE001 — refresh is best-effort
            pass
        # Match_all + exact-name filter in Python: the detector name is not a
        # text-analyzed field, so a match query can miss it.
        res = self._transport(
            "POST",
            "/_plugins/_alerting/monitors/_search",
            {"size": 200, "query": {"match_all": {}}},
        )
        for hit in res.get("hits", {}).get("hits", []):
            src = hit["_source"]
            if src.get("type") == "workflow" and src.get("name") == detector_name:
                return hit["_id"]
        return None

    def run_now(self, detector_name: str) -> bool:
        """Execute the detector's workflow on demand (don't wait for schedule)."""
        wf = self.workflow_id_for(detector_name)
        if wf is None:
            return False
        self._transport("POST", f"/_plugins/_alerting/workflows/{wf}/_execute", {})
        return True

    # ── Read ──────────────────────────────────────────────────────────────
    def findings(self, detector_id: str) -> list[dict[str, Any]]:
        """Return findings for a detector (deterministic rule matches).

        Workflow execution persists findings asynchronously to the SAP findings
        indices; refresh them first so a read right after ``run_now`` is
        consistent.
        """
        try:
            self._os.indices.refresh(index=".opensearch-sap-*findings*")
        except Exception:  # noqa: BLE001 — refresh is best-effort
            pass
        res = self._transport("GET", f"{_SA}/findings/_search?detector_id={detector_id}")
        return res.get("findings", [])
