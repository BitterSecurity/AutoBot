"""Coverage status tests — capability map + "no evidence vs no visibility".

Capability map runs over the real built-in adapters (real data). The coverage
report is exercised against a REAL OpenSearch store in the integration test
(see tests/integration) — here we verify the mapping and the silent/live logic
with the real adapters.
"""

from __future__ import annotations

from autobot.coverage import capability_map, load_coverage_adapters


def test_capability_map_from_builtin_adapters() -> None:
    cmap = capability_map(load_coverage_adapters())
    # Proxy claims web/initial-access visibility; target log claims execution.
    assert "blue-ingress-proxy" in cmap.get("T1190", [])
    assert "target-log-file" in cmap.get("T1059", [])


def test_capability_map_groups_sources_per_technique() -> None:
    adapters = load_coverage_adapters()
    cmap = capability_map(adapters)
    # every mapped technique lists at least one real source id
    assert cmap
    for technique, sources in cmap.items():
        assert technique.startswith("T")
        assert sources
