"""Pluggable log-coverage adapters (redesign §3.2, §4).

Each adapter turns one raw source into normalized OcsfEvents. Built-ins cover
the HTTP ingress proxy and target log files; external adapters install
separately and register under the ``decepticon.coverage`` entry-point group.
"""

from __future__ import annotations

from autobot.coverage.proxy import ProxyCoverageAdapter
from autobot.coverage.registry import (
    COVERAGE_GROUP,
    dispatch_normalize,
    load_coverage_adapters,
    passthrough_event,
)
from autobot.coverage.status import (
    CoverageReport,
    SourceCoverage,
    build_coverage_report,
    capability_map,
)
from autobot.coverage.target_log import TargetLogCoverageAdapter

__all__ = [
    "COVERAGE_GROUP",
    "CoverageReport",
    "ProxyCoverageAdapter",
    "SourceCoverage",
    "TargetLogCoverageAdapter",
    "build_coverage_report",
    "capability_map",
    "dispatch_normalize",
    "load_coverage_adapters",
    "passthrough_event",
]
