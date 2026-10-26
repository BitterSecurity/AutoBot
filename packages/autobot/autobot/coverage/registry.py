"""Coverage adapter registry + normalize dispatch.

Adapters are independently installable (redesign §3.2): in-tree built-ins plus
any package registering under the ``decepticon.coverage`` entry-point group.
``dispatch_normalize`` routes a raw record to the first adapter that claims it;
an unclaimed record still yields a valid passthrough event (raw_data + unmapped)
so no source detail is dropped and the agent sees every ingested record.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib.metadata import entry_points
from typing import Any

from autobot.coverage._common import hash_record
from decepticon_core.protocols.coverage import CoverageAdapterProtocol
from decepticon_core.types.ocsf_event import Metadata, OcsfEvent, SignalType

COVERAGE_GROUP = "decepticon.coverage"


def builtin_adapters() -> list[CoverageAdapterProtocol]:
    from autobot.coverage.proxy import ProxyCoverageAdapter
    from autobot.coverage.target_log import TargetLogCoverageAdapter

    return [ProxyCoverageAdapter(), TargetLogCoverageAdapter()]


def load_coverage_adapters() -> list[CoverageAdapterProtocol]:
    """Built-in adapters plus any installed under ``decepticon.coverage``."""
    adapters = builtin_adapters()
    for ep in entry_points(group=COVERAGE_GROUP):
        try:
            obj = ep.load()
            adapters.append(obj() if isinstance(obj, type) else obj)
        except Exception:  # noqa: BLE001 — a broken plugin must not break ingest
            continue
    return adapters


def passthrough_event(raw: Mapping[str, Any]) -> OcsfEvent:
    """Valid envelope for a record no adapter claimed — never drop it."""
    return OcsfEvent(
        event_id=hash_record(dict(raw)),
        event_type="unmapped",
        signal_type=SignalType.OTHER,
        source="unknown",
        raw_data=str(raw.get("log") or raw),
        unmapped=dict(raw),
        metadata=Metadata(sensor_file=raw.get("sensor_file")),
    )


def dispatch_normalize(
    raw: Mapping[str, Any],
    adapters: list[CoverageAdapterProtocol] | None = None,
) -> OcsfEvent:
    """Normalize one raw record via the first claiming adapter, else passthrough."""
    for adapter in adapters if adapters is not None else load_coverage_adapters():
        try:
            if adapter.claims(raw):
                return adapter.normalize(raw)
        except Exception:  # noqa: BLE001 — a bad adapter falls through to passthrough
            continue
    return passthrough_event(raw)
