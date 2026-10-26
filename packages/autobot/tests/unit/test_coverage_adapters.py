"""Coverage adapter tests — real raw record shapes -> OCSF events.

These feed the actual raw shapes Fluent Bit forwards (Caddy access record,
target log line, process-wrapper envelope) through the real adapters; no system
is mocked. Verifies classification, OCSF mapping, raw_data fidelity, and the
passthrough guarantee for unclaimed records.
"""

from __future__ import annotations

from autobot.coverage import (
    ProxyCoverageAdapter,
    TargetLogCoverageAdapter,
    dispatch_normalize,
    load_coverage_adapters,
)
from decepticon_core.protocols import CoverageAdapterProtocol
from decepticon_core.types.ocsf_event import SeverityId, SignalType

_PROXY_RAW = {
    "sensor_file": "/sensor-logs/access.log",
    "sensor_offset": 1024,
    "ts": 1792000000.5,
    "path": "/admin",
    "status": 403,
    "blue_request_id": "req-abc",
    "request": {"client_ip": "10.0.0.9", "host": "app", "method": "GET", "uri": "/admin"},
}

_APP_LOG_RAW = {
    "sensor_file": "/target-logs/app.log",
    "log": '{"level":"error","message":"boom","trace_id":"t-1","request_id":"r-9"}',
}

_PROC_RAW = {
    "sensor_file": "/target-logs/proc.log",
    "log": '{"source":"target-process","event_id":"p-1","event_type":"process_lifecycle",'
    '"message":"exited","pid":4242,"exit_code":1}',
}

_PLAIN_RAW = {"sensor_file": "/target-logs/x.log", "log": "just a plain line"}


def test_adapters_satisfy_protocol() -> None:
    assert isinstance(ProxyCoverageAdapter(), CoverageAdapterProtocol)
    assert isinstance(TargetLogCoverageAdapter(), CoverageAdapterProtocol)


def test_proxy_adapter_maps_http_access() -> None:
    ev = ProxyCoverageAdapter().normalize(_PROXY_RAW)
    assert ev.source == "blue-ingress-proxy"
    assert ev.signal_type is SignalType.HTTP
    assert ev.event_type == "http_access"
    assert ev.src_ip == "10.0.0.9"
    assert ev.request_id == "req-abc"
    assert ev.occurred_at is not None and ev.occurred_at.year == 2026
    assert ev.attributes["status"] == 403
    assert '"path":"/admin"' in ev.raw_data  # original preserved


def test_target_app_log_severity_and_correlation() -> None:
    ev = TargetLogCoverageAdapter().normalize(_APP_LOG_RAW)
    assert ev.event_type == "application_log"
    assert ev.severity_text == "error"
    assert ev.severity_id is SeverityId.MEDIUM
    assert ev.trace_id == "t-1"
    assert ev.request_id == "r-9"
    assert ev.message == "boom"
    assert ev.raw_data == _APP_LOG_RAW["log"]


def test_process_wrapper_envelope() -> None:
    ev = TargetLogCoverageAdapter().normalize(_PROC_RAW)
    assert ev.event_type == "process_lifecycle"
    assert ev.signal_type is SignalType.PROCESS
    assert ev.attributes["pid"] == 4242
    assert ev.attributes["exit_code"] == 1
    assert ev.metadata.source_event_id == "p-1"  # app id retained, not authority


def test_plain_line_falls_back_to_log_line() -> None:
    ev = TargetLogCoverageAdapter().normalize(_PLAIN_RAW)
    assert ev.event_type == "log_line"
    assert ev.message == "just a plain line"


def test_dispatch_routes_by_claims() -> None:
    adapters = load_coverage_adapters()
    assert dispatch_normalize(_PROXY_RAW, adapters).source == "blue-ingress-proxy"
    assert dispatch_normalize(_APP_LOG_RAW, adapters).source == "target-log-file"


def test_unclaimed_record_passthrough_never_dropped() -> None:
    weird = {"sensor_file": "/x", "totally": "unknown shape", "n": 1}
    ev = dispatch_normalize(weird, [])  # no adapters -> passthrough
    assert ev.event_type == "unmapped"
    assert ev.source == "unknown"
    assert ev.unmapped == weird  # original fields preserved for audit


def test_builtin_adapters_discovered() -> None:
    sources = {a.source_id for a in load_coverage_adapters()}
    assert {"blue-ingress-proxy", "target-log-file"} <= sources
