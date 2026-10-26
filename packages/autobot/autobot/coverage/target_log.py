"""Target application/process log coverage adapter.

Normalizes readable target log lines (Fluent Bit tag ``blue.target_logs``)
into OCSF log events. Handles the process-wrapper lifecycle envelope, JSON
application logs, and plain lines — a rewrite of the target-log branch of the
legacy receiver ``normalize()`` as a pluggable CoverageAdapter (redesign §3.2).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from autobot.coverage._common import hash_record, map_severity
from decepticon_core.types.ocsf_event import Metadata, OcsfEvent, SignalType


def _field(record: Mapping[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            return str(value)
    return None


class TargetLogCoverageAdapter:
    """Target log files (app logs + process wrapper) -> OCSF log events."""

    source_id = "target-log-file"
    signal_type = SignalType.LOG

    def claims(self, raw: Mapping[str, Any]) -> bool:
        return isinstance(raw.get("log"), str)

    def normalize(self, raw: Mapping[str, Any]) -> OcsfEvent:
        line = raw["log"]
        event_id = hash_record(dict(raw))
        meta = Metadata(
            source_id=self.source_id,
            sensor_file=raw.get("sensor_file"),
            sensor_offset=raw.get("sensor_offset"),
        )
        parsed: Any = None
        try:
            parsed = json.loads(line)
        except ValueError:
            parsed = None

        # Process-wrapper lifecycle/stdout envelope.
        if (
            isinstance(parsed, dict)
            and parsed.get("source") == "target-process"
            and isinstance(parsed.get("message"), str)
        ):
            meta.source_event_id = (
                parsed.get("event_id") if isinstance(parsed.get("event_id"), str) else None
            )
            app_msg = parsed["message"]
            event_type = (
                "process_lifecycle"
                if parsed.get("event_type") == "process_lifecycle"
                else "process_log"
            )
            return OcsfEvent(
                event_id=event_id,
                event_type=event_type,
                signal_type=SignalType.PROCESS,
                source=self.source_id,
                message=app_msg,
                attributes={
                    "pid": parsed.get("pid"),
                    "exit_code": parsed.get("exit_code"),
                    "stream": parsed.get("stream"),
                    "capture_run_id": parsed.get("capture_run_id"),
                },
                metadata=meta,
                raw_data=line,
            )

        # Structured JSON application log.
        if isinstance(parsed, dict):
            sev_text = _field(parsed, "severity_text", "severity", "level", "lvl")
            return OcsfEvent(
                event_id=event_id,
                event_type="application_log",
                signal_type=self.signal_type,
                source=self.source_id,
                severity_text=sev_text,
                severity_id=map_severity(sev_text),
                trace_id=_field(parsed, "trace_id", "traceId"),
                span_id=_field(parsed, "span_id", "spanId"),
                request_id=_field(parsed, "request_id", "requestId", "req_id"),
                message=_field(parsed, "message", "msg", "log") or line,
                attributes=parsed,
                metadata=meta,
                raw_data=line,
            )

        # Plain, unstructured line.
        return OcsfEvent(
            event_id=event_id,
            event_type="log_line",
            signal_type=self.signal_type,
            source=self.source_id,
            message=line,
            metadata=meta,
            raw_data=line,
        )

    def coverage_manifest(self) -> tuple[str, ...]:
        return ("T1059",)
