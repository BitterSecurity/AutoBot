"""HTTP ingress proxy coverage adapter.

Normalizes Caddy access records (forwarded by Fluent Bit, tag ``blue.http``)
into OCSF ``http_access`` events. Rewrite of the proxy branch of the legacy
receiver ``normalize()`` as a pluggable CoverageAdapter (redesign §3.2).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from autobot.coverage._common import (
    epoch_to_iso,
    hash_record,
    stable_event_id,
)
from decepticon_core.types.ocsf_event import Metadata, OcsfEvent, SignalType

_PROXY_LOG_PREFIX = os.environ.get("BLUE_PROXY_LOG_PREFIX", "/sensor-logs/access")
_TARGET_ID = os.environ.get("BLUE_TARGET_ID", "local-web")


class ProxyCoverageAdapter:
    """Caddy HTTP ingress access logs -> OCSF http_access events."""

    source_id = "blue-ingress-proxy"
    signal_type = SignalType.HTTP

    def claims(self, raw: Mapping[str, Any]) -> bool:
        sensor_file = raw.get("sensor_file")
        return (
            isinstance(sensor_file, str)
            and sensor_file.startswith(_PROXY_LOG_PREFIX)
            and isinstance(raw.get("request"), dict)
            and isinstance(raw.get("path"), str)
        )

    def normalize(self, raw: Mapping[str, Any]) -> OcsfEvent:
        request = raw.get("request") or {}
        request_id = raw.get("blue_request_id")
        if isinstance(request_id, str):
            event_id = stable_event_id(_TARGET_ID, "http", request_id)
        else:
            event_id = hash_record(dict(raw))
            request_id = None
        client_ip = request.get("client_ip") or request.get("remote_ip")
        method = request.get("method")
        path = raw.get("path")
        status = raw.get("status")
        return OcsfEvent(
            event_id=event_id,
            event_type="http_access",
            signal_type=self.signal_type,
            source=self.source_id,
            occurred_at=epoch_to_iso(raw.get("ts")),
            request_id=request_id,
            src_ip=str(client_ip) if client_ip is not None else None,
            device_host=request.get("host"),
            message=f"{method} {path} -> {status}" if method else str(path),
            attributes={
                "method": method,
                "path": path,
                "uri": request.get("uri"),
                "status": status,
                "protocol": request.get("proto"),
                "duration_seconds": raw.get("duration"),
                "request_bytes": raw.get("bytes_read"),
                "response_bytes": raw.get("size"),
                "request_headers": request.get("headers"),
                "response_headers": raw.get("resp_headers"),
                "request_body_ref": raw.get("blue_body_ref"),
                "request_body_sha256": raw.get("blue_body_sha256"),
            },
            metadata=Metadata(
                product_name="caddy",
                source_id=self.source_id,
                sensor_file=raw.get("sensor_file"),
                sensor_offset=raw.get("sensor_offset"),
            ),
            raw_data=json.dumps(dict(raw), separators=(",", ":"), default=str),
        )

    def coverage_manifest(self) -> tuple[str, ...]:
        # Web ingress visibility — initial-access / web-exploit surface.
        return ("T1190", "T1046")
