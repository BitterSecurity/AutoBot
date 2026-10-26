"""Shared helpers for coverage adapters — event id, severity, timestamps."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from decepticon_core.types.ocsf_event import SeverityId

# Severity strings a source might emit -> OCSF-normalized severity_id.
_SEVERITY_MAP: dict[str, SeverityId] = {
    "trace": SeverityId.INFORMATIONAL,
    "debug": SeverityId.INFORMATIONAL,
    "info": SeverityId.INFORMATIONAL,
    "information": SeverityId.INFORMATIONAL,
    "notice": SeverityId.LOW,
    "warn": SeverityId.LOW,
    "warning": SeverityId.LOW,
    "error": SeverityId.MEDIUM,
    "err": SeverityId.MEDIUM,
    "critical": SeverityId.HIGH,
    "crit": SeverityId.HIGH,
    "alert": SeverityId.CRITICAL,
    "emergency": SeverityId.CRITICAL,
    "fatal": SeverityId.FATAL,
}


def map_severity(text: str | None) -> SeverityId:
    if not text:
        return SeverityId.UNKNOWN
    return _SEVERITY_MAP.get(text.strip().lower(), SeverityId.UNKNOWN)


def stable_event_id(*parts: str) -> str:
    """Deterministic event id from stable parts (dedup key)."""
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def hash_record(raw: Any) -> str:
    """Deterministic id from the whole record (when no natural key exists)."""
    return hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def epoch_to_iso(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None
