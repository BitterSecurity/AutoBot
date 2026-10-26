"""BlueCellTap - normalize sandbox + target telemetry into a single stream.

The sandbox already pipes every tmux pane to ``<workspace>/.sessions/<name>.log``
(see ``decepticon/sandbox_kernel/tmux.py``). The Blue Cell agent
consumes that stream PLUS, when configured, target-side telemetry
collected by a sidecar daemon on each foothold (push to
``<workspace>/.sessions/_target/<host>.log``).

Each event is normalised into a ``TapEvent`` with:

  - ``ts``: best-effort timestamp (event's own ts when parseable;
    otherwise the line's read-time as a fallback).
  - ``source``: ``sandbox.tmux.<session>`` or ``target.<host>.<service>``.
  - ``actor_process``: extracted from the leading word of the line
    when it looks like a shell command, otherwise ``""``.
  - ``actor_command_line``: the full line, sanitized (ANSI stripped).
  - ``network_destinations``: best-effort extracted via the same regex
    catalog the RoE target extractor uses.
  - ``event_outcome``: ``"unknown"`` until the matcher classifies.
  - ``raw``: the original line for downstream tools.

The tap is INTENTIONALLY simple - it's a feeder, not a parser. Real
SIEM-grade enrichment (winlogbeat / Sysmon parsing) belongs in a
follow-up. The contract this module ships is: "produce a stream of
event dicts that any rule matcher can consume."
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from decepticon.middleware._command_targets import extract_targets

log = logging.getLogger(__name__)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][AB012]")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


_LEADING_CMD_RE = re.compile(r"^\s*\$\s*([\w./\-]+)|^([\w./\-]+)\s")
_TS_LEADING_RE = re.compile(
    r"^\s*"
    r"(?:\[)?"
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?)"
    r"(?:\])?"
)


@dataclass(frozen=True, slots=True)
class TapEvent:
    """One normalized event from the sandbox or a target."""

    ts: float
    source: str
    actor_process: str = ""
    actor_command_line: str = ""
    network_destinations: tuple[str, ...] = field(default_factory=tuple)
    event_outcome: str = "unknown"
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "source": self.source,
            "actor": {
                "process": self.actor_process,
                "command_line": self.actor_command_line,
            },
            "network": {
                "destinations": list(self.network_destinations),
            },
            "event": {
                "outcome": self.event_outcome,
            },
            "raw": self.raw,
        }


def _parse_line_to_event(line: str, source: str, fallback_ts: float) -> TapEvent | None:
    sanitised = _strip_ansi(line.rstrip())
    if not sanitised.strip():
        return None
    ts: float = fallback_ts
    m = _TS_LEADING_RE.match(sanitised)
    if m:
        try:
            from datetime import datetime

            stamp = m.group(1).replace("T", " ")
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            ts = parsed.timestamp()
        except (ValueError, AttributeError):
            # Malformed timestamps fall back to the file-mtime-derived
            # ts already assigned above. We never raise from the tap.
            pass
    cmd_match = _LEADING_CMD_RE.match(sanitised)
    actor_process = (cmd_match.group(1) or cmd_match.group(2) or "") if cmd_match else ""
    destinations: tuple[str, ...] = tuple(sorted(extract_targets(sanitised)))
    return TapEvent(
        ts=ts,
        source=source,
        actor_process=actor_process,
        actor_command_line=sanitised,
        network_destinations=destinations,
        event_outcome="unknown",
        raw=sanitised,
    )


class BlueCellTap:
    """Tails sandbox + target log files; yields normalised TapEvents.

    Operates in two modes:

      - **batch**: read all current content of every log file under
        ``<workspace>/.sessions/`` once. Useful for engagement
        post-processing.
      - **follow**: tail every log file forever (until ``stop()``).
        Each new line yields a ``TapEvent``. Useful for live Blue
        Cell evaluation during the engagement.
    """

    def __init__(self, workspace_path: str | Path) -> None:
        self.workspace_path = Path(workspace_path)
        self._stop = False
        self._offsets: dict[Path, int] = {}

    def stop(self) -> None:
        self._stop = True

    def _sessions_dir(self) -> Path:
        return self.workspace_path / ".sessions"

    def _target_dir(self) -> Path:
        return self.workspace_path / ".sessions" / "_target"

    def _iter_log_paths(self) -> Iterator[Path]:
        for base in (self._sessions_dir(), self._target_dir()):
            if not base.exists():
                continue
            for path in base.iterdir():
                if path.is_file() and path.suffix in {".log", ".jsonl"}:
                    yield path

    def _source_for(self, path: Path) -> str:
        if path.parent.name == "_target":
            return f"target.{path.stem}"
        return f"sandbox.tmux.{path.stem}"

    def read_batch(self) -> list[TapEvent]:
        """Read every log from offset 0 to current EOF. Resets offsets."""
        events: list[TapEvent] = []
        self._offsets = {}
        now = time.time()
        for path in self._iter_log_paths():
            source = self._source_for(path)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in content.splitlines():
                event = _parse_line_to_event(line, source, fallback_ts=now)
                if event:
                    events.append(event)
            self._offsets[path] = path.stat().st_size
        events.sort(key=lambda e: e.ts)
        return events

    def follow(self, poll_seconds: float = 1.0) -> Iterator[TapEvent]:
        """Tail every log file forever, yielding TapEvents as lines arrive.

        Yields a synthetic ``TapEvent`` with source=``"_meta.heartbeat"``
        every ``10 * poll_seconds`` so the consumer can detect a
        wedged feed.
        """
        self._stop = False
        last_heartbeat = time.time()
        heartbeat_interval = poll_seconds * 10
        while not self._stop:
            saw_event = False
            for path in self._iter_log_paths():
                offset = self._offsets.get(path, 0)
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size <= offset:
                    continue
                source = self._source_for(path)
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(offset)
                        for line in fh:
                            event = _parse_line_to_event(line, source, fallback_ts=time.time())
                            if event:
                                yield event
                                saw_event = True
                        self._offsets[path] = fh.tell()
                except OSError as exc:
                    log.warning("blue_cell.tap: failed to read %s: %s", path, exc)
                    continue
            now = time.time()
            if not saw_event and (now - last_heartbeat) >= heartbeat_interval:
                yield TapEvent(ts=now, source="_meta.heartbeat", raw="<heartbeat>")
                last_heartbeat = now
            time.sleep(poll_seconds)
