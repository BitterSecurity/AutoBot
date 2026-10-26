"""Creation-time Blue engagement configuration materialization.

Mirrors ``decepticon.roe_materialization`` for the Blue Cell: every surface
that creates engagements (MCP ``start_engagement``, the headless CLI, the TUI
adapter) writes the same enforced ``blue.json`` into a Blue-owned workspace
root, so the defensive configuration does not depend on how the engagement
was started and is never reachable by Red's workspace-scoped file tools.

The Blue root deliberately sits outside the Red engagement workspace:
Red's agents hold file access to ``~/.decepticon/workspace/<label>/``, and
Blue's observation scope, rules and sensor layout must not reach the
attacking agent by filesystem coincidence (they would contaminate Red's
reasoning and leak into client-facing Red reports by default). The
engagement label is the only shared element. Purple-team transparency, when
wanted, is deliberate logged disclosure — not filesystem reach.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from decepticon_core.utils.engagement_scope import is_valid_engagement_label

CONFIG_FILENAME = "blue.json"
LOCALHOST_HOSTNAMES = {"127.0.0.1", "localhost", "[::1]", "::1"}
SEVERITY_LEVELS = ("low", "medium", "high", "critical")


def blue_workspace(label: str) -> Path:
    """Resolve the Blue workspace directory for an engagement label.

    Mirrors ``roe_materialization.engagement_workspace`` (same label
    contract, same override pattern) but roots at ``~/.decepticon/blue/``
    instead of the Red workspace root. An absolute ``DECEPTICON_BLUE_WORKSPACE``
    replaces the whole root; the label is never joined when invalid.
    """
    if not is_valid_engagement_label(label):
        raise ValueError(
            f"invalid engagement label {label!r}; must match "
            "[A-Za-z0-9][A-Za-z0-9._-]{0,127} (no path separators or '..')"
        )
    override = os.environ.get("DECEPTICON_BLUE_WORKSPACE", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".decepticon" / "blue" / label


def config_path(label: str) -> Path:
    return blue_workspace(label) / CONFIG_FILENAME


def _parse_upstream(raw: str) -> str:
    """Validate and normalize a Blue target upstream (localhost-only).

    Same contract the TUI's ``/blue up`` enforces: localhost, 127.0.0.1 or
    [::1] with an explicit port, http(s), no credentials, root path, no
    query or fragment. Returns the origin string for compose consumption.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("target upstream must be a non-empty string")
    candidate = raw.strip() if "://" in raw else f"http://{raw.strip()}"
    try:
        parts = urlsplit(candidate)
    except ValueError as error:
        raise ValueError(f"invalid target upstream {raw!r}: {error}") from error
    if parts.scheme not in ("http", "https"):
        raise ValueError("target upstream must use http or https")
    if parts.hostname not in LOCALHOST_HOSTNAMES:
        raise ValueError(
            f"target upstream {raw!r} must be a local service "
            "(localhost, 127.0.0.1 or [::1]) in this OSS workflow"
        )
    if not parts.port:
        raise ValueError("target upstream needs an explicit port (e.g. 127.0.0.1:3000)")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("target upstream must not carry credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise ValueError("target upstream must be a bare origin (no path)")
    host = parts.hostname
    if parts.hostname == "::1":
        host = "[::1]"
    return f"{parts.scheme}://{host}:{parts.port}"


def _load_file_rules(path: Path) -> list[dict]:
    """Strictly parse a detection rule file (fail-closed).

    Same format contract as the Blue monitor's loader
    (``examples/blue-local-sensor/blue_monitor.py``, PR #1103): jsonl where
    each line is a bootstrap ``{"id", "level"?, "match": {field: pattern}}``
    or a ``{"selections": {...}, "condition": "..."}`` rule; ``re:`` prefixes
    a case-insensitive regex, otherwise the value matches as a substring.
    The monitor stays dependency-free and keeps its own copy; this package
    twin exists so creation-time validation catches exactly what the monitor
    would reject at startup.
    """
    rules: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                rules.append(_rule_from_entry(json.loads(line)))
            except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error
    return rules


def _read_rules_file(path: Path) -> None:
    """Strictly validate that a rules file will satisfy the monitor loader."""
    if not path.is_file():
        raise ValueError(
            f"rules_file must be an existing jsonl file inside the Blue workspace: {path}"
        )
    try:
        _load_file_rules(path)
    except OSError as error:
        raise ValueError(f"{path}: cannot read rules file: {error}") from error


def _rule_from_entry(entry: object) -> dict:
    if not isinstance(entry, dict):
        raise ValueError("rule line must be a JSON object")
    if not isinstance(entry.get("id"), str) or not entry["id"].strip():
        raise ValueError("rule needs a non-empty string id")
    level = str(entry.get("level", "medium")).lower()
    if level not in SEVERITY_LEVELS:
        raise ValueError(f"rule {entry['id']}: level must be low, medium, high or critical")
    mitre = entry.get("mitre", [])
    if not isinstance(mitre, list):
        raise ValueError(f"rule {entry['id']}: mitre must be a list")
    match = entry.get("match")
    selections = entry.get("selections")
    if match is not None and selections is not None:
        raise ValueError(f"rule {entry['id']}: use either match or selections, not both")
    if match is not None:
        if not isinstance(match, dict) or not match:
            raise ValueError(f"rule {entry['id']}: match must be a non-empty object")
        return {
            "id": entry["id"],
            "level": level,
            "title": str(entry.get("title", entry["id"])),
            "mitre": tuple(str(item) for item in mitre),
            "selections": {"match": {str(name): str(raw) for name, raw in match.items()}},
            "condition": "match",
        }
    if not isinstance(selections, dict) or not selections:
        raise ValueError(f"rule {entry['id']}: selections must be a non-empty object")
    normalized: dict[str, dict[str, str]] = {}
    for name, fields in selections.items():
        if not isinstance(fields, dict) or not fields:
            raise ValueError(
                f"rule {entry['id']}: selection '{name}' must map field names to patterns"
            )
        normalized[str(name)] = {str(field_name): str(raw) for field_name, raw in fields.items()}
    condition = str(entry.get("condition", "")).strip() or " ".join(normalized)
    for token in condition.split():
        clean = token.strip("()")
        if clean.lower() in {"and", "or", "not"} and clean == token:
            continue
        if token in {"(", ")"}:
            continue
        if clean not in normalized:
            raise ValueError(
                f"rule {entry['id']}: condition references unknown selection '{clean}'"
            )
    return {
        "id": entry["id"],
        "level": level,
        "title": str(entry.get("title", entry["id"])),
        "mitre": tuple(str(item) for item in mitre),
        "selections": normalized,
        "condition": condition,
    }


def validate_blue_config(config: object, *, root: Path) -> dict:
    """Validate a decoded blue.json document against the v1 schema.

    Fail-closed: any schema, target, rule or watch error raises ValueError
    with a precise message. Returns the validated document unchanged.
    """
    if not isinstance(config, dict):
        raise ValueError("blue.json must be a JSON object")
    if config.get("version") != 1:
        raise ValueError("blue.json: version must be 1")
    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("blue.json: targets must be a non-empty list")
    enabled = 0
    seen_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("blue.json: each target must be an object")
        target_id = target.get("id")
        if not isinstance(target_id, str) or not is_valid_engagement_label(target_id):
            raise ValueError(
                f"blue.json: target id {target_id!r} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,127}}"
            )
        if target_id in seen_ids:
            raise ValueError(f"blue.json: duplicate target id '{target_id}'")
        seen_ids.add(target_id)
        target["upstream"] = _parse_upstream(target.get("upstream"))
        logs = target.get("logs", [])
        if not isinstance(logs, list):
            raise ValueError(f"blue.json: target '{target_id}' logs must be a list")
        for entry in logs:
            if not isinstance(entry, str) or not entry.startswith("/") or "\0" in entry:
                raise ValueError(f"blue.json: target '{target_id}' logs need absolute host paths")
        enabled_flag = target.get("enabled", True)
        if not isinstance(enabled_flag, bool):
            raise ValueError(f"blue.json: target '{target_id}' enabled must be a boolean")
        target["enabled"] = enabled_flag
        if enabled_flag:
            enabled += 1
        if len(logs) > 1:
            raise ValueError(
                f"blue.json: target '{target_id}' carries multiple log dirs; "
                "the local sensor supports one in this phase"
            )
    if enabled != 1:
        raise ValueError(
            f"blue.json: exactly one enabled target is required in this phase (found {enabled})"
        )
    rules_file = config.get("rules_file")
    if rules_file is not None:
        if not isinstance(rules_file, str) or not rules_file.strip():
            raise ValueError("blue.json: rules_file must be a non-empty relative path")
        candidate = (root / rules_file).resolve()
        if not candidate.is_relative_to(root.resolve()):
            raise ValueError("blue.json: rules_file must stay inside the Blue workspace")
        _read_rules_file(candidate)
    watch = config.get("watch", {})
    if not isinstance(watch, dict):
        raise ValueError("blue.json: watch must be an object")
    for key in ("interval_seconds", "batch_size"):
        value = watch.get(key)
        if value is not None and (not isinstance(value, (int, float)) or value <= 0):
            raise ValueError(f"blue.json: watch.{key} must be a positive number")
    allowed = {"version", "targets", "rules_file", "watch"}
    unknown = set(config) - allowed
    if unknown:
        raise ValueError(f"blue.json: unknown keys {sorted(unknown)}")
    return config


def build_local_target_config(
    upstream: str,
    logs: list[str] | None = None,
    rules_file: str | None = None,
    watch: dict | None = None,
) -> dict:
    """Build a v1 single-target blue.json document from creation inputs.

    Shared by every engagement-creation surface (headless CLI, MCP bridge) so
    they all materialize the same reviewed configuration shape.
    """
    target: dict = {"id": "local-target", "upstream": upstream, "enabled": True}
    if logs:
        target["logs"] = list(logs)
    config: dict = {"version": 1, "targets": [target]}
    if rules_file:
        config["rules_file"] = rules_file
    if watch:
        config["watch"] = watch
    return config


def materialize_blue_config(label: str, config: object) -> Path:
    """Validate and write blue.json into the Blue workspace, fail-closed.

    An already-present file is never overwritten — a reviewed configuration
    wins, exactly like ``plan/roe.json``. Returns the destination path.
    """
    destination = config_path(label)
    if destination.is_symlink():
        raise ValueError(f"{destination} must not be a symlink.")
    if destination.exists():
        return destination  # never overwrite a reviewed configuration
    root = blue_workspace(label)
    validate_blue_config(config, root=root)
    root.mkdir(parents=True, exist_ok=True)
    # The engagement compose overlay bind-mounts this root read-only into the
    # monitor container (user "blue", uid 10001), so the directory must be
    # traversable on the host and the detection-rule files world-readable —
    # they carry patterns, not secrets. blue.json itself stays private
    # (0o600): it is operator configuration and the container never reads it.
    root.chmod(0o755)
    payload = json.dumps(config, indent=2, ensure_ascii=False).encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=root, prefix=".blue-", delete=False) as staged:
        staged_path = Path(staged.name)
        try:
            staged.write(payload)
            staged.flush()
            os.fsync(staged.fileno())
            os.chmod(staged_path, 0o600)
            os.replace(staged_path, destination)
        except BaseException:
            staged_path.unlink(missing_ok=True)
            raise
    return destination


def load_blue_config(label: str) -> tuple[dict, Path]:
    """Load and validate blue.json for consumption (fail-closed)."""
    destination = config_path(label)
    if not destination.exists():
        raise FileNotFoundError(destination)
    try:
        config = json.loads(destination.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError(f"{destination}: {error}") from error
    validate_blue_config(config, root=blue_workspace(label))
    return config, destination


def resolve_target(config: dict, target_id: str | None = None) -> dict:
    """Pick the enabled target (or an exact id match) from a validated config."""
    for target in config["targets"]:
        if target_id is not None and target.get("id") == target_id:
            if not target.get("enabled", True):
                raise ValueError(f"target '{target_id}' is disabled in blue.json")
            return target
    if target_id is not None:
        raise ValueError(f"target '{target_id}' not found in blue.json")
    enabled = [target for target in config["targets"] if target.get("enabled", True)]
    if len(enabled) != 1:
        raise ValueError("blue.json must have exactly one enabled target")
    return enabled[0]


def compose_env(config: dict, target: dict, root: Path) -> dict[str, str]:
    """Map a validated config + target to the sensor compose environment.

    The sensor DB stays a named volume; the TUI namespaces the compose
    project by the engagement label, which isolates containers, volumes and
    networks per engagement without compose file changes. The Blue workspace
    is bind-mounted read-only into the monitor container at
    ``/blue-engagement`` via the engagement compose overlay, so
    ``BLUE_RULES_FILE`` is a container path into that mount.
    """
    env = {
        "BLUE_TARGET_UPSTREAM": target["upstream"],
        "BLUE_TARGET_ID": str(target["id"]),
        "BLUE_ENGAGEMENT_DIR": str(root),
    }
    logs = target.get("logs") or []
    if logs:
        env["BLUE_TARGET_LOG_DIR"] = logs[0]
    rules_file = config.get("rules_file")
    if rules_file:
        env["BLUE_RULES_FILE"] = f"/blue-engagement/{rules_file}"
    watch = config.get("watch") or {}
    if isinstance(watch.get("interval_seconds"), (int, float)):
        env["BLUE_WATCH_INTERVAL_SECONDS"] = str(watch["interval_seconds"])
    if isinstance(watch.get("batch_size"), int):
        env["BLUE_WATCH_BATCH_SIZE"] = str(watch["batch_size"])
    return env


__all__ = [
    "CONFIG_FILENAME",
    "build_local_target_config",
    "blue_workspace",
    "config_path",
    "validate_blue_config",
    "materialize_blue_config",
    "load_blue_config",
    "resolve_target",
    "compose_env",
    "_load_file_rules",
]
