# AutoBot

**Autonomous Defense Agent for Blue Team** — the defensive sibling of
[Decepticon](https://github.com/BitterSecurity/Decepticon) (red).

AutoBot is an OSS, agent-driven SIEM. It normalizes every log/telemetry source
to **OCSF**, stores events in a **swappable backend** (OpenSearch by default),
runs **Sigma** detections, and drives a **detect → investigate → respond** loop.
Log coverage is added as **independently-installable plugins**, and the agent
reads all events source-agnostically.

By design AutoBot depends only on the shared contract layer `decepticon-core`,
not the Decepticon framework — so a defender can `pip install autobot` and run
Blue without the offensive agent. Installed alongside Decepticon
(`pip install decepticon[blue]`), its event-store backends are discovered via
the `decepticon.event_stores` entry-point group. Cybertron composes red + blue
on top.

See `docs/design/2026-10-23-autobot-redesign.md` in the Decepticon repo for the
full architecture.

## Status

Phase 1 (contracts + substrate) in progress. Apache-2.0.

## Client admission metadata

The installed `bs-autobot` package contributes an `observation` role through
`decepticon.roles`, alongside its agent/subagent entry points. Clients can identify
the read-only investigator without treating it as an execution role requiring an
attack scope. AutoBot still owns its middleware and five read-only sensor tools;
this declaration does not grant mutation or execution capabilities. Unknown roles
retain the shared core's conservative execution default.
