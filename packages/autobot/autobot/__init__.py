"""AutoBot — the defensive SIEM layer (detect → investigate → respond).

Independent OSS SIEM building blocks: pluggable log coverage (``coverage``),
swappable event-store backends (``stores``), and detection engines
(``detection``). Normalizes every source to OCSF and lets the agent read all
events source-agnostically. See docs/design/2026-10-23-autobot-redesign.md.
"""
