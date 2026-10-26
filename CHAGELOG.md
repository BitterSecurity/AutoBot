# AutoBot version history

## Unreleased

- Proposed client compatibility fix ([#14](https://github.com/BitterSecurity/AutoBot/pull/14)): declare AutoBot's observation purpose via
  its installed role entry point, so clients do not require an attack scope for
  its read-only investigation graph. AutoBot retains its own middleware and
  sensor-only tools. Unknown roles keep the shared core's execution default.
  No package version or release is claimed by this source change.
