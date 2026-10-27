# AutoBot version history

## Unreleased

- Proposed Blue Cell matcher performance fix (PR pending): precompile detection
  rule patterns and conditions once in `RuleMatcher`, instead of recompiling
  every regex and re-parsing every condition on each tap event. The per-event
  `match()` hot loop now does no `re.compile`/`eval` work. Behavior is
  unchanged (characterization tests added); ~2x faster on the 10-rule sample,
  scaling with rule count × patterns-per-rule. No package version or release is
  claimed by this source change.
- Proposed client compatibility fix ([#14](https://github.com/BitterSecurity/AutoBot/pull/14)): declare AutoBot's observation purpose via
  its installed role entry point, so clients do not require an attack scope for
  its read-only investigation graph. AutoBot retains its own middleware and
  sensor-only tools. Unknown roles keep the shared core's execution default.
  No package version or release is claimed by this source change.
