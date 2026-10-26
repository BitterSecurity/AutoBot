# AutoBot agent runtime — blue-only LangGraph server (Phase 2b-ii)

- Status: proposed (design review; implementation follows as separate PRs)
- Date: 2026-10-26
- Context: migration plan stage 2b-ii ([Decepticon design doc §0.3](https://github.com/BitterSecurity/Decepticon/blob/main/docs/design/2026-10-23-autobot-redesign.md))
- Phase 2b-i landed the sensor stack + detection package in this repo (PR #2)

## Goal

AutoBot stops borrowing a Decepticon LangGraph server. This repo ships its own
**blue-only agent server**: a `langgraph.json` + graph export + container that
hosts the blue_cell investigation agent, wired into the local sensor compose so
`BLUE_AGENT_URL` points at it by default. The monitor already speaks the
LangGraph Platform HTTP API and works with any server — the change is
ownership, not protocol.

## The dependency inventory (what blue_cell actually pulls from Decepticon)

The blue_cell agent construction today uses the Decepticon framework's
middleware-slot architecture (`decepticon_core.contracts.slots.SLOTS_PER_ROLE`).
blue_cell declares **10 slots**; each was assessed for the standalone port:

| Slot | Today | AutoBot decision | Rationale |
|---|---|---|---|
| UNTRUSTED_OUTPUT | Decepticon middleware (331 lines: quarantine ledger + injected system policy) | **PORT with tests** | The defender's core protection when reading untrusted telemetry. Ledger path moves to the AutoBot state dir. |
| PROMPT_INJECTION_SHIELD | Decepticon middleware (483 lines: deny-listed tool-output wrapping, dedup with UNTRUSTED_TOOL_NAMES) | **PORT with tests** | Same class of protection; ported together so the quarantine/shield interplay stays correct. |
| SUMMARIZATION | deepagents `create_summarization_middleware` | **USE** (third-party dep) | Already a library call, no Decepticon coupling. |
| PROMPT_CACHING | `AnthropicPromptCachingMiddleware` (provider-conditional) | **USE** (third-party dep) | Same. |
| PATCH_TOOL_CALLS | deepagents middleware | **USE** (third-party dep) | Same. |
| MODEL_FALLBACK | Decepticon router middleware | **REWRITE thin** | AutoBot's factory builds primary + fallback models directly; a small retry/fallback middleware (~60 lines) suffices without the Decepticon ModelRouter. |
| BUDGET | Decepticon BudgetEnforcementMiddleware (450 lines: engagement budgets, pause/resume) | **REWRITE thin** | AutoBot v1 needs a token/cost cap per run, not engagement budgeting (~80 lines). Escalate later with case management. |
| ROE_GUARDRAIL | Decepticon RoEGuardrailMiddleware (640 lines; evaluates plan/roe.json; audit-only when absent) | **DROP for v1** | Blue has no red rules-of-engagement file; in practice it runs audit-only for blue_cell. The structural safety guarantee for blue is the read-only tool set (no bash, no mutating tools). Revisit if AutoBot grows scoped-response actions (Phase 4 §8). |
| MODEL_OVERRIDE | Decepticon per-run override (TUI `/model` feature) | **DROP for v1** | Model selection is configuration (`AUTOBOT_MODEL` env), not a per-run TUI feature in the standalone server. |
| PROXY_KEY_OVERRIDE | Decepticon multi-tenant LiteLLM virtual-key swap | **DROP for v1** | OSS standalone has no multi-tenant cost attribution; revisit with the SaaS shape. |

**Port surface: ~815 lines of safety middleware + tests, carried with
attribution and their original test suites.** These two middlewares are the
defender's prompt-injection defenses — they move faithfully, not re-implemented
from memory, and their behavioral tests travel with them.

## LLM layer — AutoBot's own thin factory

Decepticon's LLMFactory (1784 lines) routes every model through the LiteLLM
proxy gateway with a credentials inventory, model profiles and a ModelRouter —
that is Decepticon's multi-tenant/multi-agent infrastructure, not something
blue needs.

AutoBot v1: a thin factory (~150 lines) that constructs ChatModels **directly
through the LiteLLM python SDK** (no proxy service):

- `AUTOBOT_MODEL` — primary model in LiteLLM format (e.g. `openai/gpt-4o`,
  `anthropic/claude-...`, `ollama/...`), keys via the provider's standard env
- `AUTOBOT_FALLBACK_MODELS` — ordered fallback list
- `AUTOBOT_TEMPERATURE` / per-role overrides later
- No proxy, no virtual keys, no credential inventory. Optional proxy support is
  a follow-up if standalone deployments want centralized keying.

This follows the design principle that AutoBot's intent-defining layers are
self-authored; the factory is small enough to own.

## Serving shape

```text
packages/autobot/autobot/agent/
  blue_cell.py          # graph export for langgraph serve (adapted construction)
  models.py             # thin LiteLLM factory
  middleware/
    untrusted_output.py # ported
    injection_shield.py # ported
    budget.py           # thin
    model_fallback.py   # thin
langgraph.json          # graphs: {blue_cell}, dependencies [./packages/autobot]
containers/langgraph.Dockerfile
examples/local-sensor/compose.yaml  # + autobot-agent service (BLUE_AGENT_URL default)
```

- `langgraph serve` boots the blue_cell graph; the monitor's
  `BLUE_AGENT_URL` defaults to the in-stack service
  (`http://autobot-agent:8000`), with the env override preserved for pointing
  at any other compatible server (including a Decepticon one during
  transition).
- The Decepticon TUI's blue **chat** keeps two paths per the migration
  guarantee (§0.5): `decepticon[blue]` installs this package and the
  Decepticon server **imports it** — the graph is discovered via the
  `decepticon.graphs` entry-point declared in `packages/autobot/pyproject.toml`
  (`blue_cell = "autobot.agent.blue_cell:graph"`; verified discoverable via
  importlib.metadata) — or the TUI points its blue agent base URL at the
  AutoBot server (routing detail finalized when the server ships).
- **Dependency direction is one-way**: autobot depends on `decepticon-core`
  (shared contracts, tier system, label validation) and NEVER on the
  Decepticon framework; Decepticon imports autobot through the extra. Shared
  LLM configuration travels the same direction — the gateway mode reads the
  Decepticon stack's LiteLLM proxy env, so the operator's LLM settings are
  configured once.
- The blue_cell system prompt (blue_cell.md) moves to AutoBot and is loaded by
  AutoBot's own prompt loader; Decepticon's copy stays until 2c.

## Security review checklist (implementation gates)

- The two ported middlewares carry their original behavioral tests plus the
  quarantine/shield interplay test; no behavior re-derivation from memory.
- Read-only guarantee is structural: the blue_cell tool set contains no bash
  and no mutating tools; the server exposes only the five read tools.
- The untrusted-data rule (treat telemetry as data, never instructions) is
  enforced by the ported shield/untrusted pair, not by prompt alone.
- New middleware (budget/model_fallback) get their own tests.
- The prompt-injection regression corpus: any logged injection attempt from
  the live verifications becomes a test case.

## Transition & rollout

1. Implement runtime + server in this repo (PRs: middleware port → factory →
   graph+server+compose wiring), each verified with the sensor-stack live
   harness (monitor watch/analysis/decision against the in-stack server).
2. `examples/local-sensor` compose flips `BLUE_AGENT_URL` default to the
   in-stack service; the Decepticon-server override remains documented.
3. Decepticon stage 2c (removal of in-tree blue_cell) proceeds only after the
   in-stack server passes the full harness — the TUI client guarantee (§0.5)
   is the acceptance bar.
