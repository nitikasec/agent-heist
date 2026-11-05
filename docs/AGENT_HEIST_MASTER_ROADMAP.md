# Agent Heist — Master Roadmap

*Companion to [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md). Written 5 Nov 2026.*

## Strategy in one sentence

Agent Heist wins on **verification depth** — deeper attack visibility, stronger defence verification,
more trustworthy model evaluation — **not on lab count**. Every item below serves that, and nothing
removes existing levels, the scoreboard, `--compare` or `--report`.

## Current state (verified 5 Nov 2026)

- `main` @ `6777a9d`; PRs #1–#5 all merged; no open PRs.
- 5 levels, each with a vulnerable + secure server; hints; local progress.
- Scoreboard (`bench`, `--runs`, `--compare`, `--report`); backend retries + concise errors.
- 391 passing tests; MIT; runs free (Groq free tier or local Ollama); offline test suite.
- ~5.4k LOC Python, no Docker.

## Design principles (keep the platform maintainable)

- **Additive, small, independent PRs.** One capability per PR, each with tests, no breaking changes.
- **Every level is two servers + one attack**: `levelNN_<name>.py` (vulnerable) and a secure counterpart,
  registered in `levels/__init__.py`, with a flag hash, 3-tier hint, a `solutions/levelNN.md`, and a
  `benchmarks.py` runner. This pattern already works; keep it.
- **Secrets are synthetic and redacted** from every trace and report. No real credential ever logged.
- **Prove it or don't ship it.** New defences must be verified by replaying the *same* attack in tests,
  and must distinguish "the model refused" from "the server enforced a boundary."
- **Free and offline-testable.** Tests never need a network or a key; live runs use free providers.

## Prioritised backlog (value × effort)

Ranked. Tiers = build order. Each is an independent PR.

### Tier 1 — the differentiators (build first)

**R1. Execution-trace forensics** — *high value, medium effort*
A structured, redacted trace of every attack run: user request → external/injected content → model
response → tool selected → tool arguments → permission decision → data accessed → final outcome.
JSON for machines, pretty for humans. Wire into `play` and `bench`.
*Why:* our clearest gap (COMPETITIVE_ANALYSIS §"behind" #1); the backbone for R2 and R3; "deeper attack
visibility" from the brief (§D). *Risk:* low — additive logging around the existing agent loop.

**R2. Attack-vs-defence v2** — *high value, medium effort* (depends on R1)
Extend `--compare` to: show the trace diff between vulnerable and fixed runs; name **which control**
blocked the attack (secret isolation / egress gate / authz check / pinned description); and explicitly
label **refusal vs enforcement** — never score a defence "passed" just because the model declined.
*Why:* the brief calls this "especially important" (§E); it is our most sophisticated, honest edge.

**R3. Benchmark engine v2** — *high value, medium effort* (depends on R1)
Reproducible runs: a config file (models, levels, runs, seed) + every report records model id, provider,
timestamp, run count, and — where the provider exposes them — latency and token/cost. Add aggregate
metrics: attack-success-rate, defence-success-rate, refusal-vs-enforcement. Append-only history for
`bench --compare-history`. *Why:* "more trustworthy model evaluation" (§C); turns the scoreboard into
citable research. *Guard:* never invent numbers; a missing metric is recorded as "n/a", not estimated.

### Tier 2 — credibility and coverage

**R4. OWASP mapping + learning layer** — *medium value, low effort*
A `docs/OWASP_MAPPING.md` tying each level to OWASP LLM Top 10 (2026), Agentic Top 10, and MCP Top 10.
Add `learning_objectives` to each level and a `agentheist report --level N` that emits a downloadable
per-level finding (attack, impact, root cause, fix) — plays directly to report-writing strength.
*Why:* closes the "no OWASP mapping" gap cheaply; every serious competitor maps to OWASP.

**R5. Level 6 — RAG / retrieval poisoning** — *medium value, medium effort*
A poisoned document in a knowledge base steers the agent (data exfil or action). Our biggest *content*
gap vs AIGoat. Vulnerable + secure (provenance/trust-tagging of retrieved context, egress gate).

**R6. Level 7 — Rug-pull (dynamic tool change)** — *medium value, medium effort*
A tool ships benign, gets trusted, then changes its description/behaviour on a later "update." Secure
ref pins and diffs tool metadata (hash-on-first-use). Pairs with L5; distinct from DVMCP's static
supply_chain challenge because our fix is tested.

**R7. Level 8 — Approval-bypass / insecure output handling** — *medium value, medium effort*
The human-approval prompt shows an attacker-controlled summary while the real tool call does something
else; or model output is rendered unsafely (markdown-image exfil). Secure ref binds the approval to the
exact call.

### Tier 3 — evaluate later, do not start yet

**R8. Web UI** — *high effort.* AIGoat already leads here; a UI race is the wrong fight now. Revisit only
after R1–R3 make the CLI/report experience best-in-class. Interim: ensure `--report` output is good
enough to publish as-is.

**R9. Authorised assessment of user-provided configs** (brief §G) — *high effort, high risk.* Could let
users point Agent Heist's attack suites at *their own* MCP server config to verify controls. Must be
strictly opt-in, local, authorised-only — never an unrestricted scanner against third parties. Design
only after R1–R3; it reuses R1 traces and R3 metrics.

**R10. Multi-agent attack scenario** — *high effort.* Cross-agent prompt injection / insecure delegation.
High realism but heavy to model well; defer until the single-agent core is deep.

## Explicitly rejected (for now)
- **Chasing AIGoat's 46-lab count.** Breadth without depth dilutes the differentiator.
- **Copying any competitor code.** DVMCP has no license; others are Apache/MIT but we build original
  scenarios regardless. Ideas (attack classes) are public; implementations are ours.
- **A hosted/shared leaderboard service.** Ops burden with no career payoff; local scoring is enough.

## Suggested PR sequence

1. **PR: R1 execution traces** (core + wire into play/bench; tests).
2. **PR: R2 compare v2** (control attribution + refusal-vs-enforcement; tests).
3. **PR: R3 benchmark v2** (reproducible config/report/history; tests).
4. **PR: R4 OWASP mapping + per-level reports** (docs + `report` command; tests).
5. **PR: R5 Level 6 RAG poisoning** (two servers + runner + solution + tests).
6. **PR: R6 Level 7 rug-pull**, then **R7 Level 8 approval-bypass**.

Each PR: run the full suite, keep all existing functionality, update the README and
`COMPETITIVE_ANALYSIS.md` coverage matrix. Re-verify competitor facts before quoting them publicly.

## What to tell people (positioning, honest)
> "Agent Heist is a free, open-source lab for AI-agent and MCP security. Unlike a scanner, it teaches by
> exploitation; unlike most labs, every attack ships a **tested** fix and a one-command replay that proves
> the fix works — and a cross-model scoreboard that separates *a model refusing* from *a system actually
> enforcing a boundary*."

Not: "the most comprehensive AI-security lab." That is AIGoat's claim to contest, and not our fight.
