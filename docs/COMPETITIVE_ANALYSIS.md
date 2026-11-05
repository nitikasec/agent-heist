# Agent Heist — Competitive Analysis

*Researched 5 Nov 2026. Figures are from each project's GitHub repo / docs on that date and may change.
Star counts via the GitHub API; verify before quoting. No competitor weakness here is invented — where a
claim could not be verified from the actual repo, it is marked "unverified".*

## TL;DR (the honest version)

Agent Heist is **not** the most comprehensive AI-security lab, and should not claim to be.
[AIGoat](https://github.com/AISecurityConsortium/AIGoat) is broader (46 labs vs our 5, plus a web UI and
full OWASP mapping). Pure model-evaluation tools like [garak](https://github.com/NVIDIA/garak) and
research benchmarks like [AgentDojo](https://github.com/ethz-spylab/agentdojo) are deeper at what they do.

Agent Heist's defensible edge is **verification depth**, not breadth:

1. **Every level ships a tested secure fix**, and the *same* attack is replayed against it (`--compare`),
   with the fix enforced in the server, not the prompt.
2. **A reproducible, cross-model scoreboard is built into the teaching lab** (`bench --runs --report`).
3. It is **lightweight and trustworthy**: pure Python, no Docker, 391 offline tests, free to run.

The strategy that follows from this: **don't race AIGoat on lab count. Win on "deeper attack
visibility, stronger defence verification, more trustworthy model evaluation"** — which is exactly the
brief's own stated vision.

## The landscape

Four categories, because they are not all the same kind of thing:

| Category | Projects | What it is |
|---|---|---|
| **Teaching labs (CTF-style)** | AIGoat, OWASP PwnzzAI, DVMCP (harishsg), **Agent Heist** | You attack a deliberately broken target to learn |
| **Model-eval / red-team tooling** | NVIDIA garak, Microsoft PyRIT, spikee, rebuff | Scan or red-team a model/app you point it at |
| **Research benchmarks** | AgentDojo, InjecAgent | Fixed task suites to measure attack/defence in papers |
| **Standards / guidance** | OWASP LLM Top 10, OWASP Agentic, OWASP MCP Top 10 | The documents the labs map to |

Agent Heist lives in the first category but borrows from the second (its scoreboard). That blend is
unusual and is where its differentiation sits.

## Direct competitors — verified facts + sources

### AIGoat — the real competitor
[github.com/AISecurityConsortium/AIGoat](https://github.com/AISecurityConsortium/AIGoat) · ★265 · Apache-2.0 · Python · active (pushed Oct 2026)
- **46 hands-on labs** mapped to OWASP LLM Top 10 (2026), Agentic Top 10 (2026) and MCP Top 10 (2025 beta);
  **9 CTF challenges** with runtime-generated flags; an "Agentic Kill Chain" capstone.
- **3 progressive defense levels** on each surface (chat/RAG/agent/MCP), up to NVIDIA NeMo Guardrails.
- Runs locally on **Ollama, free, no API keys**; has a **web UI**; includes **RAG poisoning** and **MCP** labs.
- **Honest takeaway:** broader, more polished, and better OWASP-mapped than Agent Heist today. We will not
  out-breadth it. (Its per-model *reproducible* benchmarking and its "is the fix enforced or did the model
  just refuse?" rigor are **unverified** — a likely gap we can own.)

### DVMCP (harishsg993010) — the name collision
[github.com/harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) · ★1365 · **no license** · Python
- ~15 challenges across easy/medium/hard/identity/supply_chain. MCP-focused; **you bring your own client**
  — there is no agent in the loop, no secure/fixed version, no model scoreboard.
- **No license = all rights reserved**: do not copy any of its code. (This is why we renamed from
  "Damn Vulnerable MCP" to Agent Heist.)

### OWASP PwnzzAI
[github.com/OWASP/PwnzzAI](https://github.com/OWASP/PwnzzAI) · ★78 · GPL-3.0 · HTML/Docker
- A deliberately vulnerable "pizza shop" web app for the OWASP LLM Top 10. Docker-based, web UI.
- Web-app-centric; not MCP/agent-tool focused; no cross-model benchmarking.

### OWASP GenAI Red Team Lab (the closest thing to "GenAI Security Lab")
[github.com/GenAI-Security-Project/GenAI-Red-Team-Lab](https://github.com/GenAI-Security-Project/GenAI-Red-Team-Lab)
- A local LLM sandbox plus example attack scripts for garak/promptfoo and an agentic example. More a
  starter kit than a structured CTF.

## Model-eval / red-team tooling (adjacent, not labs)

| Tool | Repo | ★ | License | What it is / relevance |
|---|---|---|---|---|
| NVIDIA garak | [NVIDIA/garak](https://github.com/NVIDIA/garak) | 9861 | Apache-2.0 | LLM vuln *scanner* (probes/generators/detectors), 50+ probes. "nmap for LLMs." Not a teaching lab; no MCP-agent scenarios. Our scoreboard is tiny beside it — we should **cite/interoperate**, not compete. |
| Microsoft PyRIT | [Azure/PyRIT](https://github.com/Azure/PyRIT) | (verify) | MIT | Red-teaming *orchestration* framework. Not a lab. |
| spikee | [ReversecLabs/spikee](https://github.com/ReversecLabs/spikee) | ~261 | Apache-2.0 | Prompt-injection testing toolkit for apps/guardrails. Not a lab. |
| rebuff | [protectai/rebuff](https://github.com/protectai/rebuff) | 1531 | Apache-2.0 | Prompt-injection *detection* library (a defense). Last pushed 2024. |

## Research benchmarks (adjacent)

- **AgentDojo** — [ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) · ★990 · MIT. Stateful
  environments to evaluate prompt-injection attacks/defences for tool-using agents; extensible; a leaderboard.
  The gold standard for *measuring* agent prompt-injection. Not a teaching CTF, no MCP, no "fix it yourself."
- **InjecAgent** — [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) · ★185 · MIT.
  1,054 test cases for indirect prompt injection in tool-integrated agents. A static benchmark.

## "FreakLabs"
No AI-security lab by that exact name could be verified. "FreakLabs" is a wireless/hardware-hacking group,
unrelated. The likely intended reference is **spikee** (prompt-injection toolkit, above) or the OWASP GenAI
Red Team Lab. Flagged honestly rather than guessed.

## Coverage matrix (Agent Heist today vs the field)

✔ = solid, ◑ = partial, ✗ = absent, ? = unverified for that project.

| Capability | Agent Heist | AIGoat | DVMCP | garak | AgentDojo |
|---|---|---|---|---|---|
| Prompt injection | ◑ (L1 identity) | ✔ | ✔ | ✔ | ✔ |
| Indirect prompt injection | ✔ (L2) | ✔ | ✔ | ◑ | ✔ |
| Tool poisoning (MCP) | ✔ (L5) | ✔ | ✔ | ✗ | ✗ |
| Tool-permission / confused deputy | ✔ (L3, L4) | ✔ | ✔ | ✗ | ◑ |
| Credential abuse / token passthrough | ✔ (L3) | ? | ✔ | ✗ | ✗ |
| RAG / retrieval poisoning | ✗ | ✔ | ✗ | ◑ | ✗ |
| Memory poisoning | ✗ | ? | ✗ | ✗ | ✗ |
| Rug-pull (dynamic tool change) | ✗ | ? | ✔ (supply_chain) | ✗ | ✗ |
| Multi-agent attacks | ✗ | ◑ | ✗ | ✗ | ✗ |
| **Tested secure fix per scenario** | **✔** | ◑ (defense levels) | ✗ | ✗ | ◑ (defences) |
| **Same-attack replay vs fix (`--compare`)** | **✔** | ? | ✗ | ✗ | ◑ |
| **Cross-model reproducible scoreboard** | **✔** | ? | ✗ | ✔ (scanner) | ✔ (benchmark) |
| Refusal-vs-enforcement distinction | ◑ | ? | ✗ | ✗ | ◑ |
| Execution trace / forensics | ◑ (tool-call log) | ? | ✗ | ◑ (report) | ✔ (logs) |
| OWASP Top-10 explicit mapping | ✗ (doc missing) | ✔ | ◑ | ◑ | ◑ |
| Web UI | ✗ | ✔ | ✗ | ✗ | ◑ |
| Runs free, no Docker | ✔ | ✔ (Ollama) | ◑ | ✔ | ✔ |
| Automated tests | ✔ (391) | ? | ✗ | ✔ | ✔ |

## Where Agent Heist genuinely leads (defend these)
1. **Tested fix + identical-attack replay in one command.** Few labs *prove* the fix stops the *same*
   attack; we do, in code, with 391 tests behind it.
2. **"The model refused" ≠ "the system is secure."** Our fixes are enforced server-side; the scoreboard
   can make this distinction explicit. This is a sophisticated, honest angle most labs blur.
3. **A reproducible cross-model scoreboard inside a teaching lab.** garak/AgentDojo evaluate; AIGoat
   teaches; we do both, reproducibly, for free.
4. **Lightweight and auditable.** Pure Python, offline tests, no Docker — easy to trust and contribute to.

## Where Agent Heist is behind (fix these, in priority order)
1. **Attack visibility.** No structured execution trace yet (request → injected content → tool calls →
   permission decisions → data → outcome). This is our clearest high-value gap.
2. **Benchmark rigor.** Scoreboard lacks reproducible config, model-version/timestamp capture, and an
   explicit refusal-vs-enforcement metric.
3. **Coverage gaps that matter:** RAG/retrieval poisoning, rug-pull, memory/persistent injection.
4. **OWASP mapping + learning objectives** are not documented.
5. **No web UI** (acceptable for now — see roadmap; depth beats a UI race with AIGoat).

Full prioritized plan: [AGENT_HEIST_MASTER_ROADMAP.md](AGENT_HEIST_MASTER_ROADMAP.md).
