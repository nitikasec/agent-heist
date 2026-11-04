# Agent Heist

**A hands-on lab for AI-agent and MCP security.** Each level is a real Claude-powered agent wired to an
MCP tool server with a security mistake seen in real deployments. Break it, steal the flag, then read
how the fixed version stops you.

*Built by [Nitika Kumari](https://www.linkedin.com/in/nitika-k-62979833a/) ([@nitikasec](https://github.com/nitikasec)), offensive security.*

## What makes it different
- **A real agent loop, not just a vulnerable server.** You attack an LLM agent that plans and calls
  tools, and you see every tool call it makes.
- **Real threat models.** In Level 2 you never talk to the agent: you poison a web page, a victim's
  assistant reads it, and you win only if the secret actually reaches your server's log.
- **Every level ships with a fix, and tests that prove it.** The secure versions enforce controls in
  the tool server (authorization, secret isolation, egress control) rather than in the prompt, and the
  same attack is replayed against them in the test suite.
- **Offline and safe.** The "internet" is simulated. Nothing reaches the real network.

> ⚠️ Everything here is intentionally insecure. Run it locally for learning. Never deploy it.

## Prerequisites
- **Python 3.12+** and [**uv**](https://docs.astral.sh/uv/) (or Docker).
- An **Anthropic API key** (`ANTHROPIC_API_KEY`) to *play* a level — the agent calls the Claude API,
  so running levels **incurs API usage costs**. (The test suite runs **without** a key.)

## Quick start

```bash
# needs Python 3.12+ and uv (https://docs.astral.sh/uv/)
git clone https://github.com/nitikasec/agent-heist.git && cd agent-heist
uv sync
export ANTHROPIC_API_KEY=sk-ant-...

uv run agentheist list          # see levels and progress
uv run agentheist play 1        # chat with level 1's agent
uv run agentheist submit 1 'HEIST{...}'
uv run agentheist play 2        # attack a victim's agent through a web page you control
uv run agentheist hint 3        # stuck? tier 1 is a nudge, `hint 3 3` nearly gives it away
```

### Play for free
No paid API key needed. Any OpenAI-compatible endpoint works, hosted or local.

**Free hosted model (no download):** create a free key at [console.groq.com](https://console.groq.com), then:

```bash
export AGENTHEIST_PROVIDER=openai AGENTHEIST_BASE_URL=https://api.groq.com/openai/v1
export AGENTHEIST_MODEL=openai/gpt-oss-120b AGENTHEIST_API_KEY=gsk_...
uv run agentheist play 2
```

Levels 1–3 have been solved end to end with `openai/gpt-oss-120b` on Groq's free tier.

**Local model:** [Ollama](https://ollama.com), LM Studio, llama.cpp or vLLM.

```bash
ollama pull qwen3:4b
AGENTHEIST_PROVIDER=openai AGENTHEIST_MODEL=qwen3:4b uv run agentheist play 1
# other servers: set AGENTHEIST_BASE_URL (default http://localhost:11434/v1) and AGENTHEIST_API_KEY if needed
```

Small local models fall for some attacks more easily than Claude and resist others. Comparing them
is part of the fun. Pick a model that supports tool calling.

Or with Docker:

```bash
docker build -t agentheist .
docker run -it --rm -e ANTHROPIC_API_KEY agentheist play 1

# Level 2 needs a folder you can edit from the host (your attacker website):
docker run -it --rm -e ANTHROPIC_API_KEY -e AGENTHEIST_HOME=/lab -v "$HOME/.agentheist:/lab" agentheist play 2
```

The agent uses `claude-opus-5-5` by default. Set `AGENTHEIST_MODEL` to try another model
(for example `AGENTHEIST_MODEL=claude-haiku-5-5` for a cheaper run). Seeing how different models
hold up against the same attack is half the fun.

## Rules

1. Only talk to the agent. Don't read `src/agentheist/levels/`, which contains the flags.
2. Each flag looks like `HEIST{...}`.
3. Stuck? Write-ups live in `solutions/` (spoilers!).

## Levels

| # | Name | Attack class |
|---|------|--------------|
| 1 | The Trusting Helpdesk | Authorization delegated to the LLM |
| 2 | The Poisoned Page | Indirect prompt injection and data exfiltration (the "lethal trifecta") |
| 3 | The Helpful Integration | Token passthrough and credentials leaking through tool output |
| 4+ | coming soon | confused deputy, rug-pull tool updates, approval-prompt spoofing, SSRF... |

**Level 2 is different:** you don't chat with the agent. A simulated victim asks her assistant to
review a web page, and you write that page. Files you put in `~/.agentheist/level02/site/` are served at
`http://attacker.example/`, and every request the assistant makes to your site lands in
`~/.agentheist/level02/access.log`. You can't see the victim's conversation, only which tools ran and
your own server's log, so the only way to win is real exfiltration. The whole "internet" is
simulated and offline. Nothing reaches the real network.

Fixed versions:
- Level 1, with OAuth token verification and server-side authorization:
  [`src/agentheist/secure/README.md`](src/agentheist/secure/README.md).
- Level 2, with secret isolation, taint-based egress control and untrusted-content labeling:
  `src/agentheist/levels/level02_secure_research.py` (spoilers, read the write-up first).
- Level 3, with caller authentication, per-caller token exchange, server-side delegation and redaction:
  `src/agentheist/levels/level03_secure_billing.py` (spoilers).

## How it works

```
you  ──chat──▶  agent (Claude)  ──MCP tool calls──▶  level's MCP server (stdio)
```

`agentheist play N` starts level N's MCP server as a subprocess, connects a small agent loop to it
(`src/agentheist/agent.py`), and prints every tool call the agent makes so you can see what it's doing.

In victim levels (Level 2) the loop is:

```
you ──edit──▶ your page on attacker.example
victim ──"review this page"──▶ agent ──fetch_url──▶ your page (injection)
                                agent ──read_note──▶ private data
                                agent ──fetch_url──▶ attacker.example/?data=...  ──▶ your access log
```

## Development

```bash
uv run pytest
```

Tests run without an API key: they call the MCP servers directly and use a fake Claude client.

## Limitations & scope
- **Educational only.** This is a deliberately vulnerable teaching lab. **Do not deploy it in
  production or expose it to untrusted networks** — the vulnerable levels are insecure by design.
- **Implemented levels:** **Level 1, The Trusting Helpdesk** (with a hardened `secure/` reference)
  **Level 2, The Poisoned Page** and **Level 3, The Helpful Integration** (each with a secure reference
  server). Further attack classes (confused deputy, rug-pull tools, approval-prompt spoofing, SSRF) are
  **planned but not yet implemented**.
- **Playing needs a model:** an Anthropic API key (usage **costs money**) or a free local model
  through any OpenAI-compatible server. Tests need neither.
- **Not a scanner or benchmark.** It teaches AI-agent/MCP attack and defense patterns by example;
  it does not assess or score real systems.

## Credits and originality
All code, scenarios and write-ups in this repository are original work, released under the MIT
license. The attack classes themselves are public security knowledge. Terms and research it builds on:
- The "lethal trifecta" (private data + untrusted content + external communication): Simon Willison.
- OWASP Top 10 for LLM Applications (LLM01 prompt injection, LLM02 sensitive information disclosure,
  LLM06 excessive agency).
- The MCP specification's security best practices.

