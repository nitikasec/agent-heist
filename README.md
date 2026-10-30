# Damn Vulnerable MCP

A hackable lab of **deliberately broken AI agents**. Each level is a Claude-powered agent wired to an
MCP tool server with a real-world security mistake. Chat with the agent, exploit the mistake, capture the flag.

> ⚠️ Everything here is intentionally insecure. Run it locally for learning. Never deploy it.

## Quick start

```bash
# needs Python 3.12+ and uv (https://docs.astral.sh/uv/)
git clone <this repo> && cd damn-vulnerable-mcp
uv sync
export ANTHROPIC_API_KEY=sk-ant-...

uv run dvmcp list          # see levels and progress
uv run dvmcp play 1        # chat with level 1's agent
uv run dvmcp submit 1 'DVMCP{...}'
```

Or with Docker:

```bash
docker build -t dvmcp .
docker run -it --rm -e ANTHROPIC_API_KEY dvmcp play 1
```

The agent uses `claude-opus-5-5` by default. Set `DVMCP_MODEL` to try another model
(for example `DVMCP_MODEL=claude-haiku-5-5` for a cheaper run). Seeing how different models
hold up against the same attack is half the fun.

## Rules

1. Only talk to the agent. Don't read `src/dvmcp/levels/`, which contains the flags.
2. Each flag looks like `DVMCP{...}`.
3. Stuck? Write-ups live in `solutions/` (spoilers!).

## Levels

| # | Name | Attack class |
|---|------|--------------|
| 1 | The Trusting Helpdesk | Authorization delegated to the LLM |
| 2+ | coming soon | indirect prompt injection, tool poisoning, secret exfiltration, rug-pull tools... |

For the fixed version of Level 1, with OAuth token verification and server-side authorization,
see [`src/dvmcp/secure/README.md`](src/dvmcp/secure/README.md).

## How it works

```
you  ──chat──▶  agent (Claude)  ──MCP tool calls──▶  level's MCP server (stdio)
```

`dvmcp play N` starts level N's MCP server as a subprocess, connects a small agent loop to it
(`src/dvmcp/agent.py`), and prints every tool call the agent makes so you can see what it's doing.

## Development

```bash
uv run pytest
```

Tests run without an API key: they call the MCP servers directly and use a fake Claude client.
