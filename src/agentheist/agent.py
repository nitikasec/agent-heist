"""A minimal tool-using agent: Claude on one side, a level's MCP server on the other.

The agent itself is intentionally ordinary. The vulnerabilities live in how each
level wires prompts, tools and trust together, which is what real deployments get wrong.
"""

import os
from collections.abc import Callable
from typing import Any

import anthropic
from mcp import Client

DEFAULT_MODEL = "claude-opus-5-5"
# Models that accept server-side refusal fallbacks (`fallbacks: "default"`).
FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOOL_ROUNDS = 10


def mcp_tools_to_claude(tools: list[Any]) -> list[dict[str, Any]]:
    return [
        {"name": tool.name, "description": tool.description or "", "input_schema": tool.input_schema}
        for tool in tools
    ]


class Agent:
    """Holds one conversation with Claude, routing tool calls to an MCP client."""

    def __init__(
        self,
        mcp_client: Client,
        system_prompt: str,
        claude: anthropic.AsyncAnthropic | None = None,
        model: str | None = None,
        on_tool_call: Callable[[str, dict[str, Any], str], None] | None = None,
    ):
        self.mcp = mcp_client
        self.system_prompt = system_prompt
        self.claude = claude or anthropic.AsyncAnthropic()
        self.model = model or os.environ.get("AGENTHEIST_MODEL", DEFAULT_MODEL)
        self.on_tool_call = on_tool_call
        self.messages: list[dict[str, Any]] = []
        self._tools: list[dict[str, Any]] | None = None

    async def tools(self) -> list[dict[str, Any]]:
        if self._tools is None:
            self._tools = mcp_tools_to_claude((await self.mcp.list_tools()).tools)
        return self._tools

    async def _create(self) -> Any:
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 16000,
            "system": self.system_prompt,
            "tools": await self.tools(),
            "messages": self.messages,
            "output_config": {"effort": "low"},
        }
        if self.model in FALLBACK_MODELS:
            params["betas"] = [FALLBACK_BETA]
            params["fallbacks"] = "default"
        return await self.claude.beta.messages.create(**params)

    async def send(self, user_message: str) -> str:
        """Send one user message, run any tool calls, and return the agent's reply text."""
        self.messages.append({"role": "user", "content": user_message})

        for _ in range(MAX_TOOL_ROUNDS):
            response = await self._create()
            # Append the full content (including thinking blocks) so the history stays valid.
            self.messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "refusal":
                return "[The model declined to respond.]"
            if response.stop_reason != "tool_use":
                return "".join(block.text for block in response.content if block.type == "text")

            results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                output, is_error = await self._call_tool(block.name, block.input)
                if self.on_tool_call:
                    self.on_tool_call(block.name, block.input, output)
                results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": output, "is_error": is_error}
                )
            self.messages.append({"role": "user", "content": results})

        return "[Stopped: too many tool calls in one turn.]"

    async def _call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        try:
            result = await self.mcp.call_tool(name, arguments)
        except Exception as exc:  # report tool failures back to the model instead of crashing the chat
            return f"Tool error: {exc}", True
        text = "\n".join(item.text for item in result.content if getattr(item, "type", None) == "text")
        return text, bool(result.is_error)
