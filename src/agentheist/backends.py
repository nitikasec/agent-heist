"""Model backends. Claude is the default; any OpenAI-compatible server works for free local play.

Set AGENTHEIST_PROVIDER=openai to use a local model (Ollama, LM Studio, llama.cpp, vLLM...):

    AGENTHEIST_PROVIDER=openai AGENTHEIST_MODEL=qwen3 agentheist play 1

The adapter speaks the small slice of the Claude Messages API that the agent uses, so the
agent loop doesn't care which backend it talks to. It needs only the standard library.
"""

import asyncio
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from types import SimpleNamespace
from typing import Any

import anthropic

DEFAULT_CLAUDE_MODEL = "claude-opus-5-5"
DEFAULT_LOCAL_MODEL = "llama3.1"
DEFAULT_LOCAL_URL = "http://localhost:11434/v1"
REQUEST_TIMEOUT_SECONDS = 300
USER_AGENT = "agent-heist/0.1 (+https://github.com/nitikasec/agent-heist)"
MAX_RETRIES = 2


def _retry_after(header: str | None) -> float:
    try:
        return min(10.0, max(1.0, float(header)))
    except (TypeError, ValueError):
        return 2.0


def _short_api_error(raw: str) -> str:
    try:
        err = json.loads(raw).get("error", {})
        code, msg = err.get("code", ""), err.get("message", "")
        return (f"{code}: {msg}" if code else msg)[:160]
    except (json.JSONDecodeError, AttributeError):
        return raw[:160]


class BackendError(Exception):
    """A local model server couldn't be reached or returned an error."""


def provider() -> str:
    return os.environ.get("AGENTHEIST_PROVIDER", "anthropic").strip().lower()


def default_model() -> str:
    fallback = DEFAULT_LOCAL_MODEL if provider() == "openai" else DEFAULT_CLAUDE_MODEL
    return os.environ.get("AGENTHEIST_MODEL", fallback)


def make_client() -> Any:
    if provider() == "openai":
        return OpenAICompatibleClient(
            os.environ.get("AGENTHEIST_BASE_URL", DEFAULT_LOCAL_URL), os.environ.get("AGENTHEIST_API_KEY", "")
        )
    return anthropic.AsyncAnthropic()


def to_openai_messages(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for message in messages:
        content = message["content"]
        if message["role"] == "user":
            if isinstance(content, str):
                out.append({"role": "user", "content": content})
                continue
            for block in content:
                if block.get("type") == "tool_result":
                    out.append({"role": "tool", "tool_call_id": block["tool_use_id"], "content": block["content"]})
            continue
        text = "".join(block.text for block in content if block.type == "text")
        calls = [
            {"id": b.id, "type": "function", "function": {"name": b.name, "arguments": json.dumps(b.input)}}
            for b in content
            if b.type == "tool_use"
        ]
        assistant: dict[str, Any] = {"role": "assistant", "content": text or None}
        if calls:
            assistant["tool_calls"] = calls
        out.append(assistant)
    return out


def to_openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
        for t in tools
    ]


def from_openai_response(data: dict[str, Any]) -> SimpleNamespace:
    message = data["choices"][0]["message"]
    blocks: list[SimpleNamespace] = []
    if message.get("content"):
        blocks.append(SimpleNamespace(type="text", text=message["content"]))
    for call in message.get("tool_calls") or []:
        try:
            arguments = json.loads(call["function"].get("arguments") or "{}")
        except json.JSONDecodeError:
            arguments = {}
        blocks.append(
            SimpleNamespace(
                type="tool_use", id=call.get("id") or f"call_{uuid.uuid4().hex[:12]}", name=call["function"]["name"], input=arguments
            )
        )
    stop_reason = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
    return SimpleNamespace(stop_reason=stop_reason, content=blocks)


class OpenAICompatibleClient:
    """Exposes `.beta.messages.create(**claude_params)` on top of /chat/completions."""

    def __init__(self, base_url: str, api_key: str = ""):
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **params: Any) -> SimpleNamespace:
        body = {
            "model": params["model"],
            "messages": to_openai_messages(params["system"], params["messages"]),
            "tools": to_openai_tools(params["tools"]),
        }
        data = await asyncio.to_thread(self._post, body)
        return from_openai_response(data)

    def _post(self, body: dict[str, Any], attempt: int = 0) -> dict[str, Any]:
        # Some hosted providers sit behind a firewall that rejects urllib's default User-Agent.
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            # Back off and retry on a rate limit, honoring Retry-After when given.
            if exc.code == 429 and attempt < MAX_RETRIES:
                time.sleep(_retry_after(exc.headers.get("Retry-After")))
                return self._post(body, attempt + 1)
            raise BackendError(f"HTTP {exc.code}: {_short_api_error(raw)}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise BackendError(f"Could not reach {self.url} ({exc}). Is your local model server running?") from exc
        except json.JSONDecodeError as exc:
            raise BackendError(f"{self.url} did not return JSON.") from exc
