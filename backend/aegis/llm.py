"""LLM clients: live Ollama, recording wrapper, and deterministic replay.

All clients expose `chat(messages, tools) -> assistant_message_dict`, where the
returned dict follows Ollama's shape: {"role": "assistant", "content": str,
"tool_calls": [{"function": {"name": str, "arguments": dict}}]}.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

import httpx

Message = dict[str, Any]


class LLMClient(Protocol):
    def chat(self, messages: list[Message], tools: list[dict[str, Any]]) -> Message: ...


def request_key(messages: list[Message], tools: list[dict[str, Any]]) -> str:
    """Stable hash of a chat request, used to match recorded responses."""
    blob = json.dumps({"messages": messages, "tools": tools}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


class OllamaClient:
    def __init__(self, model: str, url: str, num_ctx: int = 8192, timeout_s: float = 300.0) -> None:
        self.model = model
        self.url = url.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout_s = timeout_s

    def chat(self, messages: list[Message], tools: list[dict[str, Any]]) -> Message:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "options": {"temperature": 0, "seed": 0, "num_ctx": self.num_ctx},
        }
        resp = httpx.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout_s)
        resp.raise_for_status()
        msg = resp.json()["message"]
        return {
            "role": "assistant",
            "content": msg.get("content", ""),
            "tool_calls": msg.get("tool_calls") or [],
        }


class RecordingClient:
    """Wraps a live client and records every request/response pair."""

    def __init__(self, inner: LLMClient) -> None:
        self.inner = inner
        self.records: list[dict[str, Any]] = []

    def chat(self, messages: list[Message], tools: list[dict[str, Any]]) -> Message:
        response = self.inner.chat(messages, tools)
        self.records.append({"key": request_key(messages, tools), "response": response})
        return response

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.records, indent=2), encoding="utf-8")


class ReplayClient:
    """Returns recorded responses. Matches by request hash, falls back to call order."""

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"No cassette recorded at {path}. Run the runner with --record first.")
        self.records: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        self.by_key = {r["key"]: r["response"] for r in self.records}
        self.index = 0

    def chat(self, messages: list[Message], tools: list[dict[str, Any]]) -> Message:
        key = request_key(messages, tools)
        response = self.by_key.get(key)
        if response is None:
            if self.index >= len(self.records):
                return {"role": "assistant", "content": "[replay exhausted]", "tool_calls": []}
            response = self.records[self.index]["response"]
        self.index += 1
        return response


class ScriptedClient:
    """Test double: returns a fixed list of responses in order."""

    def __init__(self, responses: list[Message]) -> None:
        self.responses = list(responses)
        self.calls: list[list[Message]] = []

    def chat(self, messages: list[Message], tools: list[dict[str, Any]]) -> Message:
        self.calls.append([dict(m) for m in messages])
        if not self.responses:
            return {"role": "assistant", "content": "done", "tool_calls": []}
        return self.responses.pop(0)


def tool_call(name: str, **arguments: Any) -> Message:
    """Helper to build a scripted assistant tool-call message."""
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": arguments}}]}


def final(text: str) -> Message:
    return {"role": "assistant", "content": text, "tool_calls": []}
