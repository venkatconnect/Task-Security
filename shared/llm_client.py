"""Ollama client wrapper — replaces Anthropic SDK.

Ollama serves a local LLM via HTTP. This wrapper handles:
  - Text generation (for both vulnerable and mitigated paths)
  - Tool-use simulation: we ask the model to return JSON, then parse it
  - Response formatting to match our internal LLMResponse dataclass
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama2")


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[dict[str, Any]]
    stop_reason: str
    raw: Any


def _check_ollama() -> None:
    """Verify Ollama is running."""
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
        resp.raise_for_status()
    except Exception as e:
        raise RuntimeError(
            f"Cannot connect to Ollama at {OLLAMA_BASE_URL}. "
            f"Make sure Ollama is running: ollama serve\n{e}"
        )


def call(
    system: str | list[dict],
    messages: list[dict],
    tools: list[dict] | None = None,
    model: str | None = None,
    max_tokens: int = 1024,
) -> LLMResponse:
    """Call Ollama and return an LLMResponse.

    For tool-use: if tools are provided, we inject them into the system prompt
    and ask the model to return tool calls as JSON. The response text will
    contain a JSON block like:
      ```json
      {"tool_calls": [{"name": "...", "input": {...}}]}
      ```
    We parse it and split the actual text from the tool-calls metadata.
    """
    _check_ollama()

    m = model or OLLAMA_MODEL

    # Flatten system prompt (Ollama doesn't understand cache_control blocks).
    if isinstance(system, list):
        sys_text = "\n".join(
            item.get("text", "") for item in system if item.get("type") == "text"
        )
    else:
        sys_text = system

    # If we have tools, add them to the system prompt and ask for JSON.
    if tools:
        tool_desc = json.dumps(tools, indent=2)
        sys_text += (
            "\n\nWhen you need to use a tool, respond with a JSON block "
            "containing the tool calls:\n"
            "```json\n"
            '{"tool_calls": [{"id": "unique-id", "name": "tool_name", "input": {...}}]}\n'
            "```\n\n"
            f"Available tools:\n{tool_desc}"
        )

    # Build the messages for Ollama.
    ollama_messages = [{"role": "system", "content": sys_text}]
    for msg in messages:
        role = msg.get("role", "user")
        if isinstance(msg.get("content"), list):
            # Tool results come as a list of dicts; flatten to text.
            content_parts = []
            for item in msg["content"]:
                if item.get("type") == "tool_result":
                    content_parts.append(f"Tool {item.get('tool_use_id')}: {item.get('content')}")
                elif isinstance(item, str):
                    content_parts.append(item)
            content = "\n".join(content_parts)
        else:
            content = msg.get("content", "")
        ollama_messages.append({"role": role, "content": content})

    # Call Ollama.
    resp = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json={
            "model": m,
            "messages": ollama_messages,
            "stream": False,
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()

    text = data.get("message", {}).get("content", "")

    # Try to extract tool calls from the response, but keep full text for message loop.
    tool_calls: list[dict[str, Any]] = []
    if tools and "```json" in text:
        try:
            # Extract JSON block without removing it from text (needed for message loop).
            json_start = text.index("```json") + 7
            json_end = text.index("```", json_start)
            json_str = text[json_start:json_end].strip()
            parsed = json.loads(json_str)
            tool_calls = parsed.get("tool_calls", [])
            # Assign IDs if missing.
            for i, tc in enumerate(tool_calls):
                if "id" not in tc:
                    tc["id"] = f"call_{i}"
        except (ValueError, json.JSONDecodeError, IndexError):
            pass  # No valid JSON found, treat as plain text.

    return LLMResponse(
        text=text.strip(),
        tool_calls=tool_calls,
        stop_reason="end_turn",
        raw=data,
    )


def cached_system(text: str) -> str:
    """No-op wrapper for compatibility.

    Ollama doesn't support prompt caching, so this just returns the text as-is.
    """
    return text
