"""A native tool-calling loop for the steps where the model directs a search."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

TOOL_MODE_NOTE = (
    "\n\n## How to ask in this conversation\n"
    "Do not return JSON here. Ask through the tools, one question per call; the "
    "limits stated above still apply. Read every answer before the next call. "
    "When you have what you need — or nothing is worth asking — stop calling "
    "tools and reply with one short sentence. Give no verdict here."
)


def supports_tools(client: Any) -> bool:
    """True only for a client that declares native tool calls."""
    return getattr(client, "supports_tools", False) is True and callable(getattr(client, "chat_tools", None))


def function_tool(name: str, description: str, properties: dict[str, dict], required: list[str]) -> dict[str, Any]:
    """One tool definition in the shape both Ollama and chat-completions accept."""
    return {"type": "function", "function": {
        "name": name,
        "description": description,
        "parameters": {"type": "object", "required": required, "properties": properties},
    }}


@dataclass(slots=True)
class ToolLoop:
    """What one tool conversation cost and how it ended."""

    turns: list = field(default_factory=list)
    calls: int = 0
    error: str = ""


def run_tool_loop(
    client: Any,
    system: str,
    user: str,
    tools: list[dict[str, Any]],
    handlers: dict[str, Callable[[dict[str, Any]], str]],
    *,
    max_calls: int,
    max_turns: int,
) -> ToolLoop:
    """Hold one tool-calling conversation; the handlers do the work."""
    loop = ToolLoop()
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    offered = {tool["function"]["name"] for tool in tools}
    for _ in range(max(1, max_turns)):
        left = getattr(client, "budget_left_usd", None)
        if isinstance(left, (int, float)) and not isinstance(left, bool) and left <= 0:
            loop.error = "бюджет прогона исчерпан"
            break
        try:
            turn = client.chat_tools(messages, tools)
        except Exception as exc:  # noqa: BLE001 - the step keeps what it gathered
            loop.error = str(exc) or type(exc).__name__
            break
        loop.turns.append(turn)
        if not turn.tool_calls:
            break
        messages.append(turn.message)
        for call in turn.tool_calls:
            if loop.calls >= max_calls:
                content = "Not run: the limit of questions for this step is reached."
            elif call.name not in offered:
                content = f"Unknown tool {call.name!r}. Available: {', '.join(sorted(offered))}."
            else:
                loop.calls += 1
                log.info("model tool call: %s(%s)", call.name,
                         json.dumps(call.arguments or {}, ensure_ascii=False)[:300])
                try:
                    content = handlers[call.name](call.arguments or {})
                except Exception as exc:  # noqa: BLE001 - one bad call, not the conversation
                    log.debug("tool %s failed: %s", call.name, exc)
                    content = f"Not run: {type(exc).__name__}: {exc}"
            messages.append(client.tool_result_message(call, content))
        if loop.calls >= max_calls:
            break
    return loop
