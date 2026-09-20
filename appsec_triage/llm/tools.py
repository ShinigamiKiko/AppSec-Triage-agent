"""A native tool-calling loop for the steps where the model directs a search."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

TOOL_MODE_NOTE = (
    "\n\n## How to ask in this conversation\n"
    "Do not return JSON here. Ask through the tools. You may ask up to 2 independent "
    "questions in one turn — they will be answered in parallel. Read every answer "
    "before the next call. When you have what you need — or nothing is worth asking — "
    "stop calling tools and reply with one short sentence. Give no verdict here."
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
    parallel_limit: int = 2,
    finding_id: str = "",
) -> ToolLoop:
    """Hold one tool-calling conversation; the handlers do the work.
    
    Args:
        parallel_limit: Maximum number of independent tool calls to execute in parallel per turn.
        finding_id: Optional finding identifier for logging context.
    """
    parallel_limit = max(1, parallel_limit)
    loop = ToolLoop()
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    offered = {tool["function"]["name"] for tool in tools}
    log_prefix = f"[{finding_id}] " if finding_id else ""
    for turn_idx in range(max(1, max_turns)):
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
        
        # Execute tool calls: up to parallel_limit in parallel, rest sequentially
        call_results: list[tuple[Any, str]] = []  # (call, content)
        
        for batch_start in range(0, len(turn.tool_calls), parallel_limit):
            batch = turn.tool_calls[batch_start:batch_start + parallel_limit]
            
            if len(batch) == 1:
                # Single call: execute directly
                call = batch[0]
                if loop.calls >= max_calls:
                    content = "Not run: the limit of questions for this step is reached."
                elif call.name not in offered:
                    content = f"Unknown tool {call.name!r}. Available: {', '.join(sorted(offered))}."
                else:
                    loop.calls += 1
                    start = time.monotonic()
                    log.info("%stool call [turn %d]: %s(%s)", log_prefix, turn_idx + 1, call.name,
                             json.dumps(call.arguments or {}, ensure_ascii=False)[:300])
                    try:
                        content = handlers[call.name](call.arguments or {})
                        elapsed = time.monotonic() - start
                        log.info("%stool %s completed in %.2fs", log_prefix, call.name, elapsed)
                    except Exception as exc:  # noqa: BLE001 - one bad call, not the conversation
                        elapsed = time.monotonic() - start
                        log.debug("%stool %s failed after %.2fs: %s", log_prefix, call.name, elapsed, exc)
                        content = f"Not run: {type(exc).__name__}: {exc}"
                call_results.append((call, content))
            else:
                # Multiple calls: execute in parallel
                log.info("%sexecuting %d tool calls in parallel [turn %d]", log_prefix, len(batch), turn_idx + 1)
                
                def execute_one(call_obj):
                    if loop.calls >= max_calls:
                        return call_obj, "Not run: the limit of questions for this step is reached."
                    if call_obj.name not in offered:
                        return call_obj, f"Unknown tool {call_obj.name!r}. Available: {', '.join(sorted(offered))}."
                    
                    start = time.monotonic()
                    log.info("%stool call [turn %d, parallel]: %s(%s)", log_prefix, turn_idx + 1, call_obj.name,
                             json.dumps(call_obj.arguments or {}, ensure_ascii=False)[:300])
                    try:
                        result = handlers[call_obj.name](call_obj.arguments or {})
                        elapsed = time.monotonic() - start
                        log.info("%stool %s completed in %.2fs", log_prefix, call_obj.name, elapsed)
                        return call_obj, result
                    except Exception as exc:  # noqa: BLE001
                        elapsed = time.monotonic() - start
                        log.debug("%stool %s failed after %.2fs: %s", log_prefix, call_obj.name, elapsed, exc)
                        return call_obj, f"Not run: {type(exc).__name__}: {exc}"
                
                batch_start_time = time.monotonic()
                with ThreadPoolExecutor(max_workers=len(batch)) as pool:
                    futures = {pool.submit(execute_one, call): call for call in batch}
                    for future in as_completed(futures):
                        call_obj, content = future.result()
                        if content and not content.startswith("Not run:"):
                            loop.calls += 1
                        call_results.append((call_obj, content))
                batch_elapsed = time.monotonic() - batch_start_time
                log.info("%sparallel batch of %d calls completed in %.2fs", log_prefix, len(batch), batch_elapsed)
        
        # Add all results to messages in original order
        for call, content in call_results:
            messages.append(client.tool_result_message(call, content))
        
        if loop.calls >= max_calls:
            break
    return loop
