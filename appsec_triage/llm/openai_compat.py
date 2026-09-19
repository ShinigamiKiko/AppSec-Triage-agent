"""OpenAI and DeepSeek — same wire format, different structured-output support."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseHTTPClient, LLMError, ToolCall, ToolTurn, tool_arguments


class _ChatCompletionsClient(BaseHTTPClient):
    def _headers(self) -> dict[str, str]:
        if not self.cfg.api_key:
            raise LLMError(f"{self.cfg.name}: api_key is required (set the env var referenced in the profile)")
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.cfg.api_key}",
        }

    def _base_payload(self, system: str, user: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            **self.cfg.options,
        }
        if self.cfg.top_p is not None:
            payload["top_p"] = self.cfg.top_p
        if self.cfg.stop:
            payload["stop"] = self.cfg.stop
        return payload

    def _parse(self, body: dict[str, Any]) -> tuple[str, int | None, int | None]:
        choices = body.get("choices") or []
        if not choices:
            raise LLMError(f"{self.cfg.name}: response had no choices: {str(body)[:300]}")
        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        if not text and choices[0].get("finish_reason") == "length":
            raise LLMError(f"{self.cfg.name}: hit max_tokens before emitting any content")
        usage = body.get("usage") or {}
        return text, usage.get("prompt_tokens"), usage.get("completion_tokens")


    _NATIVE_TOOLS = True

    def _tool_payload(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        # No `response_format`: a JSON-mode reply cannot also be a tool call.
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            **self.cfg.options,
        }
        if self.cfg.top_p is not None:
            payload["top_p"] = self.cfg.top_p
        if self.cfg.stop:
            payload["stop"] = self.cfg.stop
        return "/chat/completions", payload

    def _tool_parse(self, body: dict[str, Any]) -> ToolTurn:
        choices = body.get("choices") or []
        if not choices:
            raise LLMError(f"{self.cfg.name}: response had no choices: {str(body)[:300]}")
        choice = choices[0]
        message = choice.get("message") or {}
        raw_calls = [item for item in (message.get("tool_calls") or []) if isinstance(item, dict)]
        text = message.get("content") or ""
        if not text and not raw_calls and choice.get("finish_reason") == "length":
            raise LLMError(f"{self.cfg.name}: hit max_tokens before emitting any content")
        calls = [
            ToolCall(
                id=str(item.get("id") or f"call_{index}"),
                name=str((item.get("function") or {}).get("name") or ""),
                arguments=tool_arguments((item.get("function") or {}).get("arguments")),
            )
            for index, item in enumerate(raw_calls)
        ]
        echo: dict[str, Any] = {"role": "assistant", "content": text}
        if raw_calls:
            echo["tool_calls"] = raw_calls
        usage = body.get("usage") or {}
        return ToolTurn(text, calls, echo, usage.get("prompt_tokens"), usage.get("completion_tokens"))

    def tool_result_message(self, call: ToolCall, content: str) -> dict[str, Any]:
        return {"role": "tool", "tool_call_id": call.id, "content": content}

class OpenAIClient(_ChatCompletionsClient):
    def _build_payload(self, system: str, user: str, json_schema: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        payload = self._base_payload(system, user)
        if self.cfg.json_mode == "json_schema" and json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "sast_triage_verdict",
                    "strict": True,
                    "schema": json_schema,
                },
            }
        elif self.cfg.json_mode == "json_object":
            payload["response_format"] = {"type": "json_object"}
        return "/chat/completions", payload


class DeepSeekClient(_ChatCompletionsClient):
    def _build_payload(self, system: str, user: str, json_schema: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        payload = self._base_payload(system, user)
        if self.cfg.json_mode != "none":
            payload["response_format"] = {"type": "json_object"}
            if json_schema:
                payload["messages"][0]["content"] += (
                    "\n\n## Output contract\n"
                    "Respond with a single JSON object that validates against this JSON Schema. "
                    "Use EXACTLY these field names, include every `required` field, and add no others:\n"
                    + json.dumps(json_schema, ensure_ascii=False)
                )
            elif "json" not in (system + user).lower():
                payload["messages"][0]["content"] += "\n\nRespond with a single JSON object."
        return "/chat/completions", payload

    def estimate_cost(self, prompt_tokens: int | None, completion_tokens: int | None) -> float | None:
        return super().estimate_cost(prompt_tokens, completion_tokens)
