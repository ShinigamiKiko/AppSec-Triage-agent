"""Ollama client — the closed-loop default."""

from __future__ import annotations

from typing import Any

from .base import BaseHTTPClient, LLMError, LLMTruncated, ToolCall, ToolTurn, tool_arguments


class OllamaClient(BaseHTTPClient):
    _NATIVE_TOOLS = True

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            h["Authorization"] = f"Bearer {self.cfg.api_key}"
        return h

    def _options(self) -> dict[str, Any]:
        options: dict[str, Any] = {
            "temperature": self.cfg.temperature,
            "num_predict": self._max_tokens(),
            **self.cfg.options,
        }
        if self.cfg.top_p is not None:
            options["top_p"] = self.cfg.top_p
        if self.cfg.stop:
            options["stop"] = self.cfg.stop
        return options

    def _build_payload(self, system: str, user: str, json_schema: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": self._options(),
        }

        if self.cfg.json_mode == "ollama_format" and json_schema:
            payload["format"] = json_schema
        elif self.cfg.json_mode != "none":
            payload["format"] = "json"

        return "/api/chat", self._with_think(payload)

    def _with_think(self, payload: dict[str, Any]) -> dict[str, Any]:
        think = (self.cfg.think or "").strip().lower()
        if think in ("true", "false"):
            payload["think"] = think == "true"
        return payload

    def _parse(self, body: dict[str, Any]) -> tuple[str, int | None, int | None]:
        text = (body.get("message") or {}).get("content", "")
        if body.get("done_reason") == "length":
            raise LLMTruncated(
                f"{self.cfg.name}: response truncated at max_tokens={self._max_tokens()}"
            )
        return text, body.get("prompt_eval_count"), body.get("eval_count")

    def _tool_payload(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        return "/api/chat", self._with_think({"model": self.model, "messages": messages, "tools": tools,
                                              "stream": False, "options": self._options()})

    def _tool_parse(self, body: dict[str, Any]) -> ToolTurn:
        if body.get("done_reason") == "length":
            raise LLMTruncated(
                f"{self.cfg.name}: response truncated at max_tokens={self._max_tokens()}"
            )
        message = body.get("message") or {}
        raw_calls = [item for item in (message.get("tool_calls") or []) if isinstance(item, dict)]
        calls = [
            ToolCall(
                id=str(item.get("id") or f"call_{index}"),
                name=str((item.get("function") or {}).get("name") or ""),
                arguments=tool_arguments((item.get("function") or {}).get("arguments")),
            )
            for index, item in enumerate(raw_calls)
        ]
        text = message.get("content") or ""
        echo: dict[str, Any] = {"role": "assistant", "content": text}
        if raw_calls:
            echo["tool_calls"] = raw_calls
        return ToolTurn(text, calls, echo, body.get("prompt_eval_count"), body.get("eval_count"))

    def tool_result_message(self, call: ToolCall, content: str) -> dict[str, Any]:
        return {"role": "tool", "tool_name": call.name, "content": content}
