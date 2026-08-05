"""Ollama client — the closed-loop default.

Ollama's native /api/chat takes decoding knobs under `options` and enforces JSON
via `format`, which since 0.5 accepts a full JSON Schema object (not just the
string "json"). That gives us grammar-constrained decoding locally, which is why
the article's 0%-invalid-JSON number is reachable without a retry loop.
"""

from __future__ import annotations

from typing import Any

from .base import BaseHTTPClient, LLMError


class OllamaClient(BaseHTTPClient):
    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            h["Authorization"] = f"Bearer {self.cfg.api_key}"
        return h

    def _build_payload(self, system: str, user: str, json_schema: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        options: dict[str, Any] = {
            "temperature": self.cfg.temperature,
            "num_predict": self.cfg.max_tokens,
            **self.cfg.options,
        }
        if self.cfg.top_p is not None:
            options["top_p"] = self.cfg.top_p
        if self.cfg.stop:
            options["stop"] = self.cfg.stop

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": options,
        }

        if self.cfg.json_mode == "ollama_format" and json_schema:
            payload["format"] = json_schema
        elif self.cfg.json_mode != "none":
            payload["format"] = "json"

        return "/api/chat", payload

    def _parse(self, body: dict[str, Any]) -> tuple[str, int | None, int | None]:
        text = (body.get("message") or {}).get("content", "")
        if body.get("done_reason") == "length":
            raise LLMError(
                f"{self.cfg.name}: response truncated at max_tokens={self.cfg.max_tokens}; "
                "raise max_tokens in the provider profile"
            )
        return text, body.get("prompt_eval_count"), body.get("eval_count")
