"""Provider-agnostic LLM interface.

Everything above this module knows only `LLMClient.complete()`. The differences
between Ollama, OpenAI and DeepSeek — JSON-mode syntax, auth, token accounting,
which knobs even exist — stay inside the concrete clients and their YAML config.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx


class LLMError(RuntimeError):
    """Non-retryable provider failure."""


class LLMRetryableError(LLMError):
    """Transient failure: timeout, 429, 5xx, connection reset."""


@dataclass(slots=True)
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int = 0
    attempts: int = 1
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@runtime_checkable
class LLMClient(Protocol):
    """The only surface the pipeline depends on."""

    name: str
    model: str

    def complete(self, system: str, user: str, *, json_schema: dict[str, Any] | None = None) -> LLMResponse: ...

    def estimate_cost(self, prompt_tokens: int | None, completion_tokens: int | None) -> float | None: ...

    def close(self) -> None: ...


class BaseHTTPClient(ABC):
    """Shared transport: one httpx client, bounded retries, exponential backoff.

    Retry policy lives here rather than in each provider because the failure
    modes are identical over HTTP; only the request/response shape differs.
    """

    def __init__(self, cfg: "ProviderConfig") -> None:  # noqa: F821 - forward ref, see config.py
        self.cfg = cfg
        self.name = cfg.name
        self.model = cfg.model
        self._client = httpx.Client(
            base_url=cfg.base_url,
            timeout=httpx.Timeout(cfg.timeout_s, connect=cfg.connect_timeout_s),
            headers=self._headers(),
        )


    @abstractmethod
    def _headers(self) -> dict[str, str]: ...

    @abstractmethod
    def _build_payload(self, system: str, user: str, json_schema: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        """Return (path, json_body)."""

    @abstractmethod
    def _parse(self, body: dict[str, Any]) -> tuple[str, int | None, int | None]:
        """Return (text, prompt_tokens, completion_tokens)."""


    def complete(self, system: str, user: str, *, json_schema: dict[str, Any] | None = None) -> LLMResponse:
        path, payload = self._build_payload(system, user, json_schema)
        started = time.monotonic()
        last_exc: Exception | None = None

        for attempt in range(1, self.cfg.max_retries + 2):
            try:
                resp = self._client.post(path, json=payload)
                if resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500:
                    raise LLMRetryableError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:300]}")
                if resp.status_code >= 400:
                    raise LLMError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:500]}")
                text, ptok, ctok = self._parse(resp.json())
                return LLMResponse(
                    text=text,
                    model=self.model,
                    prompt_tokens=ptok,
                    completion_tokens=ctok,
                    latency_ms=int((time.monotonic() - started) * 1000),
                    attempts=attempt,
                    raw=resp.json() if self.cfg.keep_raw_response else {},
                )
            except (httpx.TimeoutException, httpx.TransportError, LLMRetryableError) as exc:
                last_exc = exc
                if attempt > self.cfg.max_retries:
                    break
                time.sleep(min(self.cfg.backoff_base_s * (2 ** (attempt - 1)), self.cfg.backoff_max_s))

        raise LLMRetryableError(f"{self.name}: exhausted {self.cfg.max_retries} retries: {last_exc}") from last_exc

    def estimate_cost(self, prompt_tokens: int | None, completion_tokens: int | None) -> float | None:
        pricing = self.cfg.pricing
        if not pricing or prompt_tokens is None or completion_tokens is None:
            return None
        return round(
            prompt_tokens / 1_000_000 * pricing.get("input_usd_per_mtok", 0.0)
            + completion_tokens / 1_000_000 * pricing.get("output_usd_per_mtok", 0.0),
            6,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
