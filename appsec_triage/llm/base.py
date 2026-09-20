"""Provider-agnostic LLM interface."""

from __future__ import annotations

import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx


class LLMError(RuntimeError):
    """Non-retryable provider failure."""


class LLMRetryableError(LLMError):
    """Transient failure: timeout, 429, 5xx, connection reset."""


class _UnparsableReply(LLMRetryableError):
    """The reply was delivered but is not the JSON the schema asked for."""


@dataclass(slots=True)
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int = 0
    attempts: int = 1
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(slots=True)
class ToolCall:
    """One tool invocation the model asked for."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class ToolTurn:
    """One model turn in a native tool-calling conversation."""

    text: str
    tool_calls: list[ToolCall]
    message: dict[str, Any]
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int = 0
    attempts: int = 1


def loads_relaxed(text: str) -> Any:
    """Parse a model's JSON, tolerating raw control characters inside strings.

    A model quoting source code writes the newline it saw, where the standard
    wants `\n`. Python's parser refuses that by default, so a reply that is
    otherwise perfectly good is thrown away and asked for again. Nothing else
    is relaxed: a genuinely broken reply still raises.
    """
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(text, strict=False)


def to_strict_json(text: str) -> str:
    """The same reply, re-encoded so every consumer can parse it strictly."""
    return json.dumps(loads_relaxed(text), ensure_ascii=False)


def tool_arguments(raw: Any) -> dict[str, Any]:
    """A tool call's arguments as a dict, however the provider encoded them."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            value = loads_relaxed(raw)
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}
    return {}


@runtime_checkable
class LLMClient(Protocol):
    """The only surface the pipeline depends on."""

    name: str
    model: str

    def complete(self, system: str, user: str, *, json_schema: dict[str, Any] | None = None) -> LLMResponse: ...

    def estimate_cost(self, prompt_tokens: int | None, completion_tokens: int | None) -> float | None: ...

    def close(self) -> None: ...


class BaseHTTPClient(ABC):
    """Shared transport: one httpx client, bounded retries, exponential backoff."""

    def __init__(self, cfg: ProviderConfig) -> None:  # noqa: F821 - forward ref, see config.py
        self.cfg = cfg
        self.name = cfg.name
        self.model = cfg.model
        self._spend_lock = threading.Lock()
        self.calls = 0
        self.prompt_tokens_total = 0
        self.completion_tokens_total = 0
        self.spend_usd = 0.0
        self._native_tools_rejected = False
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
                if isinstance(last_exc, _UnparsableReply):
                    path, payload = self._build_payload(
                        system,
                        f"{user}\n\n=== CORRECTION ===\n"
                        f"Your previous reply was not valid JSON ({last_exc}). "
                        "Return one JSON object matching the schema and nothing "
                        "else. Escape every backslash and quote inside string "
                        "values — a namespace like Symfony\\\\Component needs its "
                        "backslashes doubled — and write a line break inside a "
                        "quoted value as \\n, never as a real newline.",
                        json_schema,
                    )
                resp = self._client.post(path, json=payload)
                if resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500:
                    raise LLMRetryableError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:300]}")
                if resp.status_code >= 400:
                    raise LLMError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:500]}")
                text, ptok, ctok = self._parse(resp.json())
                if json_schema is not None and text:
                    try:
                        # Hand on a reply the consumers can parse strictly, so a
                        # newline inside a quoted line does not cost three calls.
                        text = to_strict_json(text)
                    except ValueError as exc:
                        raise _UnparsableReply(
                            f"{self.name}: ответ не разбирается как JSON: {exc}") from exc
                self._record_spend(ptok, ctok)
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

    #: Set by providers whose API carries native tool calls.
    _NATIVE_TOOLS = False

    @property
    def supports_tools(self) -> bool:
        """Whether this client can hold a native tool-calling conversation."""
        return (self._NATIVE_TOOLS and bool(getattr(self.cfg, "tool_calling", True))
                and not self._native_tools_rejected)

    def _tool_payload(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        raise NotImplementedError

    def _tool_parse(self, body: dict[str, Any]) -> ToolTurn:
        raise NotImplementedError

    def tool_result_message(self, call: ToolCall, content: str) -> dict[str, Any]:
        """The message that hands a tool's output back to the model."""
        raise NotImplementedError

    def chat_tools(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ToolTurn:
        """One turn of a native tool-calling conversation, with the usual retries."""
        if not self.supports_tools:
            raise LLMError(f"{self.name}: tool calling is not enabled for this provider")
        path, payload = self._tool_payload(messages, tools)
        started = time.monotonic()
        last_exc: Exception | None = None
        for attempt in range(1, self.cfg.max_retries + 2):
            try:
                resp = self._client.post(path, json=payload)
                if resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500:
                    raise LLMRetryableError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:300]}")
                if resp.status_code >= 400:
                    # HTTP 400 with tools often means the model doesn't support them
                    error_text = resp.text[:500]
                    if resp.status_code == 400 and ("tool" in error_text.lower() or "function" in error_text.lower()):
                        self._native_tools_rejected = True
                        raise LLMError(f"{self.name}: HTTP 400 tool rejection: {error_text}")
                    raise LLMError(f"{self.name}: HTTP {resp.status_code}: {error_text}")
                turn = self._tool_parse(resp.json())
                turn.latency_ms = int((time.monotonic() - started) * 1000)
                turn.attempts = attempt
                self._record_spend(turn.prompt_tokens, turn.completion_tokens)
                return turn
            except (httpx.TimeoutException, httpx.TransportError, LLMRetryableError) as exc:
                last_exc = exc
                if attempt > self.cfg.max_retries:
                    break
                time.sleep(min(self.cfg.backoff_base_s * (2 ** (attempt - 1)), self.cfg.backoff_max_s))
        raise LLMRetryableError(f"{self.name}: exhausted {self.cfg.max_retries} retries: {last_exc}") from last_exc

    @property
    def budget_left_usd(self) -> float | None:
        """What is left of the run's ceiling, or None when no ceiling is set."""
        ceiling = getattr(self.cfg, "budget_usd", None)
        if ceiling is None:
            return None
        with self._spend_lock:
            return max(0.0, float(ceiling) - self.spend_usd)

    def _record_spend(self, prompt_tokens: int | None, completion_tokens: int | None) -> None:
        """Add one answered call to the run total."""
        cost = self.estimate_cost(prompt_tokens, completion_tokens) or 0.0
        with self._spend_lock:  # findings are triaged in parallel
            self.calls += 1
            self.prompt_tokens_total += prompt_tokens or 0
            self.completion_tokens_total += completion_tokens or 0
            self.spend_usd += cost

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
