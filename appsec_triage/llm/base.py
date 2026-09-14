"""Provider-agnostic LLM interface.

Everything above this module knows only `LLMClient.complete()`. The differences
between Ollama, OpenAI and DeepSeek — JSON-mode syntax, auth, token accounting,
which knobs even exist — stay inside the concrete clients and their YAML config.
"""

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
    """The reply was delivered but is not the JSON the schema asked for.

    Retryable like a transport failure, and distinguished from one so the next
    attempt can tell the model what was wrong instead of sending the identical
    prompt and inviting the identical malformed answer."""


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

    def __init__(self, cfg: ProviderConfig) -> None:  # noqa: F821 - forward ref, see config.py
        self.cfg = cfg
        self.name = cfg.name
        self.model = cfg.model
        # Every call the run makes passes through `complete`, so this is the only
        # place that sees all of them. Counting per verdict record instead missed
        # everything the dependency chain spends — symbol resolution, call-site
        # judgement, conditions, the audit of a call-graph closure — and those
        # findings never reach the model for a verdict at all, so they reported a
        # cost of zero while actually costing several calls each.
        self._spend_lock = threading.Lock()
        self.calls = 0
        self.prompt_tokens_total = 0
        self.completion_tokens_total = 0
        self.spend_usd = 0.0
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
                    # Resending the identical prompt invites the identical bad
                    # reply. The retry says what was wrong with the last one, so
                    # the model has something to correct rather than repeat.
                    path, payload = self._build_payload(
                        system,
                        f"{user}\n\n=== CORRECTION ===\n"
                        f"Your previous reply was not valid JSON ({last_exc}). "
                        "Return one JSON object matching the schema and nothing "
                        "else. Escape every backslash and quote inside string "
                        "values — a namespace like Symfony\\\\Component needs its "
                        "backslashes doubled.",
                        json_schema,
                    )
                resp = self._client.post(path, json=payload)
                if resp.status_code in (408, 409, 425, 429) or resp.status_code >= 500:
                    raise LLMRetryableError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:300]}")
                if resp.status_code >= 400:
                    raise LLMError(f"{self.name}: HTTP {resp.status_code}: {resp.text[:500]}")
                text, ptok, ctok = self._parse(resp.json())
                # A schema was asked for, so a reply that will not parse is a
                # failed attempt, not an answer. Measured: a PHP namespace came
                # back with an unescaped backslash, `json.loads` raised at the
                # call site, and the whole extraction was thrown away — the
                # caller degraded to a weaker source with nothing retried. The
                # retry belongs here, where every caller gets it, rather than in
                # each of the five places that parse a model reply.
                if json_schema is not None and text:
                    try:
                        json.loads(text)
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

    @property
    def budget_left_usd(self) -> float | None:
        """What is left of the run's ceiling, or None when no ceiling is set.

        The optional steps ask this before spending. They are worth several calls
        each and a run is allowed a dollar, so in practice the answer is always
        yes — the point is that a pathological project cannot turn "ask the model
        more" into an unbounded bill, and that when the ceiling is reached the
        run says so rather than quietly answering on less evidence.
        """
        ceiling = getattr(self.cfg, "budget_usd", None)
        if not ceiling:
            return None
        with self._spend_lock:
            return max(0.0, float(ceiling) - self.spend_usd)

    def _record_spend(self, prompt_tokens: int | None, completion_tokens: int | None) -> None:
        """Add one answered call to the run total. Called once per reply, retries included."""
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
