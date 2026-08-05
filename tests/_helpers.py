"""Shared fixtures for the test suite: a scripted fake provider and the record
/finding/verdict builders used across concern files. Imported as `_helpers`
(pytest puts the tests dir on sys.path)."""

from __future__ import annotations

import json

from appsec_triage.config import (
    HeuristicsConfig,
    PipelineConfig,
    PostValidationConfig,
    ProviderConfig,
)
from appsec_triage.llm.base import LLMResponse
from appsec_triage.models import CodeContext, Finding, Severity


class FakeClient:
    """Returns whatever JSON the test hands it, in order."""

    name = "fake"
    model = "fake-model"

    def __init__(self, *responses: str | Exception) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system, user, *, json_schema=None):
        self.calls.append((system, user))
        item = self._responses.pop(0) if self._responses else self._responses[-1]
        if isinstance(item, Exception):
            raise item
        return LLMResponse(text=item, model=self.model, prompt_tokens=100, completion_tokens=50, latency_ms=42)

    def estimate_cost(self, p, c):
        return None

    def close(self):
        pass


def _cfg(**post_overrides) -> PipelineConfig:
    return PipelineConfig(
        provider="fake",
        heuristics=HeuristicsConfig(enabled=True),
        post_validation=PostValidationConfig(**post_overrides),
    )


_PROVIDER = ProviderConfig(name="fake", kind="ollama", model="fake-model", base_url="http://x", concurrency=1)


# CWE-79 is the neutral default on purpose. Most tests here
# are about machinery — grounding, schema repair, batch resilience — and the
# finding class is incidental to them. The old default was CWE-798, which put
# every one of those tests inside the credential family; when that family gained
# a deterministic path that never calls the model, nineteen tests silently
# stopped exercising the code they exist to cover. A test about schema repair
# should not depend on what the finding is about. Tests that *are* about
# credentials pass `cwe="CWE-798"` explicitly.
#
# It sits below `closure_requires_named_defence_above`, so a closure in a test
# still stands without inventing a named defence — and unlike CWE-330 it has no
# heuristic that fires on the credential-shaped snippets these fixtures use,
# which would have pushed the same tests to `unknown` from the other direction.
def _finding(snippet: str, *, cwe="CWE-79", path="src/main/App.java", severity=Severity.medium) -> Finding:
    return Finding(
        finding_id="t-1",
        scanner="test",
        rule_id="test.rule",
        cwe=cwe,
        title="Analyzer finding",
        description="Analyzer flagged a suspicious literal.",
        severity=severity,
        code_context=CodeContext(file_path=path, start_line=1, snippet=snippet),
    )


def _verdict_json(**over) -> str:
    base = {
        "verdict": "false_positive",
        "evidence_class": "TEST_PLACEHOLDER",
        "confidence": 0.95,
        "cwe": "CWE-798",
        "evidence": [],
        "reason": "test",
        "missing_information": [],
        "requires_human_review": False,
    }
    return json.dumps({**base, **over})


def _record(verdict: str, cwe: str, path: str, *, rule="r1", overrides=(), snippet="x = 1") -> object:
    from appsec_triage.models import EvidenceClass, TriageRecord, Verdict, VerdictLabel

    return TriageRecord(
        finding_id=f"{rule}:{path}:{snippet[:8]}",
        cwe=cwe,
        file_path=path,
        rule_id=rule,
        verdict=Verdict(
            verdict=VerdictLabel(verdict),
            evidence_class=EvidenceClass.insufficient_context,
            confidence=0.95,
            cwe=cwe,
            reason="r",
        ),
        overrides=list(overrides),
    )


_PHP_CLOSURE = dict(
    cwe="CWE-89",
    evidence_class="SANITIZED_DATAFLOW",
    evidence=["$stmt->execute([$id]);"],
    confidence=0.95,
)

_PHP_SNIPPET = "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);"
