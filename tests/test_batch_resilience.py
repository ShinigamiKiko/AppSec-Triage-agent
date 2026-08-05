r"""One bad response must not cost the whole run.

Measured: a model answered with `\d` inside a quoted regex. That is not a valid
JSON escape, `json.loads` rejected the document, and the resulting
`JSONDecodeError` — which `triage_one` does not catch — propagated out of the
thread pool. A run of 296 findings ended with no output file at all.
"""

from __future__ import annotations

import pytest

from appsec_triage.models import CodeContext, Finding, VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.validate.schema import SchemaError, parse_verdict
from appsec_triage.llm.base import LLMResponse
from tests._helpers import FakeClient
from tests.test_verdict_evidence import _PROVIDER, _cfg

_GOOD = (
    '{"verdict":"false_positive","evidence_class":"TEST_PLACEHOLDER","confidence":0.9,'
    '"evidence":[{"quote":"token = \\"x\\"","why":"placeholder"}],"reason":"ok",'
    '"missing_information":[],"requires_human_review":false}'
)


def test_an_invalid_json_escape_is_repaired_not_fatal():
    # `\d` is a valid regex and an invalid JSON escape. Quoting source code, the
    # model produces these constantly.
    raw = (
        r'{"verdict":"confirmed","evidence_class":"EXPLOITABLE_DATAFLOW","confidence":0.9,'
        r'"evidence":[{"quote":"preg_match(/\d+/, $id)","why":"regex"}],"reason":"r",'
        r'"missing_information":[],"requires_human_review":true}'
    )
    verdict = parse_verdict(raw)
    assert verdict.verdict is VerdictLabel.confirmed
    assert "d+" in verdict.evidence[0].quote


def test_unparseable_output_raises_schema_error_not_json_error():
    # The distinction that broke the run: `triage_one` catches SchemaError only.
    with pytest.raises(SchemaError):
        parse_verdict("{ this is not json at all ")


def test_an_unexpected_exception_becomes_a_record_rather_than_a_lost_finding():
    class Exploding(FakeClient):
        """Good on every call but the second, which fails in a way the pipeline
        does not anticipate — the shape of the real crash."""

        def complete(self, system, user, *, json_schema=None):
            self.calls.append((system, user))
            if len(self.calls) == 2:
                raise RuntimeError("connection reset mid-batch")
            return LLMResponse(
                text=_GOOD, model=self.model, prompt_tokens=10, completion_tokens=5, latency_ms=1
            )

    findings = [
        Finding(
            finding_id=f"f{i}",
            scanner="semgrep",
            cwe="CWE-79",
            code_context=CodeContext(file_path=f"a{i}.py", start_line=1, snippet='token = "x"'),
        )
        for i in range(3)
    ]
    run = TriagePipeline(Exploding(), _PROVIDER, _cfg()).run(findings)

    # Every finding still has a record, and the failure is visible as one.
    assert len(run.records) == 3
    failed = [r for r in run.records if r.decided_by == "error"]
    assert len(failed) == 1
    assert "connection reset" in (failed[0].error or "")
    assert failed[0].verdict.requires_human_review is True
