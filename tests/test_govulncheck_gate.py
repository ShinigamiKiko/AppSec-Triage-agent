import json
import tempfile
import unittest
from pathlib import Path

from appsec_triage.context.builder import build
from appsec_triage.context.heuristics import HeuristicResult
from appsec_triage.ingest.govulncheck import parse
from appsec_triage.models import CodeContext, DependencyInfo, Finding, TraceStep, VerdictLabel
from appsec_triage.validate.postvalidation import (
    AUTO_APPLY_CONFIDENCE,
    apply_confidence_policy,
    apply_govulncheck_gate,
    govulncheck_baseline,
    is_authoritative_govulncheck,
)
from appsec_triage.validate.schema import parse_verdict


class GovulncheckGateTests(unittest.TestCase):
    def test_ingest_preserves_authoritative_trace_and_aliases(self):
        messages = [
            {"config": {"scanner_name": "govulncheck"}},
            {"SBOM": {"modules": [{"path": "example.com/app"}]}},
            {"osv": {"id": "GO-2024-0001", "summary": "test", "aliases": ["CVE-2024-1"]}},
            {"finding": {"osv": "GO-2024-0001", "trace": [
                {"module": "example.com/app", "function": "main", "position": {"filename": "main.go", "line": 10}},
                {"module": "example.com/vuln", "version": "v1.0.0", "function": "Bad", "position": {"filename": "vuln.go", "line": 20}},
            ], "fixed_version": "v1.1.0"}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "govuln.json"
            path.write_text("\n".join(json.dumps(message) for message in messages))
            finding = next(parse(path))
        self.assertEqual(finding.scanner, "govulncheck")
        self.assertEqual(len(finding.trace), 2)
        self.assertEqual(finding.dependency.advisory_aliases, ["CVE-2024-1"])
        self.assertTrue(is_authoritative_govulncheck(finding))
    def setUp(self):
        self.finding = Finding(
            finding_id="gov-1",
            scanner="govulncheck",
            rule_id="GO-123",
            code_context=CodeContext(file_path="main.go", start_line=10),
            trace=[
                TraceStep(file_path="main.go", line=10, role="source", message="main.input"),
                TraceStep(file_path="vendor.example/vuln.go", line=20, role="sink", message="vuln.Call"),
            ],
            dependency=DependencyInfo(package="vendor.example", ecosystem="go", installed_version="1.0.0"),
        )
        self.pkg = build(self.finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())
        self.baseline = govulncheck_baseline(self.finding)

    def verdict(self, value, quote="=== DEPENDENCY ==="):
        return parse_verdict("""{{
          "verdict": "{}", "evidence_class": "IDENTIFIER_ONLY", "confidence": 0.9,
          "confidence_rationale": "The package is not shipped in production.",
          "exploitability": "moderate", "impact": "high", "cwe": null,
          "vulnerable_symbol": null, "dataflow": [],
          "evidence": [{{"quote": {}, "why": "The dependency is development only."}}],
          "reason": "The package is development-only and is not shipped to production.",
          "missing_information": [], "blocking_question": null, "requires_human_review": false
        }}""".format(value, repr(quote).replace("'", '"')))

    def test_real_trace_is_authoritative(self):
        self.assertTrue(is_authoritative_govulncheck(self.finding))
        verdict, overrides = apply_govulncheck_gate(self.baseline, None, self.pkg, quote_threshold=0.9, error="offline")
        self.assertIs(verdict.verdict, VerdictLabel.confirmed)
        self.assertIn("authoritative baseline", overrides[0])

    def test_unknown_or_ungrounded_refutation_cannot_close(self):
        verdict, _ = apply_govulncheck_gate(self.baseline, self.baseline, self.pkg, quote_threshold=0.9)
        self.assertIs(verdict.verdict, VerdictLabel.confirmed)

    def test_grounded_concrete_refutation_can_close(self):
        quote = self.pkg.quotable_text().split("\n", 1)[0]
        verdict, overrides = apply_govulncheck_gate(
            self.baseline, self.verdict("false_positive", quote), self.pkg, quote_threshold=0.9,
        )
        self.assertIs(verdict.verdict, VerdictLabel.false_positive)
        self.assertIn("overridden", overrides[0])

    def test_only_confidence_above_threshold_can_skip_human_review(self):
        quote = self.pkg.quotable_text().split("\n", 1)[0]
        at_threshold = self.verdict("false_positive", quote).model_copy(
            update={"confidence": AUTO_APPLY_CONFIDENCE, "requires_human_review": False})
        result = apply_confidence_policy(at_threshold, []).model_copy()
        self.assertTrue(result.requires_human_review)

        above_threshold = at_threshold.model_copy(update={"confidence": 0.87})
        result = apply_confidence_policy(above_threshold, [])
        self.assertFalse(result.requires_human_review)


if __name__ == "__main__":
    unittest.main()
