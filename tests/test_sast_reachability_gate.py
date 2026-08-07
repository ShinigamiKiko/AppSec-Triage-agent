from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.models import TraceStep, VerdictLabel
from appsec_triage.pipeline import TriagePipeline


class _Symbols:
    def __init__(self, reachable: bool) -> None:
        self.reachable = reachable

    def enrich(self, finding):
        from appsec_triage.lsp.service import SymbolContext

        return SymbolContext(
            reachable_from_entrypoint=self.reachable,
            resolved=True,
        )


def _finding_with_trace():
    finding = _finding("$db->query($q);", cwe="CWE-89", path="src/Controller.php")
    finding.scanner = "codeql"
    finding.trace = [
        TraceStep(file_path="src/Controller.php", line=1, message="request q", role="source"),
        TraceStep(file_path="src/Controller.php", line=1, message="$db->query($q)", role="sink"),
    ]
    return finding


def _strict_cfg():
    return _cfg(require_sast_reachability=True)


def test_confirmed_dataflow_requires_trace_and_production_entrypoint():
    verdict = _verdict_json(
        verdict="confirmed",
        evidence_class="EXPLOITABLE_DATAFLOW",
        cwe="CWE-89",
        evidence=["$db->query($q);"],
    )
    record = TriagePipeline(
        FakeClient(verdict), _PROVIDER, _strict_cfg(), symbols=_Symbols(True)
    ).triage_one(_finding_with_trace())

    assert record.verdict.verdict is VerdictLabel.confirmed
    assert record.sast_reachability.status == "established"


def test_scanner_trace_without_lsp_entrypoint_is_unknown():
    verdict = _verdict_json(
        verdict="confirmed",
        evidence_class="EXPLOITABLE_DATAFLOW",
        cwe="CWE-89",
        evidence=["$db->query($q);"],
    )
    record = TriagePipeline(
        FakeClient(verdict), _PROVIDER, _strict_cfg(), symbols=_Symbols(False)
    ).triage_one(_finding_with_trace())

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("sast_reachability_unproven" in item for item in record.overrides)


def test_lsp_entrypoint_without_scanner_trace_is_unknown():
    finding = _finding_with_trace()
    finding.trace = []
    verdict = _verdict_json(
        verdict="confirmed",
        evidence_class="EXPLOITABLE_DATAFLOW",
        cwe="CWE-89",
        evidence=["$db->query($q);"],
    )
    record = TriagePipeline(
        FakeClient(verdict), _PROVIDER, _strict_cfg(), symbols=_Symbols(True)
    ).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("sast_reachability_unproven" in item for item in record.overrides)


def test_false_positive_requires_a_grounded_sanitized_dataflow():
    finding = _finding(
        '$q = $_GET["q"];\n$stmt = $pdo->prepare("SELECT * FROM t WHERE q = ?");\n$stmt->execute([$q]);',
        cwe="CWE-89",
        path="src/Controller.php",
    )
    finding.scanner = "psalm"
    finding.corroborated_by = ["semgrep"]
    finding.trace = [
        TraceStep(file_path="src/Controller.php", line=1, message='$_GET["q"]', role="source"),
        TraceStep(file_path="src/Controller.php", line=2, message="prepared statement", role="sanitizer"),
        TraceStep(file_path="src/Controller.php", line=3, message="$stmt->execute", role="sink"),
    ]
    safe = _verdict_json(
        verdict="false_positive",
        evidence_class="SANITIZED_DATAFLOW",
        cwe="CWE-89",
        evidence=['$stmt = $pdo->prepare("SELECT * FROM t WHERE q = ?");'],
        dataflow=[
            {
                "order": 1,
                "role": "sanitizer",
                "location": "src/Controller.php:2",
                "code": '$stmt = $pdo->prepare("SELECT * FROM t WHERE q = ?");',
                "explanation": "parameter binding separates data from SQL",
                "tainted": False,
            }
        ],
    )
    record = TriagePipeline(
        FakeClient(safe), _PROVIDER, _strict_cfg(), symbols=_Symbols(True)
    ).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.false_positive, (
        record.overrides,
        record.verdict.confidence_rationale,
    )

    unsupported = _verdict_json(
        verdict="false_positive",
        evidence_class="IDENTIFIER_ONLY",
        cwe="CWE-89",
        evidence=['$stmt = $pdo->prepare("SELECT * FROM t WHERE q = ?");'],
    )
    rejected = TriagePipeline(
        FakeClient(unsupported), _PROVIDER, _strict_cfg(), symbols=_Symbols(True)
    ).triage_one(finding)
    assert rejected.verdict.verdict is VerdictLabel.unknown
    assert any("sast_defence_unverified" in item for item in rejected.overrides)


def test_intrinsic_finding_does_not_require_a_reachability_path():
    finding = _finding('MessageDigest.getInstance("MD5")', cwe="CWE-327")
    verdict = _verdict_json(
        verdict="confirmed",
        evidence_class="IDENTIFIER_ONLY",
        cwe="CWE-327",
        evidence=['MessageDigest.getInstance("MD5")'],
    )
    record = TriagePipeline(FakeClient(verdict), _PROVIDER, _strict_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed
    assert not any("sast_reachability" in item for item in record.overrides)
