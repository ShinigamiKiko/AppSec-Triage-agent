"""An interrupted run must not lose the verdicts it already paid for.

Measured: a crash at finding 183 of 296 produced no output file at all. The
model calls are the expensive part of this pipeline and they are not
reproducible for free — 183 finished verdicts and twenty minutes went with it.
"""

from __future__ import annotations

from appsec_triage.models import EvidenceClass, SCASummary, TriageRecord, Verdict, VerdictLabel
from appsec_triage.report import audit


def _record(fid: str) -> TriageRecord:
    return TriageRecord(
        finding_id=fid,
        cwe="CWE-89",
        file_path=f"{fid}.php",
        verdict=Verdict(
            verdict=VerdictLabel.confirmed,
            evidence_class=EvidenceClass.exploitable_dataflow,
            confidence=0.8,
            reason="r",
        ),
    )


def test_records_are_readable_before_the_run_finishes(tmp_path):
    path = tmp_path / "verdicts.jsonl.partial"
    with audit.Journal(path, "default") as journal:
        journal.append(_record("f1"))
        journal.append(_record("f2"))
        # Read from a *separate* handle while the writer is still open: this is
        # exactly the state a killed process leaves behind.
        assert len(audit.Journal.recover(path)) == 2


def test_a_half_written_last_line_does_not_poison_the_recovery(tmp_path):
    path = tmp_path / "verdicts.jsonl.partial"
    with audit.Journal(path, "default") as journal:
        journal.append(_record("f1"))
    # A process killed mid-write leaves a truncated line. Refusing the file for
    # that would throw away the verdicts that did survive.
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"finding_id": "f2", "verdi')

    recovered = audit.Journal.recover(path)
    assert [r.finding_id for r in recovered] == ["f1"]


def test_the_journal_is_removed_once_the_durable_log_exists(tmp_path):
    path = tmp_path / "verdicts.jsonl.partial"
    with audit.Journal(path, "default") as journal:
        journal.append(_record("f1"))
    audit.Journal(path, "default").done()
    # Its presence is the signal "a run did not finish"; leaving it behind would
    # make the next run resume from a run that actually completed.
    assert not path.exists()


def test_recovering_a_missing_journal_is_not_an_error(tmp_path):
    assert audit.Journal.recover(tmp_path / "nothing.partial") == []


def test_journalled_records_survive_a_round_trip(tmp_path):
    path = tmp_path / "verdicts.jsonl.partial"
    original = _record("f1")
    with audit.Journal(path, "default") as journal:
        journal.append(original)

    back = audit.Journal.recover(path)[0]
    assert back.finding_id == original.finding_id
    assert back.verdict.verdict is VerdictLabel.confirmed
    assert back.verdict.reason == "r"


def test_external_fp_survives_jsonl_and_summary_as_ai_closed(tmp_path):
    import json

    from appsec_triage.pipeline import TriageRun

    record = _record("external")
    record.verdict = Verdict(
        verdict=VerdictLabel.external_fp,
        evidence_class=EvidenceClass.exploitable_dataflow,
        confidence=0.85,
        reason="mitigated by an external control",
    )
    run = TriageRun(records=[record], provider="fake", model="fake", prompt_pack="default")

    jsonl = audit.write_jsonl(run, tmp_path / "verdicts.jsonl")
    back = audit.read_jsonl(jsonl)[0]
    assert back.verdict.verdict is VerdictLabel.external_fp
    assert back.verdict.requires_human_review is False

    summary_path = audit.write_summary(run, tmp_path / "summary.json")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["external_mitigated"] == 1
    assert summary["auto_closed"] == 1
    assert summary["requires_human_review"] == 0


def test_summary_counts_sca_symbol_resolution_errors_separately(tmp_path):
    import json

    from appsec_triage.pipeline import TriageRun

    record = _record("sca-error")
    record.sca = SCASummary(resolution_error="model returned invalid JSON twice")
    run = TriageRun(records=[record], provider="fake", model="fake", prompt_pack="default")

    summary_path = audit.write_summary(run, tmp_path / "summary.json")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    assert summary["errors"] == 0
    assert summary["sca_resolution_errors"] == 1
