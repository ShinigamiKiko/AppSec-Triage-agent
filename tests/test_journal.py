"""An interrupted run must not lose the verdicts it already paid for.

Measured: a crash at finding 183 of 296 produced no output file at all. The
model calls are the expensive part of this pipeline and they are not
reproducible for free — 183 finished verdicts and twenty minutes went with it.
"""

from __future__ import annotations

from appsec_triage.models import CodeContext, Finding, TriageRecord, Verdict, VerdictLabel, EvidenceClass
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
