from __future__ import annotations

from _helpers import _record

from appsec_triage.evals.metrics import score


def test_external_fp_is_a_decided_fourth_class():
    record = _record("external_fp", "CWE-89", "src/a.php")
    card = score([record], {record.finding_id: "external_fp"}, "fake", "fake")
    result = card.as_dict()

    assert result["agreement_all"] == 100.0
    assert result["agreement_decided"] == 100.0
    assert result["abstention_rate"] == 0.0
    assert result["external_fp_rate"] == 100.0


def test_external_fp_against_a_confirmed_gold_label_is_a_dangerous_miss():
    record = _record("external_fp", "CWE-89", "src/a.php")
    card = score([record], {record.finding_id: "confirmed"}, "fake", "fake")

    assert card.dangerous_misses == [record.finding_id]
