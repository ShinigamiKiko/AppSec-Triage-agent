"""Verdict reuse across runs and the heavy-class closure rule."""

from __future__ import annotations

import pytest
from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _record, _verdict_json

from appsec_triage.models import VerdictLabel
from appsec_triage.pipeline import TriagePipeline


def _rec_for(finding, verdict="false_positive", overrides=(), error=None):
    from appsec_triage.models import EvidenceClass, TriageRecord, Verdict, VerdictLabel

    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        rule_id=finding.rule_id,
        fingerprint=__import__("appsec_triage.reuse", fromlist=["x"]).fingerprint(finding),
        verdict=Verdict(
            verdict=VerdictLabel(verdict),
            evidence_class=EvidenceClass.test_placeholder,
            confidence=0.95,
            cwe=finding.cwe,
            reason="r",
        ),
        overrides=list(overrides),
        error=error,
        model="qwen3-coder:30b",
    )


def _write_prev(tmp_path, records):
    from appsec_triage.pipeline import TriageRun
    from appsec_triage.report import audit

    run = TriageRun(records=records, provider="ollama", model="qwen3-coder:30b", prompt_pack="default")
    return audit.write_jsonl(run, tmp_path / "prev.jsonl")


def test_settled_findings_are_reused_and_unreliable_ones_redone(tmp_path):
    """The question people actually ask: redo the bad ones, keep the settled ones."""
    from appsec_triage import reuse

    settled = _finding('$a = "${VAR}";', cwe="CWE-798", path="a.php")
    unresolved = _finding('$b = "x";', cwe="CWE-798", path="b.php")
    corrected = _finding('$c = "y";', cwe="CWE-798", path="c.php")
    for f, name in ((settled, "s"), (unresolved, "u"), (corrected, "c")):
        f.finding_id = name

    prev = _write_prev(
        tmp_path,
        [
            _rec_for(settled),
            _rec_for(unresolved, verdict="unknown"),
            _rec_for(corrected, overrides=["sanity_conflict: x"]),
        ],
    )

    p = reuse.plan([settled, unresolved, corrected], prev)
    assert [f.finding_id for f in p.fresh] == ["u", "c"]
    assert [r.finding_id for r in p.reused] == ["s"]
    assert p.reused[0].reused is True


def test_changed_code_is_always_re_triaged(tmp_path):
    """A verdict about code that no longer exists is worse than no verdict."""
    from appsec_triage import reuse

    before = _finding('$a = "old";', cwe="CWE-798", path="a.php")
    before.finding_id = "a"
    prev = _write_prev(tmp_path, [_rec_for(before)])

    after = _finding('$a = "new";', cwe="CWE-798", path="a.php")
    after.finding_id = "a"
    p = reuse.plan([after], prev)

    assert [f.finding_id for f in p.fresh] == ["a"]
    assert p.reused == []


def test_a_line_shift_does_not_invalidate_a_verdict(tmp_path):
    """Someone adding an import above must not cost an hour of GPU."""
    from appsec_triage import reuse

    original = _finding('$a = "${VAR}";', cwe="CWE-798", path="a.php")
    original.finding_id = "a"
    original.code_context.start_line = 10
    prev = _write_prev(tmp_path, [_rec_for(original)])

    shifted = _finding('$a = "${VAR}";', cwe="CWE-798", path="a.php")
    shifted.finding_id = "a-renumbered"
    shifted.code_context.start_line = 47

    p = reuse.plan([shifted], prev)
    assert len(p.reused) == 1 and p.fresh == []


def test_redo_selection_is_explicit():
    from appsec_triage import reuse

    assert reuse.parse_redo(None) == reuse.DEFAULT_REDO
    assert reuse.parse_redo("all") == ("all",)
    assert reuse.parse_redo("unknown, confirmed") == ("unknown", "confirmed")
    with pytest.raises(ValueError):
        reuse.parse_redo("whatever")


def test_missing_previous_run_falls_back_to_full_triage(tmp_path):
    from appsec_triage import reuse

    f = _finding('$a = "x";', cwe="CWE-798")
    p = reuse.plan([f], tmp_path / "does-not-exist.jsonl")
    assert p.fresh == [f] and p.reused == []


# --- safety policy: closures on heavy classes -----------------------------------


def test_unexplained_closure_on_a_heavy_class_becomes_unknown():
    """ "It looks fine" is not a closure when the class would actually hurt."""
    from appsec_triage.config import PostValidationConfig

    cfg = _cfg()
    cfg.post_validation = PostValidationConfig(closure_requires_named_defence_above=26)

    finding = _finding("$cmd = shell_exec($target);", cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="INSUFFICIENT_CONTEXT",
            cwe="CWE-78",
            evidence=[{"quote": "$cmd = shell_exec($target);", "why": "seems ok"}],
            reason="probably fine",
        )
    )
    record = TriagePipeline(client, _PROVIDER, cfg).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("unexplained_closure" in o for o in record.overrides)
    assert "what makes it safe" in record.verdict.blocking_question


def test_a_named_and_quoted_defence_still_closes_a_heavy_class():
    """The rule must not make heavy classes unclosable — that would defeat the filter."""
    from appsec_triage.config import PostValidationConfig

    cfg = _cfg()
    cfg.post_validation = PostValidationConfig(closure_requires_named_defence_above=26)

    finding = _finding("$stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?');", cwe="CWE-89")
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="SANITIZED_DATAFLOW",
            cwe="CWE-89",
            evidence=[
                {
                    "quote": "$stmt = $pdo->prepare('SELECT * FROM t WHERE id = ?');",
                    "why": "bound placeholder, the value never enters the SQL text",
                }
            ],
            reason="parameterised",
        )
    )
    record = TriagePipeline(client, _PROVIDER, cfg).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.overrides == []


def test_light_classes_are_not_subject_to_the_closure_rule():
    """Hygiene findings are where the 88% saving comes from; do not tax them."""
    from appsec_triage.config import PostValidationConfig

    cfg = _cfg()
    cfg.post_validation = PostValidationConfig(closure_requires_named_defence_above=26)

    finding = _finding("assert x == 1", cwe="CWE-703")
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="INSUFFICIENT_CONTEXT",
            cwe="CWE-703",
            evidence=[{"quote": "assert x == 1", "why": "test assertion"}],
        )
    )
    record = TriagePipeline(client, _PROVIDER, cfg).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.false_positive


def test_closures_on_heavy_classes_are_challenged():
    from appsec_triage import verify
    from appsec_triage.config import VerificationConfig

    cfg = VerificationConfig(enabled=True, challenge_closures_above_consequence=26)

    rce_closed = _record("false_positive", "CWE-78", "a.php")
    sqli_closed = _record("false_positive", "CWE-89", "b.php")
    hygiene_closed = _record("false_positive", "CWE-703", "c.php")
    weak_hash_closed = _record("false_positive", "CWE-327", "d.php")

    assert verify.should_challenge(rce_closed, cfg)
    assert verify.should_challenge(sqli_closed, cfg)
    assert not verify.should_challenge(hygiene_closed, cfg)
    assert not verify.should_challenge(weak_hash_closed, cfg), "weight 14 is below the threshold"


# --- cross-scanner corroboration ------------------------------------------------
