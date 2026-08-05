"""Finding the same construct where no scanner looked.

The agent's structural blind spot: it judges only what a scanner sent it. If a
rule fired in one of eleven places, the other ten were never seen — not judged
safe, simply invisible. This searches outward from a weakness already confirmed.
"""

from __future__ import annotations

from appsec_triage import variants
from appsec_triage.models import (
    CodeContext,
    EvidenceClass,
    Finding,
    TriageRecord,
    Verdict,
    VerdictLabel,
)

MAC = r"        return $sign === sha1(\sprintf('%s%s', \json_encode($params), $this->signKey));"
SAME_DEFECT = r"    return $token === sha1(\sprintf('%s%s', \json_encode($data), $this->key));"


def test_two_instances_of_one_defect_share_a_shape():
    # Variable and property names differ; the construct does not.
    assert variants.shape(MAC) == variants.shape(SAME_DEFECT)


def test_the_call_survives_normalisation():
    """The distinction the whole module rests on.

    Clustering strips identifiers because two firings of one rule differ only in
    names. Here the call *is* the defect — strip `sha1(` and every line matches.
    """
    assert "sha1(" in variants.shape(MAC)
    assert "===" in variants.shape(MAC)


def test_a_called_member_is_not_mistaken_for_a_read_one():
    # A greedy identifier defeated an earlier lookahead: `String.valueOf(`
    # matched as `valueO` with `f(` left over, turning a call into a member read.
    assert "valueOf(" in variants.shape("String s = String.valueOf(new Random().nextLong());")


def test_an_ordinary_line_is_not_a_pattern():
    # A shape that matches half the codebase finds nothing useful.
    for line in ("return $x;", "$id = 5;", "}"):
        assert not variants.is_distinctive(variants.shape(line))


def _seed(path="a.php", line=177):
    record = TriageRecord(
        finding_id="seed-1",
        cwe="CWE-327",
        file_path=path,
        start_line=line,
        kind="weakness",
        verdict=Verdict(
            verdict=VerdictLabel.confirmed,
            evidence_class=EvidenceClass.exploitable_dataflow,
            confidence=0.9,
            reason="homebrew MAC",
        ),
    )
    return (record, MAC)


def test_a_variant_in_another_file_is_found(tmp_path):
    (tmp_path / "Other.php").write_text(f"<?php\nclass X {{\n{SAME_DEFECT}\n}}\n", encoding="utf-8")
    found = variants.search([_seed()], [], [tmp_path])
    assert len(found) == 1
    assert found[0].file_path.endswith("Other.php")
    assert found[0].line == 3


def test_a_place_the_scanner_already_reported_is_not_a_variant(tmp_path):
    """It has a verdict already; re-surfacing it is duplicate work."""
    (tmp_path / "Other.php").write_text(f"<?php\n{SAME_DEFECT}\n", encoding="utf-8")
    reported = Finding(
        finding_id="f",
        scanner="semgrep",
        code_context=CodeContext(file_path="/src/Other.php", start_line=2, snippet=SAME_DEFECT),
    )
    assert variants.search([_seed()], [reported], [tmp_path]) == []


def test_one_location_is_reported_once_per_seed(tmp_path):
    """Two weaknesses on one line — a timing comparison and a weak hash — share
    a seed location, and would otherwise report the same candidate twice."""
    (tmp_path / "Other.php").write_text(f"<?php\n{SAME_DEFECT}\n", encoding="utf-8")
    timing, weak = _seed(), _seed()
    timing[0].finding_id, weak[0].finding_id = "seed-a", "seed-b"
    assert len(variants.search([timing, weak], [], [tmp_path])) == 1


def test_a_seed_without_a_distinctive_shape_contributes_nothing(tmp_path):
    (tmp_path / "Other.php").write_text("<?php\nreturn $x;\n", encoding="utf-8")
    record, _ = _seed()
    assert variants.search([(record, "return $x;")], [], [tmp_path]) == []
