"""The four triage rules and the two ranking axes.

Rules 13, 1, 3 and 6 from Google's mantis (Apache-2.0 — the ideas are reused,
the wording here is our own). Each exists because of a specific way a triage
model goes wrong, and each is stated in the prompt where the model can act on
it rather than in a docstring where it cannot.
"""

from __future__ import annotations

import pytest

from appsec_triage.models import Verdict, VerdictLabel, EvidenceClass, TriageRecord
from appsec_triage.prompts import registry
from appsec_triage import prioritize
from appsec_triage.config import TriageQueueConfig


@pytest.fixture(scope="module")
def system_prompt() -> str:
    text, _ = registry.render_system("CWE-89")
    return text.lower()


def test_a_confirmed_dataflow_must_name_where_untrusted_data_enters(system_prompt):
    # Rule 13. "It comes from the request" without a location is an assumption.
    assert "ingress point" in system_prompt
    assert "file:line" in system_prompt


def test_intrinsic_flaws_are_exempt_from_needing_an_ingress_point(system_prompt):
    # The carve-out that keeps rule 13 from hiding hardcoded keys and broken
    # crypto — neither needs a caller to be a defect.
    assert "intrinsic flaws" in system_prompt
    assert "does not need to be reachable" in system_prompt


def test_a_hypothetical_bad_caller_is_not_a_vulnerability(system_prompt):
    # Rule 1, with its exception: a validator *is* judged on bad input.
    assert "hypothetical caller" in system_prompt or "hypothetical" in system_prompt
    assert "validator" in system_prompt


def test_a_race_is_not_dismissed_for_being_unlikely(system_prompt):
    # Rule 3. Strict reproducibility, except where the attacker can retry: the
    # attacker is not rolling dice once.
    assert "one time in a million" in system_prompt
    assert "automated and repeated" in system_prompt


def test_a_test_directory_never_closes_a_finding(system_prompt):
    # Rule 6. Fixtures ship and example servers get deployed; the path lowers
    # priority and settles nothing.
    assert "decides nothing" in system_prompt
    assert "never on a directory name" in system_prompt


def _record(exploitability=None, impact=None, verdict=VerdictLabel.confirmed) -> TriageRecord:
    return TriageRecord(
        finding_id="f",
        cwe="CWE-89",
        file_path="a.php",
        verdict=Verdict(
            verdict=verdict,
            evidence_class=EvidenceClass.exploitable_dataflow,
            confidence=0.8,
            exploitability=exploitability,
            impact=impact,
            reason="r",
        ),
    )


def test_a_trivially_exploitable_finding_outranks_a_difficult_one():
    """What a CWE weight cannot express.

    Two findings of the same class: one reachable with a crafted URL, one
    needing chained conditions. The consequence table scores them identically.
    """
    easy, _ = prioritize.score(_record("trivial", "critical"))
    hard, _ = prioritize.score(_record("difficult", "low"))
    assert easy > hard


def test_the_axes_do_not_reorder_closed_findings():
    # Ranking things the pipeline already closed spends attention on nothing.
    with_axes, reasons = prioritize.score(_record("trivial", "critical", VerdictLabel.false_positive))
    without, _ = prioritize.score(_record(None, None, VerdictLabel.false_positive))
    assert with_axes == without
    assert not any("exploitability" in r for r in reasons)


def test_a_missing_axis_costs_nothing():
    # An older audit log has neither field; it must still score.
    assert prioritize.score(_record(None, None))[0] > 0
