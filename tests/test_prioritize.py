"""Review-queue budget/clustering and the stack-convention prompt section."""

from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _record, _verdict_json

from appsec_triage.pipeline import TriagePipeline
from appsec_triage.prompts import registry


def test_queue_budget_is_a_ceiling_not_a_quota():
    """Spare capacity must not be filled with findings triage already settled."""
    from appsec_triage import prioritize
    from appsec_triage.config import TriageQueueConfig

    records = [_record("unknown", "CWE-98", "src/a.php")] + [
        _record("false_positive", "CWE-98", f"src/fp{i}.php", snippet=f"y = {i}") for i in range(30)
    ]
    queue = prioritize.build(records, TriageQueueConfig(review_budget_pct=90))

    assert len(queue.to_review) == 1, "only the unresolved finding belongs in the queue"
    assert queue.to_review[0].record.verdict.verdict.value == "unknown"


def test_clustering_collapses_one_pattern_into_one_decision():
    from appsec_triage import prioritize
    from appsec_triage.config import TriageQueueConfig

    records = [_record("unknown", "CWE-98", f"src/mod{i}/x.php") for i in range(12)]
    queue = prioritize.build(records, TriageQueueConfig(review_budget_pct=100))

    assert len(queue.to_review) == 1
    assert queue.to_review[0].cluster_size == 12

    spread = prioritize.build(records, TriageQueueConfig(review_budget_pct=100, cluster=False))
    assert len(spread.to_review) == 12


def test_exempt_items_survive_a_zero_budget():
    """A live-credential shape is cheap to check and expensive to miss."""
    from appsec_triage import prioritize
    from appsec_triage.config import TriageQueueConfig

    exempt = [
        _record(
            "false_positive",
            "CWE-798",
            f"src/a{i}.php",
            snippet=f"k={i}",
            overrides=["sanity_conflict: closed despite ['known_secret_shape']"],
        )
        for i in range(3)
    ]
    noise = [_record("false_positive", "CWE-703", f"src/n{i}.php", snippet=f"z={i}") for i in range(40)]
    queue = prioritize.build([*exempt, *noise], TriageQueueConfig(review_budget_pct=1))

    # The three collapse into one item — same rule, same CWE, same code shape —
    # which is clustering doing its job, not the budget dropping anything.
    assert len(queue.to_review) == 1, "exempt items are never deferred"
    assert queue.to_review[0].exempt
    assert queue.to_review[0].cluster_size == 3
    # 1% of 43 findings is a budget of 1; three exemptions blow through it, and
    # that has to be said out loud rather than silently dropping two of them.
    assert queue.overflowed


def test_nothing_is_deleted_by_the_budget():
    from appsec_triage import prioritize
    from appsec_triage.config import TriageQueueConfig

    records = [_record("unknown", "CWE-89", f"src/q{i}.php", snippet=f"sql{i}") for i in range(20)]
    queue = prioritize.build(records, TriageQueueConfig(review_budget_pct=10))

    assert len(queue.items) == len(queue.to_review) + len(queue.deferred)
    assert sum(i.cluster_size for i in queue.items) == 20, "every finding is still represented"


# --- stack conventions ---------------------------------------------------------


def test_symfony_is_detected_from_composer(tmp_path):
    from appsec_triage.context import stack

    (tmp_path / "composer.json").write_text(
        '{"require": {"symfony/framework-bundle": "^6.4", "doctrine/orm": "^2.17"}}', encoding="utf-8"
    )
    found = stack.detect([tmp_path])
    assert [p.id for p in found] == ["symfony"]


def test_unrelated_repo_gets_no_stack_section(tmp_path):
    """Guessing a stack wrong is worse than not guessing."""
    from appsec_triage.context import stack

    (tmp_path / "composer.json").write_text('{"require": {"monolog/monolog": "^3.0"}}', encoding="utf-8")
    assert stack.detect([tmp_path]) == []
    assert stack.render([]) == ""


def test_stack_section_is_framed_as_context_not_permission():
    """A convention that can close findings on its own is an excuse generator."""
    from appsec_triage.context import stack

    section = stack.render(stack.load_all()[:1])
    lowered = section.lower()
    assert "never *outrank* evidence" in section or "never outrank" in lowered
    assert "heuristic signal" in lowered


def test_stack_section_comes_last_in_the_system_prompt():
    """Conventions first would invite reasoning from convention, then evidence-fitting."""
    system, _ = registry.render_system("CWE-798", stack_section="## Stack conventions\nSYMFONY MARKER")

    assert system.index("Absolute rules") < system.index("SYMFONY MARKER")
    assert system.index("CWE-798 family") < system.index("SYMFONY MARKER")


def test_pipeline_injects_stack_conventions_into_the_prompt(tmp_path):
    from appsec_triage.context.source import SourceResolver

    (tmp_path / "composer.json").write_text('{"require": {"symfony/framework-bundle": "^6.4"}}', encoding="utf-8")
    (tmp_path / "app.php").write_text("<?php $password = 'x';\n", encoding="utf-8")

    # Any class will do — this is about prompt composition, not credentials,
    # and a credential is now settled before a prompt is ever built.
    finding = _finding("echo $_GET['q'];", cwe="CWE-79", path="app.php")
    client = FakeClient(_verdict_json(evidence=["echo $_GET['q'];"]))
    pipeline = TriagePipeline(client, _PROVIDER, _cfg(), source=SourceResolver([tmp_path]))
    pipeline.triage_one(finding)

    system, _user = client.calls[0]
    assert "Stack conventions" in system
    assert "resolved when the container is compiled" in system


# --- regression: the DVWA measurement ------------------------------------------
