"""Source resolver widening and quote-grounding edge cases."""

from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.config import (
    HeuristicsConfig,
)
from appsec_triage.models import VerdictLabel
from appsec_triage.pipeline import TriagePipeline


def test_source_resolver_widens_a_cropped_snippet(tmp_path):
    """Bandit crops to the flagged lines, cutting the opening of a multi-line call."""
    from appsec_triage.context.source import SourceResolver

    src = tmp_path / "pkg" / "man_pages.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "import subprocess\n"
        "\n"
        "def show(program):\n"
        "    subprocess.Popen(\n"
        "        [MAN_COMMAND, program],\n"
        "        shell=False,\n"
        "    )\n",
        encoding="utf-8",
    )
    resolver = SourceResolver([tmp_path])
    win = resolver.window("pkg/man_pages.py", 5, 6, context=3)

    assert win and win.resolved
    assert "subprocess.Popen(" in win.text, "the call opening must now be quotable"
    assert resolver.stats()["resolved"] == 1


def test_source_resolver_refuses_paths_outside_its_roots(tmp_path):
    """A scanner report is untrusted input; traversal must not read anything."""
    from appsec_triage.context.source import SourceResolver

    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("top secret\n", encoding="utf-8")

    resolver = SourceResolver([root])
    assert resolver.window("../secret.txt", 1, 1, context=2) is None
    assert resolver.window("ok.py", 1, 1, context=2) is not None


def test_unresolvable_path_falls_back_to_the_scanner_snippet(tmp_path):
    from appsec_triage.context import builder, heuristics
    from appsec_triage.context.source import SourceResolver

    finding = _finding("assert x == 1", cwe="CWE-703", path="not/on/disk.py")
    heur = heuristics.evaluate(finding, HeuristicsConfig())
    pkg = builder.build(finding, heur, _cfg(), None, SourceResolver([tmp_path]))

    assert pkg.code_widened is False
    assert "assert x == 1" in pkg.code_context


def test_multiline_quote_survives_the_line_number_gutter():
    """Regression: rendering `  45 | code` broke every multi-line quote.

    The model copies source lines; the haystack had a line number wedged between
    each pair. Grounding must canonicalize the gutter away on both sides.
    """
    from appsec_triage.validate.postvalidation import quote_is_grounded

    haystack = (
        "=== CODE CONTEXT (read from the file, `line | source`) ===\n"
        "   43 | def show(program):\n"
        "   44 |     subprocess.Popen(\n"
        "   45 |         [MAN_COMMAND, program],\n"
        "   46 |         shell=False,\n"
        "   47 |     )\n"
    )
    quoted_by_model = "subprocess.Popen(\n    [MAN_COMMAND, program],\n    shell=False,\n)"
    assert quote_is_grounded(quoted_by_model, haystack, 0.85)
    # A genuinely invented line must still be rejected.
    assert not quote_is_grounded("subprocess.Popen(cmd, shell=True)", haystack, 0.85)


def test_prose_in_the_evidence_field_is_dropped_not_fatal():
    """Measured on a real repo: this model mixes commentary into `evidence`.

    Failing the verdict for that turned 19 of 43 sound conclusions into
    `unknown`. The property to enforce is that *something* verifiable supports a
    decisive verdict, not that the model never editorialises.
    """
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(
        _verdict_json(
            evidence=[
                {"quote": 'String token = "${SERVICE_TOKEN}";', "why": "the value is a template"},
                {"quote": "The literal is a config placeholder", "why": "prose in the quote field"},
            ]
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive, "verdict must survive"
    assert [e.quote for e in record.verdict.evidence] == ['String token = "${SERVICE_TOKEN}";']
    assert any("unverified_evidence_dropped" in o for o in record.overrides)


def test_verdict_with_no_verifiable_quote_at_all_is_still_downgraded():
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(_verdict_json(evidence=["The code looks fine to me", "Nothing suspicious was found here"]))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("hallucinated_evidence" in o for o in record.overrides)


# --- scanners: a crashed scanner must never read as a clean codebase -----------
