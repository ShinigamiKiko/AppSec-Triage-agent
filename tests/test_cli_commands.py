"""Every subcommand parses, runs, and exits with the code it promises.

Written before splitting `cli.py` apart, because the module had 869 lines, nine
commands and two tests — neither of which invoked a command. A refactor guarded
only by "it still imports" is not guarded.

The read-only commands run for real. The ones that spend money or execute third
-party binaries are exercised through the parser only: what can break in a move
is the wiring, and the wiring is what the parser holds.
"""

from __future__ import annotations

import json

import pytest

from appsec_triage import cli


def run(argv: list[str]) -> int:
    return cli.main(argv)


@pytest.mark.parametrize("argv", [
    ["scanners"],
    ["providers"],
    ["prompts"],
    ["doctor"],
])
def test_a_read_only_command_runs_and_succeeds(argv, capsys):
    assert run(argv) == 0
    assert capsys.readouterr().out.strip()


@pytest.mark.parametrize("argv", [
    ["triage", "findings.json"],
    ["scan", "."],
    ["run", "."],
    ["queue", "v.jsonl"],
    ["variants", "v.jsonl"],
    ["bench", "corpus.jsonl"],
])
def test_every_command_is_wired_to_a_handler(argv):
    """The failure a move introduces: a parser entry with no `func`."""
    args = cli.build_parser().parse_args(argv)
    assert callable(getattr(args, "func", None))


def test_an_unknown_command_is_rejected():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["not-a-command"])


def _verdict_line(finding_id="f1", verdict="confirmed"):
    return json.dumps({
        "finding_id": finding_id,
        "cwe": "CWE-89",
        "file_path": "src/App.php",
        "start_line": 10,
        "kind": "weakness",
        "verdict": {
            "verdict": verdict,
            "evidence_class": "EXPLOITABLE_DATAFLOW",
            "confidence": 0.8,
            "confidence_band": "high",
            "reason": "r",
            "requires_human_review": True,
        },
        "decided_by": "llm",
    })


def test_queue_builds_from_a_verdict_log(tmp_path, capsys):
    log = tmp_path / "verdicts.jsonl"
    log.write_text(_verdict_line() + "\n", encoding="utf-8")
    assert run(["queue", str(log)]) == 0
    assert "review item" in capsys.readouterr().out


def test_variants_reports_its_seeds(tmp_path, capsys):
    """The seed list is the safety surface: this search multiplies its input."""
    log = tmp_path / "verdicts.jsonl"
    log.write_text(_verdict_line() + "\n", encoding="utf-8")
    assert run(["variants", str(log), "--source-root", str(tmp_path)]) == 0
    assert "seed" in capsys.readouterr().err.lower()


def test_variants_says_so_when_there_is_nothing_to_seed_from(tmp_path, capsys):
    log = tmp_path / "verdicts.jsonl"
    log.write_text(_verdict_line(verdict="false_positive") + "\n", encoding="utf-8")
    assert run(["variants", str(log)]) == 0
    assert "no confirmed" in capsys.readouterr().err


def test_a_missing_input_file_exits_two_not_one(tmp_path):
    """Exit 1 is the CI gate tripping; 2 is the tool failing to start. A caller
    that cannot tell them apart will block merges on a broken container."""
    assert run(["triage", str(tmp_path / "nope.json")]) == 2
