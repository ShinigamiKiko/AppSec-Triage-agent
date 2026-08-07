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
from types import SimpleNamespace

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


def test_run_adds_cdxgen_osv_findings_and_coverage(tmp_path, monkeypatch):
    from appsec_triage.models import CodeContext, DependencyInfo, Finding
    from appsec_triage.sca import discover as discover_mod

    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "out"

    def fake_scan(args):
        scan_dir = args.out
        scan_dir.mkdir(parents=True)
        (scan_dir / "scan-manifest.json").write_text(
            json.dumps({"target": str(target), "scans": [{"scanner": "semgrep", "ok": True, "findings": 0}]}),
            encoding="utf-8",
        )
        return 0

    finding = Finding(
        finding_id="GHSA-x-demo/pkg",
        scanner="cdxgen+osv",
        rule_id="GHSA-x",
        code_context=CodeContext(file_path="composer.json"),
        dependency=DependencyInfo(package="demo/pkg", ecosystem="composer", installed_version="1.0.0"),
    )
    discovery = SimpleNamespace(
        findings=[finding], packages_checked=1, packages_succeeded=1, problems=[], usable=True
    )
    monkeypatch.setattr(cli, "cmd_scan", fake_scan)
    monkeypatch.setattr(discover_mod, "discover", lambda _: discovery)
    monkeypatch.setattr(cli, "_run_triage", lambda *args, **kwargs: 0)

    args = SimpleNamespace(target=str(target), out=str(out), scanner=None)
    assert cli.cmd_run(args) == 0

    dependencies = json.loads((out / "scans" / "dependencies.json").read_text(encoding="utf-8"))
    assert dependencies[0]["scanner"] == "cdxgen+osv"
    manifest = json.loads((out / "scans" / "scan-manifest.json").read_text(encoding="utf-8"))
    assert manifest["scans"][-1]["scanner"] == "cdxgen+osv"
    assert manifest["scans"][-1]["ok"] is True


def test_full_go_run_cannot_omit_govulncheck(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    target = tmp_path / "target"
    target.mkdir()
    (target / "main.go").write_text("package main", encoding="utf-8")
    monkeypatch.setattr(cli, "scanners_for_target", lambda _: ["codeql", "govulncheck"])
    monkeypatch.setattr(cli, "cmd_scan", lambda _: pytest.fail("scan must not start with incomplete Go tooling"))

    args = SimpleNamespace(target=str(target), out=str(tmp_path / "out"), scanner=["codeql"])

    assert cli.cmd_run(args) == 2
    assert "govulncheck" in capsys.readouterr().err


def test_full_go_run_cannot_disable_gopls(tmp_path, monkeypatch, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.go").write_text("package main", encoding="utf-8")
    monkeypatch.setattr(cli, "scanners_for_target", lambda _: ["codeql", "govulncheck"])
    monkeypatch.setattr(cli, "cmd_scan", lambda _: pytest.fail("scan must not start without gopls"))

    args = SimpleNamespace(
        target=str(target),
        out=str(tmp_path / "out"),
        scanner=None,
        no_lsp=True,
        lsp_config=None,
    )

    assert cli.cmd_run(args) == 2
    assert "requires gopls" in capsys.readouterr().err
