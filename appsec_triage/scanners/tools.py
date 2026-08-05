"""Concrete scanners: Semgrep · CodeQL · Bandit · Trivy · Gitleaks.

Each one is small; the interesting content is the per-tool quirks, which is
exactly what a config file cannot express.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path

from ..config import REPO_ROOT
from .base import Availability, ScanResult, Scanner, _first_line

_CODEQL_LANGS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".java": "java", ".kt": "java", ".go": "go", ".rb": "ruby",
    ".cs": "csharp", ".cpp": "cpp", ".cc": "cpp", ".c": "cpp", ".h": "cpp",
    ".swift": "swift", ".rs": "rust",
}

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "target", "build", "dist", "__pycache__"}
_SEMGREP_EXCLUDES = [
    ".git", "vendor", "node_modules", ".run", "var", "cache", "logs",
    "_data", "_output", "build", "dist", "tmp", "tests", "tests-codeception",
]


class SemgrepScanner(Scanner):
    """Semgrep. No native Windows build exists, so Docker is the usual route.

    `--sarif` writes to stdout, which keeps the container filesystem read-only.
    The default ruleset needs network access to fetch `p/default`; a local
    ruleset (`--config <dir>`) runs fully offline — see the config comment.
    """

    name = "semgrep"

    @property
    def success_exit_codes(self) -> frozenset[int]:
        """0 clean · 1 findings · 2 partial · 7 invalid rules.

        2 is allowed because Semgrep returns it after a fully successful scan
        whenever a single target was skipped (an oversized file is enough).
        Trusting the exit code alone would either reject good scans or accept
        broken ones, so the real gate is `report_health`, which reads
        `executionSuccessful` out of the SARIF. 7 stays fatal: an invalid
        ruleset means nothing was checked.
        """
        return frozenset({0, 1, 2})

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("semgrep"), "--version"]

    def local_rules_path(self) -> Path | None:
        if not self.cfg.local_rules_dir:
            return None
        path = (REPO_ROOT / self.cfg.local_rules_dir).resolve()
        return path if path.is_dir() else None

    def _rules_args(self, mounted_at: str | None = None) -> list[str]:
        """Local rules win: the registry needs semgrep.dev, which a closed loop
        cannot reach — and depending on it would contradict the whole design."""
        if local := self.local_rules_path():
            return ["--config", mounted_at or str(local)]
        return [arg for rule in self.cfg.rules for arg in ("--config", rule)]

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            self.resolve_binary("semgrep"), "scan", *self._rules_args(),
            *(arg for directory in _SEMGREP_EXCLUDES for arg in ("--exclude", directory)),
            "--sarif", "--quiet", "--no-git-ignore", "--disable-version-check",
            "--metrics", "off",
            "--timeout", str(self.cfg.per_file_timeout_s),
            str(target),
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        local = self.local_rules_path()
        prefix = ["docker", "run", "--rm", "-v", f"{target}:/src:ro", "-w", "/src"]
        if local:
            prefix += ["-v", f"{local}:/rules:ro", "--network", "none"]
        elif not self.cfg.docker_network:
            prefix += ["--network", "none"]
        prefix += [*self.cfg.docker_args, self.cfg.image or ""]
        return [
            *prefix,
            "semgrep", "scan", *self._rules_args(mounted_at="/rules" if local else None),
            *(arg for directory in _SEMGREP_EXCLUDES for arg in ("--exclude", directory)),
            "--sarif", "--quiet", "--no-git-ignore", "--disable-version-check",
            "--metrics", "off",
            "--timeout", str(self.cfg.per_file_timeout_s),
            "/src",
        ]


class BanditScanner(Scanner):
    """Bandit (Python). Invoked as the `bandit` console script on PATH.

    Not `python -m bandit`: bandit is installed in its own isolated environment
    (pipx), so the interpreter running this process cannot import it. The
    console script is the portable entry point regardless of how it was
    installed; override the path with `binary:` in the scanner profile if needed.

    Bandit exits 1 whenever it finds anything, which the base class already
    treats as normal. Its JSON is not SARIF; the bandit ingest adapter handles it.
    """

    name = "bandit"

    @property
    def output_suffix(self) -> str:
        return ".json"

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("bandit"), "--version"]

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        argv = [self.resolve_binary("bandit"), "-r", str(target), "-f", "json", "-q"]
        if self.cfg.severity:
            argv.append("-" + "l" * {"low": 1, "medium": 2, "high": 3}.get(self.cfg.severity, 1))
        return argv

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [*self._docker_prefix(target), "bandit", "-r", "/src", "-f", "json", "-q"]

    def count_findings(self, path: Path) -> int:
        try:
            return len(json.loads(path.read_text(encoding="utf-8")).get("results") or [])
        except (OSError, json.JSONDecodeError):
            return 0


class TrivyScanner(Scanner):
    """Trivy filesystem scan: misconfigurations, secrets, vulnerable dependencies.

    Note this is the one tool here that legitimately produces CVEs — its
    `vuln` scanner reads dependency manifests, which is SCA, not SAST.
    """

    name = "trivy"

    @property
    def success_exit_codes(self) -> frozenset[int]:
        return frozenset({0})

    def _native_version_argv(self) -> list[str] | None:
        return ["trivy", "--version"]

    def _scanners_arg(self) -> list[str]:
        return ["--scanners", ",".join(self.cfg.rules or ["vuln", "secret", "misconfig"])]

    def _skip_args(self) -> list[str]:
        """Directories of build output that are not dependency manifests.

        Not an optimisation. On a real Python repository trivy timed out on a
        single `__pycache__/*.pyc` and aborted the *entire* scan — the whole SCA
        leg for that project was lost to one compiled artifact. Nothing of value
        is given up: none of these directories carries a manifest or a lockfile.
        """
        skip = ["__pycache__", "node_modules", ".git", "vendor/bundle", ".venv", "venv"]
        args: list[str] = []
        for directory in skip:
            args += ["--skip-dirs", f"**/{directory}"]
        return args

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            "trivy", "fs", "--format", "sarif", "--quiet",
            *self._scanners_arg(), *self._skip_args(), str(target),
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            *self._docker_prefix(target), "fs", "--format", "sarif", "--quiet",
            *self._scanners_arg(), *self._skip_args(), "/src",
        ]


class GitleaksScanner(Scanner):
    """Gitleaks: secrets in the working tree and in history."""

    name = "gitleaks"

    @property
    def success_exit_codes(self) -> frozenset[int]:
        return frozenset({0})

    def _native_version_argv(self) -> list[str] | None:
        return ["gitleaks", "version"]

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            "gitleaks", "detect", "--source", str(target),
            "--report-format", "sarif", "--report-path", str(out_file),
            "--no-banner", "--exit-code", "0",
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            "docker", "run", "--rm",
            "-v", f"{target}:/src:ro",
            "-v", f"{out_file.parent.resolve()}:/out",
            self.cfg.image or "zricethezav/gitleaks:latest",
            "detect", "--source", "/src",
            "--report-format", "sarif", "--report-path", f"/out/{out_file.name}",
            "--no-banner", "--exit-code", "0",
        ]

    @property
    def writes_stdout(self) -> bool:
        return False


class PsalmScanner(Scanner):
    """Psalm taint analysis — the only real source->sink dataflow for PHP.

    CodeQL has no PHP support and never will, so for PHP this is the one tool that
    answers "does untrusted input actually reach this sink" rather than "does this
    line match a dangerous pattern". Its SARIF carries `codeFlows`, which the
    ingest layer prefers over any pattern match at the same location.

    Two things make Psalm unlike the other scanners here:

    * **It needs the project's autoloader.** Taint tracking follows calls across
      files, so Psalm has to resolve the classes it analyses — it runs *inside*
      the target (`run_in_target`) and reads `psalm.xml` + `vendor/autoload.php`
      there. A target without `composer install` (or at least
      `composer dump-autoload`) gives Psalm nothing to trace, and it says so.
    * **It writes its report to a file, not stdout** (`--report`), so
      `writes_stdout` is False and the base class does not capture stdout.

    Docker is deliberately not offered: a container has no access to the target's
    installed dependencies, which is exactly what taint tracking needs.
    """

    name = "psalm"

    @property
    def writes_stdout(self) -> bool:
        return False

    @property
    def success_exit_codes(self) -> frozenset[int]:
        """0 clean · 1/2 issues found. Psalm exits non-zero once it reports
        anything, the same shape as Semgrep; `report_health` is the real gate."""
        return frozenset({0, 1, 2})

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("psalm"), "--version"]

    def _probe_docker(self) -> Availability:
        return Availability(
            False, detail="psalm is native-only here (taint tracking needs the target's own autoloader)"
        )

    def report_health(self, path: Path) -> str | None:
        """Zero taint findings is a real clean result, not a broken run.

        The base check treats a SARIF with no rules and no results as "the
        scanner ran nothing" — correct for Semgrep, where an empty ruleset means
        nothing was inspected. Taint analysis is different: a codebase with no
        reachable source->sink flow legitimately yields zero results, and a
        target where taint tracking cannot recognise framework sources (a Symfony
        app without psalm/plugin-symfony) also yields zero. Rejecting those would
        turn a clean taint pass into a scan failure. A genuinely broken Psalm
        (missing autoloader) writes no report at all and is caught upstream by
        the exit code and the "no report written" gate. We keep only the
        authoritative signal — SARIF's own executionSuccessful flag."""
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"report is not readable JSON: {exc}"
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            return "report is not SARIF"
        for run in doc["runs"]:
            for inv in run.get("invocations") or []:
                if inv.get("executionSuccessful") is False:
                    detail = (inv.get("exitCodeDescription") or "").strip()
                    return f"SARIF reports executionSuccessful=false{': ' + detail if detail else ''}"
        return None

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            self.resolve_binary("psalm"),
            "--taint-analysis",
            f"--report={out_file.resolve()}",
            f"--root={target}",
            "--no-progress",
            "--no-cache",
            "--no-diff",
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise NotImplementedError


class CodeQLScanner(Scanner):
    """CodeQL — the only two-phase tool here.

    `database create` compiles the source, then `database analyze` runs a query
    suite against it. That first phase is the expensive one (minutes, and for
    compiled languages it needs a working build), which is why CodeQL is not a
    sensible default and gets its own timeout.

    Docker is deliberately not offered: the official image is large and the
    database directory has to survive between the two phases, which makes a
    read-only mount pointless.
    """

    name = "codeql"

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("codeql"), "version", "--format", "terse"]

    def _probe_docker(self) -> Availability:
        return Availability(False, detail="codeql is native-only here (two-phase, needs a writable database dir)")

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise NotImplementedError

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise NotImplementedError

    def detect_languages(self, target: Path) -> list[str]:
        """Every CodeQL language present in the tree, most-frequent first.

        `cfg.language` pins a single language and skips detection. Otherwise each
        detected language gets its own database and analysis pass: CodeQL
        compiles exactly one language per database, so a mixed Go + TS repo needs
        two passes. JS and TS share the `javascript` extractor, so a JS/TS repo
        is still one pass — the map collapses `.ts`/`.tsx` to `javascript`.
        """
        if self.cfg.language:
            return [self.cfg.language]
        counts: Counter[str] = Counter()
        for path in target.rglob("*"):
            if not path.is_file() or _SKIP_DIRS & set(path.parts):
                continue
            if lang := _CODEQL_LANGS.get(path.suffix.lower()):
                counts[lang] += 1
        return [lang for lang, _ in counts.most_common()]

    def detect_language(self, target: Path) -> str | None:
        """Dominant CodeQL language only — retained for single-language callers."""
        langs = self.detect_languages(target)
        return langs[0] if langs else None

    @staticmethod
    def _merge_runs(docs: list[dict]) -> dict:
        """Fold several single-language SARIF documents into one multi-run file.

        The ingest already iterates `runs` (sarif.py), so concatenating each
        language's runs under one document is all a downstream reader needs: one
        codeql.sarif.json carrying every language's results, one manifest entry,
        no change to dedup.
        """
        return {
            "version": docs[0].get("version", "2.1.0"),
            "$schema": docs[0].get("$schema", "https://json.schemastore.org/sarif-2.1.0.json"),
            "runs": [run for doc in docs for run in (doc.get("runs") or [])],
        }

    def _analyze_one(self, exe: str, target: Path, out_dir: Path, language: str, part: Path) -> str | None:
        """Create a database for one language and analyze it into `part`.

        Returns None on success or a short error string. Isolated per language so
        one broken build (a compiled language with no toolchain) does not sink the
        languages that would analyze cleanly. The database is removed afterwards —
        hundreds of megabytes per language would otherwise pile up on a mixed repo.
        """
        db_dir = out_dir / f".codeql-db-{language}"
        shutil.rmtree(db_dir, ignore_errors=True)
        create = [
            exe, "database", "create", str(db_dir),
            f"--language={language}", f"--source-root={target}", "--overwrite",
        ]
        analyze = [
            exe, "database", "analyze", str(db_dir),
            f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls",
            "--format=sarif-latest", f"--output={part}",
        ]
        try:
            for phase, argv in (("database create", create), ("database analyze", analyze)):
                proc = subprocess.run(
                    argv, capture_output=True, text=True,
                    timeout=self.cfg.timeout_s, encoding="utf-8", errors="replace",
                )
                if proc.returncode != 0:
                    tail = "\n".join((proc.stderr or "").strip().splitlines()[-6:])
                    return f"'{phase}' exited {proc.returncode}: {tail[:300]}"
        except subprocess.TimeoutExpired:
            return f"timed out after {self.cfg.timeout_s}s (a compiled language needs a working build)"
        except OSError as exc:
            return str(exc)
        finally:
            shutil.rmtree(db_dir, ignore_errors=True)
        return None if part.is_file() else "analyze produced no SARIF"

    def scan(self, target: Path, out_dir: Path) -> ScanResult:
        avail = self.available()
        if not avail.usable:
            return ScanResult(scanner=self.name, ok=False, error=str(avail))

        target = Path(target).resolve()
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{self.name}{self.output_suffix}"

        languages = self.detect_languages(target)
        if not languages:
            return ScanResult(
                scanner=self.name, ok=False,
                error="could not detect a CodeQL language in the target; set `language` in the scanner profile",
            )

        exe = self.resolve_binary("codeql")
        started = time.monotonic()
        docs: list[dict] = []
        failures: list[str] = []
        last_cmd = [exe, "database", "analyze"]
        for language in languages:
            part = out_dir / f".codeql-{language}.sarif.json"
            part.unlink(missing_ok=True)
            last_cmd = [
                exe, "database", "analyze", f"--language={language}",
                f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls",
            ]
            if err := self._analyze_one(exe, target, out_dir, language, part):
                failures.append(f"{language}: {err}")
                continue
            try:
                docs.append(json.loads(part.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                failures.append(f"{language}: unreadable SARIF ({exc})")
            finally:
                part.unlink(missing_ok=True)

        duration = time.monotonic() - started
        note = "; ".join(failures)
        if not docs:
            return ScanResult(
                scanner=self.name, ok=False, command=last_cmd, mode="native",
                version=avail.version, duration_s=duration,
                error=note or "analyze produced no SARIF",
            )

        out_file.write_text(json.dumps(self._merge_runs(docs)), encoding="utf-8")
        return ScanResult(
            scanner=self.name, ok=out_file.is_file(),
            output_path=out_file if out_file.is_file() else None,
            findings=self.count_findings(out_file) if out_file.is_file() else 0,
            duration_s=duration, command=last_cmd, version=avail.version, mode="native",
            error=None if out_file.is_file() else "failed to write merged SARIF",
            stderr_tail=f"partial: {note}" if failures else "",
        )


REGISTRY: dict[str, type[Scanner]] = {
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "trivy": TrivyScanner,
    "gitleaks": GitleaksScanner,
    "codeql": CodeQLScanner,
    "psalm": PsalmScanner,
}
