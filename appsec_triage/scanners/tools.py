"""Concrete scanners: CodeQL · Psalm · Wolfee."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import quoteattr

from .base import Availability, Scanner, ScannerError, ScanResult

log = logging.getLogger(__name__)

_CODEQL_LANGS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".java": "java", ".kt": "java", ".go": "go", ".rb": "ruby",
    ".cs": "csharp", ".cpp": "cpp", ".cc": "cpp", ".c": "cpp", ".h": "cpp",
    ".swift": "swift", ".rs": "rust",
}

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "target", "build", "dist", "__pycache__"}


def exclude_directory(name: str) -> None:
    """Keep the scanners out of a directory for the rest of this process."""
    name = (name or "").strip().strip("/")
    if not name or "/" in name:
        return
    _SKIP_DIRS.add(name)

class WolfeeScanner(Scanner):
    """Wolfee SCA scan with source-aware dependency reachability."""

    name = "wolfee"

    @property
    def writes_stdout(self) -> bool:
        return False

    @property
    def success_exit_codes(self) -> frozenset[int]:
        return frozenset(range(256))

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("wolfee"), "version"]

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            self.resolve_binary("wolfee"), "scan", "--reachable", str(target),
            "--format", "sarif", "--output", str(out_file), "--quiet",
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise ScannerError("wolfee must run natively; configure binary: with the wolfee executable path")


class PsalmScanner(Scanner):
    """Psalm interprocedural taint analysis for PHP."""

    name = "psalm"

    def scan(self, target: Path, out_dir: Path) -> ScanResult:
        target = Path(target).resolve()
        # Psalm writes a file itself: a failed invocation must not reuse an old report.
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            (Path(out_dir) / f"{self.name}{self.output_suffix}").unlink(missing_ok=True)
        except OSError as exc:
            return ScanResult(scanner=self.name, ok=False, error=f"cannot clear previous Psalm report: {exc}")
        configured = next((target / name for name in ("psalm.xml", "psalm.xml.dist")
                            if (target / name).is_file()), None)
        self._runtime_config = configured
        self._runtime_root = target
        temporary = None
        if configured is None or not (target / "vendor" / "autoload.php").is_file():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", prefix="psalm-autonomous-", dir=out_dir,
                encoding="utf-8", delete=False,
            ) as handle:
                # vendor/ is read for types through the autoloader, never
                # analysed: the taint paths wanted are the project's own, and
                # analysing an old dependency tree is what makes Psalm crash.
                autoload = target / "vendor" / "autoload.php"
                # Psalm refuses a config naming a directory that is not there,
                # so only the ones this project actually has are listed.
                skip = [target / name for name in ("vendor", "node_modules")
                        if (target / name).is_dir()]
                ignored = "".join(
                    f'      <directory name={quoteattr(str(path))} />\n' for path in skip)
                handle.write(
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<psalm xmlns="https://getpsalm.org/schema/config" errorLevel="8"'
                    + (f' autoloader={quoteattr(str(autoload))}' if autoload.is_file() else "")
                    + '>\n'
                    '  <projectFiles>\n'
                    f'    <directory name={quoteattr(str(target))} />\n'
                    + (f'    <ignoreFiles>\n{ignored}    </ignoreFiles>\n' if ignored else "")
                    + '  </projectFiles>\n'
                    '</psalm>\n'
                )
                temporary = Path(handle.name)
            self._runtime_config = temporary
            # The project, not the directory the report is written to: --root is
            # what Psalm resolves the analysed tree against.
            self._runtime_root = target
        try:
            return super().scan(target, out_dir)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @property
    def writes_stdout(self) -> bool:
        return False

    @property
    def success_exit_codes(self) -> frozenset[int]:
        """0 clean · 1/2 issues found; `report_health` is the real gate."""
        return frozenset({0, 1, 2})

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("psalm"), "--version"]

    def _probe_docker(self) -> Availability:
        return Availability(
            False, detail="psalm is native-only here (autonomous analysis uses the local Psalm binary)"
        )

    def report_health(self, path: Path) -> str | None:
        """Zero taint findings is a real clean result, not a broken run."""
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"report is not readable JSON: {exc}"
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list) or not doc["runs"]:
            return "report is not SARIF"
        for run in doc["runs"]:
            if not isinstance(run, dict) or not isinstance(run.get("results"), list):
                return "SARIF run has no results array"
            for inv in run.get("invocations") or []:
                if inv.get("executionSuccessful") is False:
                    detail = (inv.get("exitCodeDescription") or "").strip()
                    return f"SARIF reports executionSuccessful=false{': ' + detail if detail else ''}"
        return None

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        config = getattr(self, "_runtime_config", None)
        root = getattr(self, "_runtime_root", target)
        return [
            self.resolve_binary("psalm"),
            *( [f"--config={config}"] if config else []),
            "--taint-analysis",
            f"--report={out_file.resolve()}",
            f"--root={root}",
            "--no-progress",
            "--no-cache",
            "--no-diff",
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise NotImplementedError


class CodeQLScanner(Scanner):
    """CodeQL — the only two-phase tool here."""

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
        """Every CodeQL language present in the tree, most-frequent first."""
        if self.cfg.language:
            return [self.cfg.language]
        counts: Counter[str] = Counter()
        for path in target.rglob("*"):
            if not path.is_file() or _SKIP_DIRS & set(path.parts):
                continue
            if lang := _CODEQL_LANGS.get(path.suffix.lower()):
                counts[lang] += 1
        return [lang for lang, _ in counts.most_common()]


    MANIFEST = ".codeql-databases.json"

    @staticmethod
    def database_dir(out_dir: Path | str, language: str) -> Path:
        """Where this language's database lives."""
        return Path(out_dir) / f".codeql-db-{language}"

    @classmethod
    def databases(cls, out_dir: Path | str) -> dict[str, Path]:
        """Language → database, as recorded by the scan that built them."""
        manifest = Path(out_dir) / cls.MANIFEST
        try:
            recorded = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        found = {}
        for language, where in (recorded or {}).items():
            path = Path(where)
            if (path / "codeql-database.yml").is_file():
                found[str(language)] = path
        return found

    @staticmethod
    def _merge_runs(docs: list[dict]) -> dict:
        """Fold several single-language SARIF documents into one multi-run file."""
        return {
            "version": docs[0].get("version", "2.1.0"),
            "$schema": docs[0].get("$schema", "https://json.schemastore.org/sarif-2.1.0.json"),
            "runs": [run for doc in docs for run in (doc.get("runs") or [])],
        }

    def _analyze_one(self, exe: str, target: Path, out_dir: Path, language: str, part: Path) -> str | None:
        """Create a database for one language and analyze it into `part`."""
        db_dir = self.database_dir(out_dir, language)
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
                    check=False,
                )
                if proc.returncode != 0:
                    tail = "\n".join((proc.stderr or "").strip().splitlines()[-6:])
                    return f"'{phase}' exited {proc.returncode}: {tail[:300]}"
        except subprocess.TimeoutExpired:
            return f"timed out after {self.cfg.timeout_s}s (a compiled language needs a working build)"
        except OSError as exc:
            return str(exc)
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
        built: dict[str, str] = {}
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
            built[language] = str(self.database_dir(out_dir, language))
            try:
                docs.append(json.loads(part.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                failures.append(f"{language}: unreadable SARIF ({exc})")
            finally:
                part.unlink(missing_ok=True)

        duration = time.monotonic() - started
        note = "; ".join(failures)
        if built:
            (out_dir / self.MANIFEST).write_text(
                json.dumps(built, indent=2), encoding="utf-8")
            log.info("codeql databases kept for the dependency phase: %s",
                     ", ".join(sorted(built)))
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
    "wolfee": WolfeeScanner,
    "codeql": CodeQLScanner,
    "psalm": PsalmScanner,
}
