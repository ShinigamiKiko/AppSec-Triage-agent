"""Scanner and combined scan/triage commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from ... import scanners
from ...scanners import tools as scanner_tools
from ...scanners.selection import scanners_for_target
from ..common import run_triage


def cmd_sbom(args: argparse.Namespace) -> int:
    from ...sca import discover as discover_mod
    target = Path(args.target).resolve()
    out_path = Path(args.out)
    result = discover_mod.discover(target, sbom_path=Path(args.sbom) if args.sbom else None, limit=args.limit or 0)
    payload = [json.loads(f.model_dump_json(exclude_none=True)) for f in result.findings]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"→ пакетов опрошено: {result.packages_checked}", file=sys.stderr)
    print(f"→ находок: {len(result.findings)} -> {out_path}", file=sys.stderr)
    for problem in result.problems[:10]: print(f"  ! {problem}", file=sys.stderr)
    if result.problems: print(f"  ! всего проблем: {len(result.problems)} — эти пакеты не проверены, а не признаны чистыми", file=sys.stderr)
    return 0 if result.usable else 2


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out_dir = Path(args.out)
    chosen = args.scanner or scanners_for_target(target)
    if not chosen:
        print("error: no usable scanner — run `appsec-triage scanners` to see why", file=sys.stderr)
        return 2
    print(f"→ scanning {target} with: {', '.join(chosen)}", file=sys.stderr)
    results = scanners.scan_all(target, chosen, out_dir, on_start=lambda n: print(f"  … {n}", end="", file=sys.stderr, flush=True))
    for r in results:
        status = f"{r.findings} finding(s) in {r.duration_s:.0f}s" if r.ok else f"FAILED: {r.error}"
        print(f"\r  {'✓' if r.ok else '✗'} {r.scanner:<10} {status}", file=sys.stderr)
        if r.note:
            print(f"    ! {r.note}", file=sys.stderr)
    manifest = scanners.write_manifest(target, results, out_dir)
    print(f"→ manifest: {manifest}", file=sys.stderr)
    for r in results:
        if r.ok and r.output_path: print(r.output_path)
    return 0 if any(r.ok for r in results) else 1


def _prepare_sbom(target: Path, scan_dir: Path, given: str | None) -> Path | None:
    """The run's SBOM, written where ingest will not read it as findings."""
    from ...sca import sbom as sbom_mod

    if given:
        return Path(given)
    if not sbom_mod.available():
        print("  ! cdxgen не установлен — прямые и транзитивные пакеты не различить", file=sys.stderr)
        return None
    document, problem = sbom_mod.generate(target)
    if document is None:
        print(f"  ! SBOM не снят: {problem}", file=sys.stderr)
        return None
    path = scan_dir / ".sbom.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    components = len(sbom_mod.components(document))
    print(f"→ SBOM: {components} компонент(ов) -> {path}", file=sys.stderr)
    return path


def _install_dependencies(target: Path) -> Path:
    """A copy of `target` with its dependencies installed, or `target` itself.

    The bridge into a parent package reads the parent's installed source; without
    it every transitive finding ends as "the path could not be checked".
    """
    from ...sca import install as install_mod

    if not install_mod.needs_install(target):
        return target
    workspace = Path(os.environ.get("APPSEC_WORKSPACE")
                     or Path(tempfile.gettempdir()) / "appsec-workspace")
    sources = ([f"npm с {install_mod.PUBLIC_REGISTRY}"] if install_mod._needs_npm(target) else []) \
        + (["composer с GitHub по коммитам из composer.lock"] if install_mod._needs_composer(target) else [])
    print(f"→ зависимости: ставлю {', '.join(sources)} в копию проекта {workspace}", file=sys.stderr)
    result = install_mod.install(target, workspace)
    if result.rewritten:
        print(f"  → {result.rewritten} адрес(ов) lock-файла переведены с приватного прокси на "
              "публичный реестр — версии прежние", file=sys.stderr)
    for item in result.dropped[:12]:
        print(f"  ! не установлен: {item}", file=sys.stderr)
    if not result.usable:
        print(f"  ! зависимости не поставлены: {result.problem or 'дерево пустое'} — "
              "скан пойдёт без установленных зависимостей", file=sys.stderr)
        return target
    if result.problem:
        print(f"  ! установлено не всё: {result.problem}", file=sys.stderr)
    versions = "из lock-файла" if result.faithful else "разрешены заново — lock-файла нет"
    print(f"→ установлено пакетов: {result.installed} ({result.tool}, версии {versions})",
          file=sys.stderr)
    return result.workspace


def cmd_run(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out = Path(args.out).resolve()
    if not getattr(args, "no_preflight", False):
        from ...config import load_pipeline_config, load_provider_config
        from ..common import node_modules_problem, preflight_provider
        cfg = load_pipeline_config(getattr(args, "config", None))
        provider_cfg = load_provider_config(getattr(args, "provider", None) or cfg.provider)
        if problem := preflight_provider(provider_cfg):
            print(f"error: {problem}", file=sys.stderr)
            return 2
        args._preflight_done = True
        print(f"→ провайдер {provider_cfg.name} отвечает", file=sys.stderr)
        if getattr(args, "install_deps", False):
            target = _install_dependencies(target)
        if problem := node_modules_problem([target]):
            print(f"  ! {problem}", file=sys.stderr)
    elif getattr(args, "install_deps", False):
        target = _install_dependencies(target)
    scan_dir = out / "scans"
    if out.is_relative_to(target):
        relative = out.relative_to(target)
        scanner_tools.exclude_directory(relative.parts[0])
        print(f"→ каталог вывода {relative.parts[0]}/ внутри цели — исключён из скана", file=sys.stderr)
    if cmd_scan(argparse.Namespace(target=target, out=scan_dir, scanner=args.scanner)) != 0: return 1
    reports = [p for p in scan_dir.iterdir() if p.suffix in (".json", ".sarif") and p.name != "scan-manifest.json"]
    if not reports:
        print("error: scanners produced no readable report", file=sys.stderr)
        return 1
    wolfee_report = scan_dir / "wolfee.sarif.json"
    _drop_stale_dependencies(scan_dir)
    if not getattr(args, "no_deps", False):
        sbom_file = _prepare_sbom(target, scan_dir, getattr(args, "sbom", None))
        if sbom_file:
            args.sbom = str(sbom_file)
        if not wolfee_report.is_file():
            deps_file = scan_dir / "dependencies.json"
            if cmd_sbom(argparse.Namespace(target=target, out=deps_file,
                                           sbom=str(sbom_file) if sbom_file else None,
                                           limit=0)) != 0:
                print("  ! зависимости не разобраны — триаж пойдёт только по находкам сканеров", file=sys.stderr)
    if not getattr(args, "govulncheck", None):
        _go_call_graph(args, target, out)
    args.scan_dir = scan_dir
    return run_triage(args, scan_dir, out, [target])


def _drop_stale_dependencies(scan_dir: Path) -> None:
    """Remove dependencies.json when wolfee reported this time.

    The file is written only when wolfee has no report; next to a fresh wolfee report it
    is a previous run's, and every .json in scans/ is read as findings — the same
    advisories were triaged twice, once from each.
    """
    stale = scan_dir / "dependencies.json"
    if (scan_dir / "wolfee.sarif.json").is_file() and stale.is_file():
        stale.unlink()
        print("→ dependencies.json прошлого прогона убран: wolfee отработал", file=sys.stderr)


def _go_call_graph(args: argparse.Namespace, target: Path, out: Path) -> None:
    """govulncheck over every Go module of the tree, for reachability only.

    wolfee runs it at the root, and a repository with its Go module in a subdirectory
    (backend/go.mod) got no call graph at all. The report feeds the chain's
    reachability; it adds no findings of its own — wolfee has reported them already.
    Outside scans/: every .json there is read as a scanner report.
    """
    import shutil

    from ...sca import govulncheck as govulncheck_mod

    wanted = {e.strip().lower() for e in os.environ.get("APPSEC_ECOSYSTEMS", "").split(",") if e.strip()}
    if wanted and not wanted & {"go", "golang"}:
        return
    if shutil.which("govulncheck") is None or not govulncheck_mod.modules(target):
        return
    from ...sca import gotoolchain

    for module in govulncheck_mod.modules(target):
        release, where = gotoolchain.project_release(target, module)
        if release:
            relative = module.relative_to(target).as_posix()
            print(f"→ Go {'' if relative == '.' else relative + ' '}собирается на {release} ({where}) — "
                  f"stdlib проверяется по нему (образ: {gotoolchain.local_release() or '?'})", file=sys.stderr)
    report = out / "govulncheck-reach.json"
    count, findings, problems = govulncheck_mod.run(target, report)
    print(f"→ govulncheck: Go-модулей {count}, записей о достижимости {findings}", file=sys.stderr)
    for problem in problems[:3]:
        print(f"  ! govulncheck: {problem}", file=sys.stderr)
    if findings:
        args.govulncheck_reach = str(report)
