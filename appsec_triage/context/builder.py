"""Context builder: Finding + heuristics + history -> EvidencePackage.

The model never sees a raw scanner record. It sees a package where every field
is either verbatim scanner output or a machine-checkable signal — which is what
makes the anti-hallucination quote check in post-validation meaningful.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import PipelineConfig
from ..models import EvidencePackage, Finding, HeuristicSignal, RiskContext, SASTReachability
from ..redact import redact_secrets
from .heuristics import HeuristicResult
from .source import SourceResolver

if TYPE_CHECKING:
    from ..lsp.service import SymbolContext
    from .deps import DependencyIndex
    from .routes import RouteIndex


DATAFLOW_CWES = {
    "CWE-78", "CWE-77", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-95", "CWE-98",
    "CWE-79", "CWE-22", "CWE-23", "CWE-434", "CWE-502", "CWE-611", "CWE-643",
    "CWE-918", "CWE-917", "CWE-943", "CWE-1236",
}


class HistoryStore:
    """Prior human decisions on similar findings.

    v0 is an in-memory index keyed by (cwe, top heuristic signal); it is filled
    from the labelled corpus when one is supplied. The interface is deliberately
    narrow so a real vector store can replace it without touching the builder.
    """

    def __init__(self, entries: dict[tuple[str, str], list[str]] | None = None) -> None:
        self._entries = entries or {}

    def lookup(self, finding: Finding, heur: HeuristicResult, limit: int = 3) -> list[str]:
        cwe = finding.cwe or "unknown"
        out: list[str] = []
        for sig in heur.signals:
            for line in self._entries.get((cwe, sig.name), []):
                if line not in out:
                    out.append(line)
                if len(out) >= limit:
                    return out
        return out


def build(
    finding: Finding,
    heur: HeuristicResult,
    cfg: PipelineConfig,
    history: HistoryStore | None = None,
    source: "SourceResolver | None" = None,
    symbols: "SymbolContext | None" = None,
    deps_index: "DependencyIndex | None" = None,
    deps_roots: list | None = None,
    routes: "RouteIndex | None" = None,
    deployment=None,
    risk_context=None,
) -> EvidencePackage:
    snippet = (finding.code_context.snippet or "").strip()
    truncated = finding.code_context.truncated
    widened = False

    if source and cfg.code_context_lines > 0:
        wide = (finding.cwe or "").upper() in DATAFLOW_CWES
        win = source.window(
            finding.code_context.file_path,
            finding.code_context.start_line,
            finding.code_context.end_line,
            cfg.dataflow_context_lines_after if wide else cfg.code_context_lines,
            before=cfg.dataflow_context_lines_before if wide else None,
        )
        if win:
            snippet = win.text
            truncated = False
            widened = True
    if len(snippet) > cfg.max_code_chars:
        snippet = snippet[: cfg.max_code_chars] + "\n... [truncated]"
        truncated = True

    redacted_count = 0
    if cfg.redact_secrets:
        snippet, redacted_count = redact_secrets(snippet)

    code_source = "snippet" if snippet else "description_only"

    steps, omitted = _trim_trace(finding.trace, cfg.max_trace_steps)
    trace_lines = []
    for step in steps:
        if step is None:
            trace_lines.append(f"... {omitted} middle step(s) omitted — a sanitizer in here would not be shown")
            continue
        head = f"{step.role}: {step.file_path}:{step.line or '?'}"
        code = source.line(step.file_path, step.line) if source else None
        if code:
            trace_lines.append(f"{head}  |  {code[:160]}")
        elif step.message:
            trace_lines.append(f"{head} — {step.message}")
        else:
            trace_lines.append(head)

    required_lang = cfg.lsp.language_for(finding.code_context.file_path) if cfg.lsp.required_languages else None
    lsp_required_missing = bool(
        required_lang
        and required_lang in cfg.lsp.required_languages
        and (symbols is None or not symbols.resolved)
    )

    symbol_lines: list[str] = []
    reachability: str | None = None
    production_entrypoint = False
    route_path: str | None = None
    signals = list(heur.signals)
    if symbols is not None:
        symbol_lines = [f"definition of {d.symbol or 'value'}: {d}" for d in symbols.definitions]
        symbol_lines += [f"called from: {c}" for c in symbols.callers]

        if symbols.taint_sources:
            src = symbols.taint_sources[0]
            signals.append(
                HeuristicSignal(
                    name="lsp_resolved_taint_source",
                    detail=f"an interpolated value resolves to user input at {src.file_path}:{src.line} "
                    f"({(src.text or '').strip()[:80]!r}) — the language server found the dataflow "
                    "source the scanner could not see",
                    direction="toward_confirmed",
                    weight=0.65,
                )
            )

        if symbols.reachable_from_entrypoint:
            production_entrypoint = True
            reachability = "reachable from an HTTP entry point"
            signals.append(
                HeuristicSignal(
                    name="reachable_from_entrypoint",
                    detail="a caller registers this code as a route or endpoint",
                    direction="toward_confirmed",
                    weight=0.6,
                )
            )
        elif symbols.callers_all_non_production:
            reachability = "every caller found lives in tests or fixtures"
            signals.append(
                HeuristicSignal(
                    name="callers_are_non_production",
                    detail="every caller found is a test, fixture or migration — "
                    "note this is what the server could see, not proof of unreachability",
                    direction="toward_fp",
                    weight=0.3,
                )
            )
        elif symbols.callers:
            reachability = "callers found, none of them an entry point one hop away"

    if routes is not None and routes.usable:
        enclosing_route = routes.enclosing(
            finding.code_context.file_path, finding.code_context.start_line or 0
        )
        if enclosing_route is not None:
            production_entrypoint = True
            route_path = enclosing_route.path
        reachability, route_signal = _route_reachability(routes, finding, reachability)
        if route_signal is not None:
            signals.append(route_signal)

    dependency = finding.dependency
    if dependency is not None:
        dependency = _enrich_dependency(dependency, deps_index, deps_roots, signals)

    trace_roles = {step.role for step in finding.trace}
    source_to_sink = {"source", "sink"}.issubset(trace_roles)
    if source_to_sink and production_entrypoint:
        reachability_status = "established"
        reachability_detail = "scanner trace establishes source-to-sink and LSP/routes establish a production entrypoint"
    elif source_to_sink or production_entrypoint:
        reachability_status = "partial"
        reachability_detail = "only one half of source-to-sink and production-entrypoint reachability is established"
    else:
        reachability_status = "unknown"
        reachability_detail = "neither a complete scanner trace nor a production entrypoint was established"
    sast_reachability = SASTReachability(
        status=reachability_status,
        trace_scanner=finding.scanner if finding.trace else None,
        source_to_sink=source_to_sink,
        production_entrypoint=production_entrypoint,
        route=route_path,
        detail=reachability_detail,
    )
    external_controls = deployment.matching_controls(finding, route_path) if deployment else []

    return EvidencePackage(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        rule_id=finding.rule_id,
        title=finding.title,
        description=finding.description,
        file_path=finding.code_context.file_path,
        start_line=finding.code_context.start_line,
        end_line=finding.code_context.end_line,
        in_noisy_zone=heur.in_noisy_zone,
        noisy_zone_reason=heur.noisy_zone_reason,
        code_context=(snippet + ("\n[payload truncated by the scanner]" if truncated else "")) or None,
        code_source=code_source,
        code_widened=widened,
        secrets_redacted=redacted_count,
        source=finding.source,
        sink=finding.sink,
        sanitizers=finding.sanitizers,
        trace=trace_lines,
        heuristic_signals=signals,
        dependency=dependency,
        symbol_context=symbol_lines,
        reachability=reachability,
        sast_reachability=sast_reachability,
        external_controls=external_controls,
        lsp_required_missing=lsp_required_missing,
        lsp_resolved_clean=bool(
            symbols is not None
            and symbols.resolved
            and not symbols.taint_sources
        ),
        history=(history.lookup(finding, heur) if history else []),
        risk_context=risk_context or RiskContext(),
    )


def _trim_trace(trace: list, limit: int) -> tuple[list, int]:
    """Head and tail of the path, with a `None` marking the gap between them.

    Weighted toward the tail: the sink and the hops just before it carry the
    verdict, while the middle of a long inter-procedural path is mostly plumbing.
    """
    if limit <= 0 or len(trace) <= limit:
        return list(trace), 0
    head = max(1, limit // 3)
    tail = limit - head
    return [*trace[:head], None, *trace[-tail:]], len(trace) - limit


def _route_reachability(routes, finding, existing: str | None):
    """Answer "is this line inside an HTTP entry point?" from the routing table."""
    from ..models import HeuristicSignal

    path = finding.code_context.file_path
    line = finding.code_context.start_line or 0
    route = routes.enclosing(path, line)
    if route is not None:
        return (
            f"inside an HTTP entry point — {route.describe()}",
            HeuristicSignal(
                name="http_entrypoint_method",
                detail=f"the flagged line is inside a routed controller action: {route.describe()}",
                direction="toward_confirmed",
                weight=0.6,
            ),
        )

    hit = routes.perimeter(path)
    if hit is not None:
        hops, chain = hit
        via = " <- ".join(reversed(chain)) if chain else "route table"
        return (
            f"{hops} hop(s) from an HTTP entry point (via {via})",
            HeuristicSignal(
                name="near_http_entrypoint",
                detail=f"this file sits {hops} reference hop(s) from a routed controller ({via}). "
                "It places the code inside the request-handling perimeter; it does not prove this "
                "particular method runs for a request.",
                direction="neutral",
                weight=0.0,
            ),
        )
    return existing, None


def _enrich_dependency(dep, index, roots, signals):
    """Add the two facts the scanner never reports, as signals the model reads."""
    from ..models import HeuristicSignal

    dev_only = index.is_dev_only(dep.package) if index is not None else None
    imported = None
    if roots:
        from .deps import is_imported

        imported = is_imported(dep.package, dep.ecosystem, list(roots))

    if dev_only:
        signals.append(
            HeuristicSignal(
                name="dev_dependency_only",
                detail=f"{dep.package} is listed in the lockfile's development section — it builds and "
                "tests the application and does not ship",
                direction="toward_fp",
                weight=0.6,
            )
        )
    if imported:
        signals.append(
            HeuristicSignal(
                name="package_imported",
                detail=f"our source names {dep.package}, so the vulnerable code is in play",
                direction="toward_confirmed",
                weight=0.4,
            )
        )
    return dep.model_copy(update={"dev_only": dev_only, "imported": imported})


def render_for_prompt(pkg: EvidencePackage) -> str:
    """Deterministic, compact rendering. Stable ordering keeps prompt caching warm."""
    location = pkg.file_path
    if pkg.start_line:
        location += f":{pkg.start_line}"
        if pkg.end_line and pkg.end_line != pkg.start_line:
            location += f"-{pkg.end_line}"

    lines = [
        "=== FINDING ===",
        f"finding_id: {pkg.finding_id}",
        f"cwe: {pkg.cwe or 'unspecified'}",
        f"rule_id: {pkg.rule_id or 'unspecified'}",
        f"title: {pkg.title or 'unspecified'}",
        f"location: {location}",
        f"file_path: {pkg.file_path}",
        f"code_source: {pkg.code_source}",
        f"in_noisy_zone: {pkg.in_noisy_zone}" + (f" ({pkg.noisy_zone_reason})" if pkg.noisy_zone_reason else ""),
    ]
    if pkg.description:
        lines += ["", "=== ANALYZER DESCRIPTION ===", pkg.description.strip()]
    if pkg.code_context:
        header = (
            "=== CODE CONTEXT (read from the file, `line | source`) ==="
            if pkg.code_widened
            else "=== CODE CONTEXT (as reported by the analyzer) ==="
        )
        lines += ["", header, pkg.code_context]
    if pkg.source or pkg.sink or pkg.sanitizers:
        lines += [
            "",
            "=== DATAFLOW ===",
            f"source: {pkg.source or 'not reported'}",
            f"sink: {pkg.sink or 'not reported'}",
            f"sanitizers: {', '.join(pkg.sanitizers) if pkg.sanitizers else 'none reported'}",
        ]
    if pkg.trace:
        lines += ["", "=== TRACE ===", *pkg.trace]
    if pkg.symbol_context:
        lines += [
            "",
            "=== RESOLVED SYMBOLS (from the language server, verbatim source) ===",
            *(f"- {c}" for c in pkg.symbol_context),
        ]
    elif pkg.lsp_required_missing:
        lines += [
            "",
            "=== RESOLVED SYMBOLS (language server is REQUIRED for this file type) ===",
            "the language server returned nothing for this finding. The origin of every value on the "
            "flagged line is UNVERIFIED — do not assume where a value comes from, and do not close a "
            "dataflow finding on such an assumption.",
        ]
    if pkg.reachability:
        lines += ["", "=== REACHABILITY ===", pkg.reachability]
    if pkg.sast_reachability:
        reach = pkg.sast_reachability
        lines += [
            "",
            "=== SAST REACHABILITY GATE ===",
            f"status: {reach.status}",
            f"source-to-sink trace: {'yes' if reach.source_to_sink else 'no'}"
            + (f" ({reach.trace_scanner})" if reach.trace_scanner else ""),
            f"production entrypoint: {'yes' if reach.production_entrypoint else 'no'}",
            f"route: {reach.route or 'not established'}",
            reach.detail,
        ]
    if pkg.external_controls:
        lines += ["", "=== VERIFIED EXTERNAL COMPENSATING CONTROLS ==="]
        for control in pkg.external_controls:
            lines += [
                f"- control_id: {control.control_id}",
                f"  kind: {control.kind}; direction: {control.direction}",
                f"  coverage: {control.coverage}",
                f"  evidence: {control.evidence}",
                f"  bypass precluded: {'yes' if control.bypass_precluded else 'no'}",
            ]
    risk = pkg.risk_context
    lines += [
        "",
        "=== RUNTIME RISK CONTEXT (priority/exposure only; never closes a vulnerability) ===",
        f"internet exposed: {_tri_state_text(risk.internet_exposed)}",
        f"authentication required: {_tri_state_text(risk.auth_required)}",
        f"business critical: {_tri_state_text(risk.business_critical)}",
        "platform baseline: kubernetes; restricted egress; shared nginx ingress/external load balancer; "
        "backend is not directly exposed",
        "Internet exposure means reachability through the shared load balancer, not direct pod exposure. "
        "Authentication means a caller must authenticate before reaching the service.",
        "The shared load balancer routes traffic and is not a WAF or sanitizer. Use these facts only "
        "for exploitability, impact, and priority.",
    ]
    if risk.warnings:
        lines += [f"risk context warning: {warning}" for warning in risk.warnings]
    if pkg.dependency:
        dep = pkg.dependency
        lines += [
            "",
            "=== DEPENDENCY ===",
            f"package: {dep.ecosystem or 'unknown'}/{dep.package}",
            f"installed: {dep.installed_version or 'not reported'}",
            f"fixed in: {', '.join(dep.fixed_versions) if dep.fixed_versions else 'no fix published'}",
            f"upgrade target for this branch: {dep.upgrade_target or 'none above the installed version'}",
            f"ships to production: {'no — development only' if dep.dev_only else ('yes' if dep.dev_only is False else 'unknown')}",
            f"named in our source: {'yes' if dep.imported else ('not found — see the note in the prompt' if dep.imported is False else 'unknown')}",
        ]
        if dep.advisory_url:
            lines.append(f"advisory: {dep.advisory_url}")

    if pkg.heuristic_signals:
        lines += ["", "=== HEURISTIC SIGNALS (precomputed, trustworthy) ==="]
        lines += [f"- {s.name} [{s.direction}]: {s.detail}" for s in pkg.heuristic_signals]
    if pkg.history:
        lines += ["", "=== PRIOR HUMAN DECISIONS ON SIMILAR FINDINGS ===", *(f"- {h}" for h in pkg.history)]
    return "\n".join(lines)


def _tri_state_text(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "true" if value else "false"
