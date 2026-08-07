"""The five-layer pipeline: ingest -> heuristics -> context -> LLM -> post-validation.

One `TriageRecord` comes out per finding, always — a provider outage produces an
`unknown` record with the error attached, never a dropped finding. Losing a
finding silently is the one failure mode an AppSec pipeline cannot have.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, Sequence

from .config import PipelineConfig, ProviderConfig
from . import prioritize as priority_mod
from . import reuse as reuse_mod
from . import risk as risk_ctx
from . import scope as scope_filter
from . import verify as verify_pass
from . import deployment as deployment_ctx
from .context import builder, deps, heuristics
from .context import routes as route_index
from .context.builder import HistoryStore
from .context import stack as stack_detect
from .lsp.service import LSPService
from .context.source import SourceResolver
from .llm.base import LLMClient, LLMError
from .models import (
    EvidenceClass,
    EvidenceQuote,
    ExternalControlReference,
    Finding,
    RiskContext,
    TriageRecord,
    Verdict,
    VerdictLabel,
    VulnerableSymbol,
)
from .prompts import registry
from .validate import postvalidation
from .validate.schema import VERDICT_SCHEMA, SchemaError, parse_verdict

log = logging.getLogger(__name__)

_SUPPORTING_CODEQL_RULES = {"go/govulncheck-targeted-taint"}


@dataclass(slots=True)
class TriageRun:
    records: list[TriageRecord]
    provider: str
    model: str
    prompt_pack: str
    scope_excluded: dict[str, int] = None  # type: ignore[assignment]
    reuse: dict | None = None
    coverage: object | None = None
    risk_context: RiskContext | None = None
    sca_stats: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.scope_excluded is None:
            self.scope_excluded = {}
        if self.sca_stats is None:
            self.sca_stats = {}

    @property
    def triaged_count(self) -> int:
        """Findings that actually reached the model, excluding scope drops."""
        return sum(1 for r in self.records if r.model is not None and not r.reused)

    @property
    def total_cost_usd(self) -> float:
        return round(sum(r.cost_usd or 0.0 for r in self.records), 4)

    def counts(self) -> dict[str, int]:
        out = {label.value: 0 for label in VerdictLabel}
        for r in self.records:
            out[r.verdict.verdict.value] += 1
        return out


class TriagePipeline:
    def __init__(
        self,
        client: LLMClient,
        provider_cfg: ProviderConfig,
        cfg: PipelineConfig,
        history: HistoryStore | None = None,
        source: "SourceResolver | None" = None,
        symbols: "LSPService | None" = None,
    ) -> None:
        self.client = client
        self.provider_cfg = provider_cfg
        self.cfg = cfg
        self.history = history
        self.source = source
        self.symbols = symbols
        self.risk_context = risk_ctx.load()
        self.stacks = stack_detect.detect(list(source.roots)) if source else []
        self.deps_roots = list(source.roots) if source else []
        self.deps_index = deps.build_index(self.deps_roots) if self.deps_roots else None
        self.routes = route_index.build_index(self.deps_roots) if self.deps_roots else None
        if self.deps_index and self.deps_index.usable:
            log.info(
                "dependency index: %d production, %d development (%s)",
                len(self.deps_index.production),
                len(self.deps_index.dev_only),
                ", ".join(self.deps_index.lockfiles_read),
            )
        self.dep_chain = None
        if getattr(cfg, "resolve_vulnerable_symbols", False):
            from .sca.chain import DependencyChain

            self.dep_chain = DependencyChain(
                client, self.deps_roots, lsp=symbols, routes=self.routes,
                nvd_api_key=getattr(cfg, "nvd_api_key", None),
                deployment=deployment_ctx.load(getattr(cfg, "deployment_config", None)),
            )
            log.info("dependency symbol chain enabled (databases will be queried per CVE)")
        self._codeql_findings: list[Finding] = []
        self.deployment = deployment_ctx.load(getattr(cfg, "deployment_config", None))
        self.stack_section = stack_detect.render(self.stacks)
        if self.deployment.usable:
            sections = (self.stack_section, self.deployment.render())
            self.stack_section = "\n\n".join(x for x in sections if x)
            log.info("deployment context in play: %s", ", ".join(sorted(self.deployment.facts)))
        if self.stacks:
            log.info("stack conventions in play: %s", ", ".join(s.id for s in self.stacks))
        log.info(
            "runtime risk context: internet=%s auth=%s business_critical=%s; platform=kubernetes",
            self.risk_context.internet_exposed,
            self.risk_context.auth_required,
            self.risk_context.business_critical,
        )
        for warning in self.risk_context.warnings:
            log.warning("risk context: %s", warning)

    def _finalize(self, record: TriageRecord, finding: Finding) -> TriageRecord:
        record = record.model_copy(update={"scanner_severity": finding.severity})
        return priority_mod.assign_priority(record, finding, self.risk_context)

    def _not_distributed_record(self, finding: Finding, result, sca=None) -> TriageRecord:
        """Close a dependency finding on a fact established by the SCA chain.

        The only dependency outcome decided without the model. It rests on the
        contents of the published archive — four PhpSpreadsheet XSS advisories
        are in `samples/`, and composer installs no `samples/` directory — which
        is a fact about a file listing, not an inference about behaviour.
        """
        external = bool(result.decision.reassigned)
        owner = (sca.owner if sca else "") or "external system owner"
        return TriageRecord(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            file_path=finding.code_context.file_path,
            rule_id=finding.rule_id,
            kind="dependency",
            start_line=finding.code_context.start_line,
            fingerprint=reuse_mod.fingerprint(finding),
            verdict=Verdict(
                verdict=VerdictLabel.external_fp if external else VerdictLabel.false_positive,
                evidence_class=EvidenceClass.identifier_only,
                confidence=0.85,
                confidence_band="high",
                confidence_rationale=(
                    f"Closed for this service because the SCA chain assigned the condition to {owner}."
                    if external
                    else "Closed on a positive SCA fact such as package placement, usage, condition, or archive contents."
                ),
                cwe=finding.cwe,
                reason=" ".join([result.decision.headline, *result.decision.reasons[:2]]),
                external_control=(
                    ExternalControlReference(
                        control_id="sca-infrastructure-owner",
                        why_effective=f"The vulnerable precondition belongs to {owner}, not this service.",
                    )
                    if external
                    else None
                ),
                requires_human_review=False,
            ),
            decided_by="llm" if external else "heuristics",
            provider=self.provider_cfg.name,
            model=self.provider_cfg.model if external else None,
            sca=sca,
        )

    def _platform_handled_record(self, finding: Finding, entry) -> TriageRecord:
        """Closed because the deployment owns the check, with the fact named.

        The reason states which declared fact it rests on, so a reviewer can go
        and check that claim against the manifests rather than take it on trust.
        """
        return TriageRecord(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            file_path=finding.code_context.file_path,
            rule_id=finding.rule_id,
            kind="misconfiguration",
            start_line=finding.code_context.start_line,
            fingerprint=reuse_mod.fingerprint(finding),
            verdict=Verdict(
                verdict=VerdictLabel.external_fp,
                evidence_class=EvidenceClass.identifier_only,
                confidence=0.85,
                confidence_band="high",
                confidence_rationale=(
                    f"Closed on a declared deployment fact (`{entry.requires}`), not on inference. "
                    "If that declaration is wrong, this verdict is wrong with it."
                ),
                cwe=finding.cwe,
                reason=f"The platform handles this: {entry.why}.",
                external_control=ExternalControlReference(
                    control_id=f"platform:{entry.rule}",
                    why_effective=entry.why,
                ),
                requires_human_review=False,
            ),
            decided_by="heuristics",
            provider=self.provider_cfg.name,
            model=None,
        )

    def _misconfiguration_record(self, finding: Finding) -> TriageRecord:
        line = (finding.code_context.snippet or "").strip().splitlines()
        verdict = Verdict(
            verdict=VerdictLabel.confirmed,
            evidence_class=EvidenceClass.identifier_only,
            confidence=0.9,
            confidence_band="high",
            confidence_rationale=(
                "The scanner parsed the file and read the directive itself, at very-high precision. "
                "Nothing here rests on inference."
            ),
            cwe=finding.cwe,
            vulnerable_symbol=VulnerableSymbol(
                name=(line[0][:120] if line else (finding.rule_id or "configuration")),
                kind="config_key",
                location=f"{finding.code_context.file_path}:{finding.code_context.start_line or '?'}",
                why=finding.title or "configuration check failed",
            ),
            evidence=[EvidenceQuote(quote=line[0][:200], why="the flagged directive")] if line else [],
            reason=(finding.description or finding.title or "Configuration check failed.").strip()[:1500],
            requires_human_review=False,
        )
        return TriageRecord(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            file_path=finding.code_context.file_path,
            rule_id=finding.rule_id,
            start_line=finding.code_context.start_line,
            fingerprint=reuse_mod.fingerprint(finding),
            verdict=verdict,
            kind="misconfiguration",
            decided_by="heuristics",
            provider=self.provider_cfg.name,
            model=None,
        )

    def _secret_record(self, finding: Finding) -> TriageRecord | None:
        """Decide a credential finding from its value, or hand it over unjudged."""
        from . import secrets as secret_policy

        value = secret_policy.flagged_value(finding.code_context.snippet)
        kind, why = secret_policy.classify(value)
        if kind == "unclear":
            return None

        placeholder = kind == "placeholder"
        line = (finding.code_context.snippet or "").strip().splitlines()
        verdict = Verdict(
            verdict=VerdictLabel.false_positive if placeholder else VerdictLabel.confirmed,
            evidence_class=EvidenceClass.test_placeholder if placeholder else EvidenceClass.secret_value,
            confidence=0.9,
            confidence_band="high",
            confidence_rationale=(
                "Decided from the value itself — length, alphabet and entropy — with no inference "
                "and no model call."
            ),
            cwe=finding.cwe,
            vulnerable_symbol=None
            if placeholder
            else VulnerableSymbol(
                name=(line[0].split("=")[0].strip()[:80] if line else (finding.rule_id or "credential")),
                kind="literal",
                location=f"{finding.code_context.file_path}:{finding.code_context.start_line or '?'}",
                why="a generated credential committed to the repository",
            ),
            evidence=[EvidenceQuote(quote=line[0][:200], why=why)] if line else [],
            reason=(
                why
                if placeholder
                else f"{why}. Whether it is still valid and whether this file is published are the two "
                "facts that set the urgency, and neither can be read from the code — rotate it if in doubt."
            ),
            requires_human_review=not placeholder,
        )
        return TriageRecord(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            file_path=finding.code_context.file_path,
            rule_id=finding.rule_id,
            start_line=finding.code_context.start_line,
            fingerprint=reuse_mod.fingerprint(finding),
            verdict=verdict,
            decided_by="heuristics",
            provider=self.provider_cfg.name,
            model=None,
        )


    def triage_one(self, finding: Finding) -> TriageRecord:
        if finding.misconfiguration:
            if entry := self.deployment.handled_by_platform(finding.rule_id):
                return self._finalize(self._platform_handled_record(finding, entry), finding)
            return self._finalize(self._misconfiguration_record(finding), finding)

        if self.cfg.secrets_without_model and _is_secret_family(finding.cwe):
            record = self._secret_record(finding)
            if record is not None:
                return self._finalize(record, finding)

        heur = heuristics.evaluate(finding, self.cfg.heuristics) if self.cfg.heuristics.enabled else _no_heuristics()
        symbols = self.symbols.enrich(finding) if self.symbols else None
        pkg = builder.build(
            finding,
            heur,
            self.cfg,
            self.history,
            self.source,
            symbols,
            deps_index=self.deps_index,
            deps_roots=self.deps_roots,
            routes=self.routes,
            deployment=self.deployment,
            risk_context=self.risk_context,
        )

        if heur.hard_fp:
            verdict = Verdict(
                verdict=VerdictLabel.false_positive,
                evidence_class=EvidenceClass.test_placeholder,
                confidence=0.95,
                cwe=finding.cwe,
                evidence=[s.detail for s in heur.signals if s.direction == "toward_fp"][:3],
                reason=f"Closed by deterministic pre-check: {heur.hard_fp_reason}",
                missing_information=[],
                requires_human_review=False,
            )
            return self._finalize(TriageRecord(
                finding_id=finding.finding_id,
                cwe=finding.cwe,
                file_path=finding.code_context.file_path,
                rule_id=finding.rule_id,
                start_line=finding.code_context.start_line,
                fingerprint=reuse_mod.fingerprint(finding),
                verdict=verdict,
                decided_by="heuristics",
                provider=self.provider_cfg.name,
                model=None,
            ), finding)

        kind = "dependency" if finding.dependency else None
        system, prompt = registry.render_system(finding.cwe, self.cfg.prompt_pack, self.stack_section, kind)
        user = builder.render_for_prompt(pkg)

        sca_summary = None
        sca_closed = False
        if self.dep_chain is not None and finding.dependency:
            try:
                chain = self.dep_chain.run(finding, codeql_findings=self._codeql_findings)
            except Exception:  # noqa: BLE001 - a lookup must not cost the finding
                log.exception("dependency symbol chain failed for %s", finding.finding_id)
            else:
                sca_summary = chain.summary(finding.dependency)
                if chain.closes:
                    sca_closed = True
                    return self._finalize(
                        self._not_distributed_record(finding, chain, sca_summary), finding
                    )
                user = f"{user}\n\n{chain.render()}"

        base = dict(
            finding_id=finding.finding_id,
            cwe=finding.cwe,
            file_path=finding.code_context.file_path,
            rule_id=finding.rule_id,
            kind="dependency" if finding.dependency else "weakness",
            start_line=finding.code_context.start_line,
            symbol_context=pkg.symbol_context,
            reachability=pkg.reachability,
            sast_reachability=pkg.sast_reachability,
            external_controls=pkg.external_controls,
            risk_context=self.risk_context,
            fingerprint=reuse_mod.fingerprint(finding),
            provider=self.provider_cfg.name,
            model=self.provider_cfg.model,
            prompt_id=prompt.id,
            prompt_version=prompt.version,
            sca=sca_summary,
        )

        repaired = False
        try:
            resp = self.client.complete(system, user, json_schema=VERDICT_SCHEMA)
            try:
                raw_verdict = parse_verdict(resp.text)
            except SchemaError as schema_exc:
                log.info("finding %s: schema repair round (%s)", finding.finding_id, str(schema_exc)[:120])
                repair_user = (
                    f"{user}\n\n## Correction required\n"
                    f"Your previous answer failed schema validation.\n"
                    f"Previous answer:\n```json\n{resp.text[:4000]}\n```\n"
                    f"Validation errors:\n{str(schema_exc)[:1000]}\n\n"
                    "Return the SAME verdict as one JSON object that satisfies the schema exactly: "
                    "every required field present (including `evidence_class`), correct field names, "
                    "no extra fields anywhere."
                )
                resp = self.client.complete(system, repair_user, json_schema=VERDICT_SCHEMA)
                raw_verdict = parse_verdict(resp.text)
                repaired = True
        except (LLMError, SchemaError) as exc:
            log.warning("finding %s: %s", finding.finding_id, exc)
            if self.cfg.fail_fast:
                raise
            return self._finalize(TriageRecord(
                **base,
                verdict=_error_verdict(finding, str(exc)),
                decided_by="error",
                error=str(exc),
            ), finding)

        outcome = postvalidation.validate(raw_verdict, pkg, finding, self.cfg.post_validation)
        verdict, overrides, decided_by = outcome.verdict, list(outcome.overrides), (
            "post_validation" if outcome.changed else "llm"
        )

        challenge_note: str | None = None
        record_so_far = TriageRecord(**base, verdict=verdict, overrides=overrides, decided_by=decided_by)
        if verify_pass.should_challenge(record_so_far, self.cfg.verification):
            result = verify_pass.challenge(
                self.client, pkg, verdict, user, self.cfg.verification,
                self.cfg.post_validation.quote_match_threshold,
                self.cfg.prompt_pack, self.stack_section,
            )
            verdict, challenge_overrides, challenge_note = verify_pass.apply(
                verdict, result, self.cfg.verification.mode
            )
            if challenge_overrides:
                overrides += challenge_overrides
                if self.cfg.verification.mode == "authoritative" and not result.survives and not result.error:
                    decided_by = "challenged"

        if repaired:
            overrides = overrides + ["schema_repaired: provider response needed a correction round"]

        if finding.dependency is not None and verdict.verdict.is_closed and not sca_closed:
            verdict = verdict.model_copy(update={
                "verdict": VerdictLabel.unknown,
                "evidence_class": EvidenceClass.insufficient_context,
                "confidence": min(verdict.confidence, 0.3),
                "confidence_band": "low",
                "confidence_rationale": (
                    "A dependency finding can close only when every cdxgen path is factually broken."
                ),
                "reason": (
                    "Dependency closure was rejected because the SCA chain did not prove that "
                    "every cdxgen dependency path is absent."
                ),
                "missing_information": [
                    *verdict.missing_information,
                    "complete source and bridge evidence for every cdxgen dependency path",
                ],
                "blocking_question": (
                    "Can every cdxgen dependency path be resolved through exact-version parent source?"
                ),
                "external_control": None,
                "requires_human_review": True,
            })
            overrides.append(
                "sca_closure_gate: not every cdxgen dependency path was proven closed"
            )
            decided_by = "post_validation"

        return self._finalize(TriageRecord(
            **base,
            challenge_note=challenge_note,
            verdict=verdict,
            original_verdict=raw_verdict if (outcome.changed or overrides) else None,
            overrides=overrides,
            decided_by=decided_by,
            latency_ms=resp.latency_ms,
            prompt_tokens=resp.prompt_tokens,
            completion_tokens=resp.completion_tokens,
            cost_usd=self.client.estimate_cost(resp.prompt_tokens, resp.completion_tokens),
            attempts=resp.attempts,
        ), finding)


    def run(self, findings: Iterable[Finding], *, progress=None, on_record=None) -> TriageRun:
        """Triage every finding.

        `on_record` is called with each record the moment it is decided. The
        caller uses it to journal results as they land: holding everything in
        memory until the last finding returns means a crash at 183 of 296
        destroys 183 finished verdicts and the money that bought them.
        """
        all_findings = list(findings)
        if self.dep_chain is not None:
            self._codeql_findings = [
                f for f in all_findings if (f.scanner or "").lower() == "codeql" and f.trace
            ]
            log.info("codeql dataflow paths available for reachability: %d",
                     len(self._codeql_findings))

        scoped = scope_filter.apply(all_findings, self.cfg.scope)
        if scoped.excluded:
            log.info("scope filter excluded %d finding(s): %s", len(scoped.excluded), scoped.counts)
        items: Sequence[Finding] = [
            finding
            for finding in scoped.kept
            if finding.rule_id not in _SUPPORTING_CODEQL_RULES
        ]
        prepare = getattr(self.dep_chain, "prepare", None)
        if callable(prepare):
            try:
                prepare(finding for finding in items if finding.dependency is not None)
            except Exception:  # noqa: BLE001 - preparation failure degrades individual findings
                log.exception("dependency batch preparation failed; continuing per finding")
        workers = max(1, min(self.cfg.max_workers, self.provider_cfg.concurrency))
        records: list[TriageRecord | None] = [None] * len(items)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.triage_one, f): i for i, f in enumerate(items)}
            for done, future in enumerate(as_completed(futures), 1):
                index = futures[future]
                try:
                    records[index] = future.result()
                except Exception as exc:  # noqa: BLE001 - the batch must survive one finding
                    log.exception("triage failed for %s", items[index].finding_id)
                    records[index] = self._finalize(
                        _error_record(items[index], self.provider_cfg, exc), items[index]
                    )
                if on_record:
                    try:
                        on_record(records[index])
                    except Exception:  # noqa: BLE001 - journalling must never sink a verdict
                        log.exception("could not journal %s", items[index].finding_id)
                if progress:
                    progress(done, len(items))

        by_id = {finding.finding_id: finding for finding in all_findings}
        excluded = [
            self._finalize(record, by_id[record.finding_id])
            for record in scoped.excluded
            if record.finding_id in by_id
        ]
        return TriageRun(
            records=[r for r in records if r is not None] + excluded,
            provider=self.provider_cfg.name,
            model=self.provider_cfg.model,
            prompt_pack=self.cfg.prompt_pack,
            scope_excluded=scoped.counts,
            risk_context=self.risk_context,
            sca_stats=(self.dep_chain.stats_snapshot() if self.dep_chain is not None
                       and hasattr(self.dep_chain, "stats_snapshot") else {}),
        )


def _is_secret_family(cwe: str | None) -> bool:
    from .context.heuristics import SECRET_FAMILY_CWES

    return bool(cwe) and cwe.upper() in SECRET_FAMILY_CWES


def _no_heuristics() -> heuristics.HeuristicResult:
    return heuristics.HeuristicResult(
        signals=[], hard_fp=False, hard_fp_reason=None, in_noisy_zone=False, noisy_zone_reason=None
    )


def _error_record(finding: Finding, provider_cfg: ProviderConfig, exc: Exception) -> TriageRecord:
    """A finding that failed in a way `triage_one` did not anticipate.

    It still gets a record, and the record still says `unknown` and demands a
    human — a finding that vanishes because of an exception is the one outcome
    this pipeline must never produce.
    """
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        rule_id=finding.rule_id,
        start_line=finding.code_context.start_line,
        fingerprint=reuse_mod.fingerprint(finding),
        verdict=_error_verdict(finding, f"{type(exc).__name__}: {exc}"),
        decided_by="error",
        provider=provider_cfg.name,
        model=provider_cfg.model,
        error=f"{type(exc).__name__}: {exc}"[:500],
    )


def _error_verdict(finding: Finding, error: str) -> Verdict:
    return Verdict(
        verdict=VerdictLabel.unknown,
        evidence_class=EvidenceClass.insufficient_context,
        confidence=0.0,
        cwe=finding.cwe,
        evidence=[],
        reason=f"Triage failed before a verdict could be produced: {error[:300]}",
        missing_information=["model verdict unavailable"],
        requires_human_review=True,
    )
