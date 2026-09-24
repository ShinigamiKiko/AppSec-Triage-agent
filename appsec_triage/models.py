"""Core data contracts: Finding -> EvidencePackage -> Verdict."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


class CodeContext(BaseModel):
    """The code the analyzer pointed at, plus a small window around it."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    language: str | None = None
    truncated: bool = False


class TraceStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_path: str
    line: int | None = None
    message: str | None = None
    role: Literal["source", "sink", "sanitizer", "step"] = "step"


class DependencyInfo(BaseModel):
    """A vulnerable third-party component — the SCA half of the problem."""

    model_config = ConfigDict(extra="forbid")

    package: str
    ecosystem: str | None = None
    installed_version: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    advisory_aliases: list[str] = Field(default_factory=list)
    advisory_url: str | None = None
    dev_only: bool | None = None
    imported: bool | None = None
    # runtime | image_only | build_only | unknown, from the shipping check (sca/shipping.py).
    shipped: str | None = None
    # browser | node | both | unknown — where the code that loads the package runs.
    runtime: str | None = None
    reachability: str | None = None
    call_site: str | None = None
    call_line: str | None = None

    @property
    def upgrade_target(self) -> str | None:
        """The lowest published fix above the installed version."""
        if not self.installed_version:
            return self.fixed_versions[0] if self.fixed_versions else None
        current = _release_parts(self.installed_version)
        if current is None:
            return self.fixed_versions[0] if self.fixed_versions else None
        above = [
            (parts, raw)
            for raw in self.fixed_versions
            if (parts := _release_parts(raw)) is not None and parts > current
        ]
        return min(above)[1] if above else None


def _release_parts(version: str) -> tuple[int, ...] | None:
    """Plain dotted release -> comparable tuple."""
    text = version.strip().lower().lstrip("v")
    if not text or any(ch in text for ch in "-+ "):
        return None
    try:
        return tuple(int(p) for p in text.split("."))
    except ValueError:
        return None


class Finding(BaseModel):
    """A single normalized SAST finding, scanner-agnostic."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    scanner: str
    rule_id: str | None = None
    cwe: str | None = Field(default=None, description="Canonical form: 'CWE-798'")
    title: str | None = None
    description: str | None = None
    severity: Severity = Severity.unknown
    code_context: CodeContext
    trace: list[TraceStep] = Field(default_factory=list)
    source: str | None = None
    sink: str | None = None
    sanitizers: list[str] = Field(default_factory=list)
    corroborated_by: list[str] = Field(default_factory=list)
    dependency: DependencyInfo | None = None
    misconfiguration: bool = False
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)


class HeuristicSignal(BaseModel):
    """One machine-checkable fact about the finding, produced before the LLM."""

    model_config = ConfigDict(extra="forbid")

    name: str
    detail: str
    direction: Literal["toward_fp", "toward_confirmed", "neutral"] = "neutral"
    weight: float = 0.0


class EvidencePackage(BaseModel):
    """What the model actually sees."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    cwe: str | None
    rule_id: str | None
    title: str | None
    description: str | None
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    in_noisy_zone: bool
    noisy_zone_reason: str | None
    code_context: str | None
    code_source: Literal["snippet", "description_only"]
    code_widened: bool = False
    secrets_redacted: int = 0
    source: str | None
    sink: str | None
    sanitizers: list[str]
    trace: list[str]
    heuristic_signals: list[HeuristicSignal]
    symbol_context: list[str] = Field(default_factory=list)
    reachability: str | None = None
    lsp_required_missing: bool = False
    lsp_resolved_clean: bool = False
    dependency: DependencyInfo | None = None
    history: list[str] = Field(default_factory=list)
    evidence_blocks: list[str] = Field(default_factory=list)
    context_notes: list[str] = Field(default_factory=list)
    dependency_analysis: str | None = None
    repository_code_collected: bool = False
    repository_bytes_read: int = 0
    code_questions: list[str] = Field(default_factory=list)
    # Searches and language-server lookups the walk made, with their answers verbatim —
    # a "no match" among them. Shown to the verdict, so an absence can be quoted.
    code_facts: list[str] = Field(default_factory=list)

    def quotable_text(self) -> str:
        """Exactly the text the model was shown, used to verify its quotes."""
        from .context.builder import render_for_prompt

        return render_for_prompt(self)


class VerdictLabel(str, Enum):
    confirmed = "confirmed"
    false_positive = "false_positive"
    unknown = "unknown"


class EvidenceClass(str, Enum):
    secret_value = "SECRET_VALUE"
    identifier_only = "IDENTIFIER_ONLY"
    test_placeholder = "TEST_PLACEHOLDER"
    exploitable_dataflow = "EXPLOITABLE_DATAFLOW"
    sanitized_dataflow = "SANITIZED_DATAFLOW"
    insufficient_context = "INSUFFICIENT_CONTEXT"


class DataflowRole(str, Enum):
    source = "source"
    propagation = "propagation"
    sanitizer = "sanitizer"
    sink = "sink"


class DataflowStep(BaseModel):
    """One hop of the reconstructed path, in the model's own words."""

    model_config = ConfigDict(extra="forbid")

    order: int
    role: DataflowRole
    location: str | None = None
    code: str | None = None
    explanation: str = ""
    tainted: bool = True
    grounded: bool = True


class VulnerableSymbol(BaseModel):
    """The specific thing that is wrong — the answer to 'what exactly?'."""

    model_config = ConfigDict(extra="forbid")

    name: str
    kind: Literal["sink", "api_call", "literal", "generator", "algorithm", "config_key"]
    location: str | None = None
    why: str = ""


class EvidenceQuote(BaseModel):
    """A verbatim line plus what it proves."""

    model_config = ConfigDict(extra="forbid")

    quote: str = Field(description="Copied character-for-character from the input. Never paraphrased.")
    why: str = Field(default="", description="What this line proves. Free prose belongs here, not in `quote`.")
    grounded: bool = True


class Verdict(BaseModel):
    """The strict contract the model must return."""

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictLabel
    evidence_class: EvidenceClass
    confidence: float = Field(ge=0.0, le=1.0)
    self_reported_confidence: float | None = None
    confidence_band: Literal["high", "medium", "low"] | None = None
    confidence_rationale: str = Field(
        default="",
        description="Why this number and not a higher/lower one. Forces the model to justify certainty.",
    )
    exploitability: Literal["trivial", "moderate", "difficult"] | None = None
    impact: Literal["critical", "high", "medium", "low"] | None = None
    cwe: str | None = None
    vulnerable_symbol: VulnerableSymbol | None = None
    dataflow: list[DataflowStep] = Field(default_factory=list)
    evidence: list[EvidenceQuote] = Field(default_factory=list)
    reason: str = ""
    missing_information: list[str] = Field(default_factory=list)
    blocking_question: str | None = Field(
        default=None,
        description="For `unknown` only: the single fact that would settle it. Tells the human where to look.",
    )
    requires_human_review: bool = True


class SCASummary(BaseModel):
    """What the dependency chain found, in the shape a report table needs."""

    model_config = ConfigDict(extra="forbid")

    package: str = ""
    installed_version: str = ""
    placement: str = ""
    upgrade: str = ""
    symbol: str = ""
    what_changed: str = ""
    flaw: str = ""
    flaw_ru: str = ""
    outcome: str = ""
    outcome_note: str = ""
    call_sites: list[str] = Field(default_factory=list)
    trace: str = ""
    external: str = ""
    owner: str = ""
    condition: str = ""
    condition_state: str = ""
    condition_hits: list[str] = Field(default_factory=list)
    exploitability: str = ""
    audit: str = ""
    closure_kind: str = ""
    audited: bool = False
    route: str = ""
    codeql_calls: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    # runtime | image_only | build_only | unknown — does the running application load it.
    shipped: str = ""
    # browser | node | both | unknown — where the code that loads it runs.
    runtime: str = ""
    loaded_via: list[str] = Field(default_factory=list)
    # import | codeql | lsp | name — how a call site was attributed to the package.
    call_evidence: str = ""
    severity: str = ""
    # critical | high | medium | low | none — how urgent the fix is, separate from the verdict.
    priority: str = ""
    # Which rule of sca/policy.py decided it.
    policy: str = ""
    # What the policy could not settle and handed to the model.
    open_question: str = ""


class TriageRecord(BaseModel):
    """One fully-audited decision: verdict + everything needed to reproduce it."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    cwe: str | None
    file_path: str
    kind: Literal["weakness", "dependency", "misconfiguration"] = "weakness"
    severity: Severity = Severity.unknown
    rule_id: str | None = None
    start_line: int | None = None
    trace: list[TraceStep] = Field(default_factory=list)
    symbol_context: list[str] = Field(default_factory=list)
    reachability: str | None = None
    challenge_note: str | None = None
    verdict: Verdict
    original_verdict: Verdict | None = None
    overrides: list[str] = Field(default_factory=list)
    decided_by: Literal["scope", "heuristics", "policy", "llm", "post_validation", "challenged", "error"] = "llm"
    provider: str | None = None
    model: str | None = None
    prompt_id: str | None = None
    prompt_version: str | None = None
    latency_ms: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    cost_usd: float | None = None
    attempts: int = 1
    error: str | None = None
    fingerprint: str | None = None
    reused: bool = False
    sca: SCASummary | None = None
    code_questions: list[str] = Field(default_factory=list)
    # Seconds per stage (chain, walk, verdict, retrieval, challenge, total) — where the time went.
    timings: dict[str, float] = Field(default_factory=dict)
