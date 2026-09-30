"""Config loading: one YAML profile per provider + one pipeline config."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "configs"


class ConfigError(RuntimeError):
    pass


def _expand_env(value: Any) -> Any:
    """Recursively expand ${VAR} and ${VAR:-default} inside loaded YAML."""
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            var, default = m.group(1), m.group(2)
            got = os.environ.get(var)
            if got is None:
                if default is None:
                    raise ConfigError(f"environment variable {var} is not set (referenced in config)")
                return default
            return got

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass(slots=True)
class ProviderConfig:
    """Common transport/decoding knobs."""

    name: str
    kind: Literal["ollama", "openai", "deepseek", "mailbox"]

    @property
    def leaves_the_perimeter(self) -> bool:
        """Does a prompt sent to this provider reach a third party?"""
        return self.kind not in ("ollama", "mailbox")
    model: str
    base_url: str
    api_key: str | None = None

    temperature: float = 0.0
    max_tokens: int = 1024
    top_p: float | None = None
    stop: list[str] = field(default_factory=list)

    json_mode: Literal["none", "json_object", "json_schema", "ollama_format"] = "json_object"

    timeout_s: float = 120.0
    connect_timeout_s: float = 10.0
    max_retries: int = 2
    backoff_base_s: float = 1.0
    backoff_max_s: float = 20.0
    concurrency: int = 4

    pricing: dict[str, float] = field(default_factory=dict)
    budget_usd: float = 5.0
    keep_raw_response: bool = False
    tool_calling: bool = True
    think: str = ""

    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, name: str) -> ProviderConfig:
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(data) - known - {"name"}
        if unknown:
            raise ConfigError(f"provider '{name}': unknown config keys: {sorted(unknown)}")
        data = {**data, "name": name}
        return cls(**data)


@dataclass(slots=True)
class HeuristicsConfig:
    enabled: bool = True
    autoclose_on_hard_fp: bool = False
    min_secret_entropy: float = 3.5
    min_secret_length: int = 16
    noisy_path_patterns: list[str] = field(default_factory=list)
    placeholder_markers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PostValidationConfig:
    enabled: bool = True
    require_evidence_quotes: bool = True
    quote_match_threshold: float = 0.85
    confidence_floor: float = 0.7
    confirmed_confidence_floor: float = 0.75
    escalate_severities: list[str] = field(default_factory=lambda: ["critical", "high"])
    closure_requires_named_defence_above: int = 0


@dataclass(slots=True)
class ScannerConfig:
    """How to invoke one SAST tool."""

    name: str = "scanner"
    mode: Literal["auto", "native", "docker"] = "auto"
    binary: str | list[str] | None = None
    image: str | None = None
    rules: list[str] = field(default_factory=list)
    local_rules_dir: str | None = None
    language: str | None = None
    severity: str | None = None
    timeout_s: float = 1800.0
    per_file_timeout_s: int = 30
    docker_network: bool = False
    docker_args: list[str] = field(default_factory=list)
    run_in_target: bool = False
    suites: dict[str, list[str]] = field(default_factory=dict)
    model_packs: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, name: str) -> ScannerConfig:
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(data) - known - {"name"}
        if unknown:
            raise ConfigError(f"scanner '{name}': unknown config keys: {sorted(unknown)}")
        return cls(**{**data, "name": name})


@dataclass(slots=True)
class ScopeConfig:
    """What is not worth triaging at all."""

    enabled: bool = True
    exclude_rules: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    only_cwes: list[str] = field(default_factory=list)
    min_severity: str | None = None
    only_ecosystems: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LSPConfig:
    """Language servers, for the questions a scanner cannot answer."""

    enabled: bool = False
    reachability: bool = True
    max_definitions: int = 4
    max_callers: int = 8
    startup_timeout_s: float = 120.0
    index_timeout_s: float = 90.0
    request_timeout_s: float = 20.0
    search_timeout_s: float = 60.0
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)
    required_languages: list[str] = field(default_factory=list)

    def language_for(self, path: str) -> str | None:
        """Which configured server owns this file, by extension."""
        suffix = Path(path).suffix.lower()
        for language, spec in self.servers.items():
            if suffix in [s.lower() for s in (spec or {}).get("extensions", [])]:
                return language
        return None


@dataclass(slots=True)
class VerificationConfig:
    """Second, adversarial pass over selected verdicts."""

    enabled: bool = False
    mode: Literal["advisory", "authoritative"] = "advisory"
    challenge_verdicts: list[str] = field(default_factory=lambda: ["confirmed"])
    challenge_on_override: bool = False
    challenge_cwes: list[str] = field(default_factory=list)
    challenge_closures_above_consequence: int = 0
    challenge_kinds: list[str] = field(default_factory=lambda: ["weakness"])
    downgrade_confirmed: bool = True


@dataclass(slots=True)
class TriageQueueConfig:
    """How much manual review the team is willing to spend, and on what."""

    enabled: bool = True
    review_budget_pct: float = 30.0
    cluster: bool = True
    min_score: int = 50
    auto_decide_target_pct: float = 70.0


@dataclass(slots=True)
class PipelineConfig:
    provider: str = "ollama"
    prompt_pack: str = "default"
    max_workers: int = 4
    fail_fast: bool = False
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    queue: TriageQueueConfig = field(default_factory=TriageQueueConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    lsp: LSPConfig = field(default_factory=LSPConfig)
    heuristics: HeuristicsConfig = field(default_factory=HeuristicsConfig)
    post_validation: PostValidationConfig = field(default_factory=PostValidationConfig)
    code_context_lines: int = 6
    dataflow_context_lines_before: int = 30
    dataflow_context_lines_after: int = 10
    max_code_chars: int = 4000
    max_trace_steps: int = 12
    max_evidence_chars: int = 32000
    context_retrieval_rounds: int = 2
    code_walk_first: bool = True
    slow_finding_seconds: int = 900
    max_tool_calls: int = 20
    callsite_search_rounds: int = 3
    callsite_dataflow_requests: int = 4
    skip_closure_audits: list[str] = field(default_factory=list)
    sbom_path: str = ""
    build_untrusted_input: bool = False
    parallel_llm: int = 2
    redact_secrets: bool = False
    secrets_without_model: bool = True
    deployment_config: str | None = None
    resolve_vulnerable_symbols: bool = True
    nvd_api_key: str | None = None
    govulncheck_report: str | None = None
    scan_out_dir: str | None = None


def load_provider_config(name: str, *, config_dir: Path | None = None) -> ProviderConfig:
    """Load `configs/providers/<name>.yaml`."""
    base = config_dir or CONFIG_DIR
    path = base / "providers" / f"{name}.yaml"
    if not path.is_file():
        available = sorted(p.stem for p in (base / "providers").glob("*.yaml"))
        raise ConfigError(f"no provider profile '{name}' at {path}. Available: {available}")
    data = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return ProviderConfig.from_dict(data, name=name)


def provider_kind(name: str, *, config_dir: Path | None = None) -> str:
    """The profile's `kind` without resolving its environment (keys may not be set yet)."""
    path = (config_dir or CONFIG_DIR) / "providers" / f"{name}.yaml"
    if not path.is_file():
        return ""
    return str((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("kind", ""))


OLLAMA_PIPELINE = CONFIG_DIR / "pipeline-ollama.yaml"
_OLLAMA_ONLY = ("callsite_search_rounds", "callsite_dataflow_requests", "skip_closure_audits")


def keep_ollama_only_settings(cfg: PipelineConfig, provider_kind: str) -> None:
    """The lightened checks are Ollama's alone: any other provider gets the defaults back,
    whatever the file said."""
    from dataclasses import MISSING

    if provider_kind == "ollama":
        return
    for f in PipelineConfig.__dataclass_fields__.values():  # type: ignore[attr-defined]
        if f.name in _OLLAMA_ONLY:
            setattr(cfg, f.name, f.default_factory() if f.default_factory is not MISSING else f.default)


def _read_pipeline(path: Path, seen: tuple[Path, ...] = ()) -> dict:
    """The file's keys over those of the file it `extends:`, section by section."""
    raw = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.is_file() else {}
    parent = raw.pop("extends", None)
    if not parent:
        return raw
    parent_path = (path.parent / parent).resolve()
    if parent_path in seen or parent_path == path.resolve():
        raise ConfigError(f"{path}: extends loops back to {parent_path}")
    if not parent_path.is_file():
        raise ConfigError(f"{path}: extends a missing file {parent_path}")
    merged = _read_pipeline(parent_path, (*seen, path.resolve()))
    for key, value in raw.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def load_pipeline_config(path: Path | None = None) -> PipelineConfig:
    path = path or (CONFIG_DIR / "pipeline.yaml")
    raw = _expand_env(_read_pipeline(path))
    scope = ScopeConfig(**raw.pop("scope", {}) or {})
    queue = TriageQueueConfig(**raw.pop("queue", {}) or {})
    verify = VerificationConfig(**raw.pop("verification", {}) or {})
    heur = HeuristicsConfig(**raw.pop("heuristics", {}) or {})
    post = PostValidationConfig(**raw.pop("post_validation", {}) or {})
    return PipelineConfig(
        scope=scope, queue=queue, verification=verify, heuristics=heur, post_validation=post, **raw
    )


def load_lsp_config(path: Path | None = None) -> LSPConfig:
    path = path or (CONFIG_DIR / "lsp.yaml")
    if not path.is_file():
        return LSPConfig()
    raw = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    known = set(LSPConfig.__dataclass_fields__)  # type: ignore[attr-defined]
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"{path}: unknown keys {sorted(unknown)}")
    return LSPConfig(**raw)


def list_providers(config_dir: Path | None = None) -> list[str]:
    base = (config_dir or CONFIG_DIR) / "providers"
    return sorted(p.stem for p in base.glob("*.yaml")) if base.is_dir() else []


def load_scanner_config(name: str, *, config_dir: Path | None = None) -> ScannerConfig:
    base = config_dir or CONFIG_DIR
    path = base / "scanners" / f"{name}.yaml"
    if not path.is_file():
        available = sorted(p.stem for p in (base / "scanners").glob("*.yaml"))
        raise ConfigError(f"no scanner profile '{name}' at {path}. Available: {available}")
    data = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return ScannerConfig.from_dict(data, name=name)


def list_scanners(config_dir: Path | None = None) -> list[str]:
    base = (config_dir or CONFIG_DIR) / "scanners"
    return sorted(p.stem for p in base.glob("*.yaml")) if base.is_dir() else []
