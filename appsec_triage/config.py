"""Config loading: one YAML profile per provider + one pipeline config.

Provider profiles deliberately do NOT share a schema beyond the common fields —
`options` is a free-form dict passed straight through to the provider, because
Ollama's `num_ctx`/`num_predict` and OpenAI's `seed`/`top_p` have nothing to do
with each other and pretending otherwise leaks one provider's model into all.
"""

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
    """Recursively expand ${VAR} and ${VAR:-default} inside loaded YAML.

    Secrets never live in the YAML files; they are referenced by env var name
    so the configs stay committable.
    """
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
    """Common transport/decoding knobs. Provider-specific ones live in `options`."""

    name: str
    kind: Literal["ollama", "openai", "deepseek"]

    @property
    def leaves_the_perimeter(self) -> bool:
        """Does a prompt sent to this provider reach a third party?

        Ollama runs where the pipeline runs, so the code never moves. The hosted
        providers keep request logs, and a prompt built from a `.env` can carry
        live signing keys — measured on a real project, 32 and 64 characters of
        them. What follows from this is which defaults apply, not a refusal:
        the choice of provider is the operator's.
        """
        return self.kind != "ollama"
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
    keep_raw_response: bool = False

    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, name: str) -> "ProviderConfig":
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
    require_sast_reachability: bool = True


@dataclass(slots=True)
class ScannerConfig:
    """How to invoke one SAST tool. Per-tool quirks live in scanners/tools.py."""

    name: str = "scanner"
    mode: Literal["auto", "native", "docker"] = "auto"
    # One path, or several to try in order. A list is what lets one profile
    # serve a workstation and an image at once: the same tool lives under `~`
    # on one and in `/usr/local/bin` on the other.
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

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, name: str) -> "ScannerConfig":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(data) - known - {"name"}
        if unknown:
            raise ConfigError(f"scanner '{name}': unknown config keys: {sorted(unknown)}")
        return cls(**{**data, "name": name})


@dataclass(slots=True)
class ScopeConfig:
    """What is not worth triaging at all. Deterministic policy, never a guess."""

    enabled: bool = True
    exclude_rules: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    only_cwes: list[str] = field(default_factory=list)
    min_severity: str | None = None


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
    """Second, adversarial pass over selected verdicts.

    Not a re-vote: asked the same question twice a model repeats its mistake, and
    this one's errors are systematic. The second pass asks "what is wrong with
    this verdict" instead, which is a different task and breaks the shared prior.

    Selective by default — a pass costs as much as the first, so it is spent
    where precision is measurably weakest (`confirmed`) and where the checks
    already flagged something.
    """

    enabled: bool = False
    mode: Literal["advisory", "authoritative"] = "advisory"
    challenge_verdicts: list[str] = field(default_factory=lambda: ["confirmed"])
    challenge_on_override: bool = False
    challenge_cwes: list[str] = field(default_factory=list)
    challenge_closures_above_consequence: int = 0


@dataclass(slots=True)
class TriageQueueConfig:
    """How much manual review the team is willing to spend, and on what."""

    enabled: bool = True
    review_budget_pct: float = 30.0
    cluster: bool = True
    min_score: int = 50


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
    redact_secrets: bool = False
    secrets_without_model: bool = True
    deployment_config: str | None = None
    resolve_vulnerable_symbols: bool = False
    nvd_api_key: str | None = None


def load_provider_config(name: str, *, config_dir: Path | None = None) -> ProviderConfig:
    """Load `configs/providers/<name>.yaml`."""
    base = config_dir or CONFIG_DIR
    path = base / "providers" / f"{name}.yaml"
    if not path.is_file():
        available = sorted(p.stem for p in (base / "providers").glob("*.yaml"))
        raise ConfigError(f"no provider profile '{name}' at {path}. Available: {available}")
    data = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return ProviderConfig.from_dict(data, name=name)


def load_pipeline_config(path: Path | None = None) -> PipelineConfig:
    path = path or (CONFIG_DIR / "pipeline.yaml")
    raw = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.is_file() else {}
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
