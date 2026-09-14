"""Provider factory: profile name -> concrete client.

Adding a fourth provider means one class + one YAML file + one line here.
"""

from __future__ import annotations

from ..config import ConfigError, ProviderConfig
from .base import LLMClient
from .ollama import OllamaClient
from .openai_compat import DeepSeekClient, OpenAIClient

_REGISTRY = {
    "ollama": OllamaClient,
    "openai": OpenAIClient,
    "deepseek": DeepSeekClient,
}


def build_client(cfg: ProviderConfig) -> LLMClient:
    try:
        klass = _REGISTRY[cfg.kind]
    except KeyError:
        raise ConfigError(f"provider '{cfg.name}': unsupported kind '{cfg.kind}'. Known: {sorted(_REGISTRY)}") from None
    return klass(cfg)  # type: ignore[return-value]


