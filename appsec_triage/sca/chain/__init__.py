"""Compatibility facade for dependency-chain analysis."""

from .models import ChainResult
from .orchestration import DependencyChain

__all__ = ["DependencyChain", "ChainResult"]
