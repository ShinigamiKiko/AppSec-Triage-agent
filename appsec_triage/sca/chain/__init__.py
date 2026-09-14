"""Compatibility facade for dependency-chain analysis."""

from .helpers import _call_site_position, _needs_llm_advisory
from .models import ChainResult
from .orchestration import DependencyChain

# Keep these module attributes available for existing integrations and tests
# that patch the chain's external steps at their historical import path.
from .. import advisories as adv
from .. import exploitable as exploitable_mod
from .. import llm_advisory

__all__ = ["DependencyChain", "ChainResult"]
