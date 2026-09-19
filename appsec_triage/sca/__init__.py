"""Deciding a dependency CVE by the symbol it lives in, not by the version alone."""

from .advisories import Advisory, collect
from .presence import PresenceResult, SymbolPresence, find_symbol
from .reach import Reachability, ReachResult, assess, needs_input_path
from .resolve import SymbolResolver, VulnerableSymbol
from .verdict import CVEDecision, CVEVerdict, decide

__all__ = [
    "Advisory",
    "CVEDecision",
    "CVEVerdict",
    "PresenceResult",
    "ReachResult",
    "Reachability",
    "SymbolPresence",
    "SymbolResolver",
    "VulnerableSymbol",
    "assess",
    "collect",
    "decide",
    "find_symbol",
    "needs_input_path",
]
