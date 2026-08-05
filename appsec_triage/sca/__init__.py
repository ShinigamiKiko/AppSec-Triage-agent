"""Deciding a dependency CVE by the symbol it lives in, not by the version alone.

A version range says a vulnerable package is installed. It does not say the
application can reach the flaw, and on a real project that gap turned 89 CVEs
into 89 items nobody could act on.

The chain runs inside the scan, per finding, with nothing prepared in advance:

1. the scanner reports a package and version;
2. `advisories` asks OSV, GHSA and NVD what the flaw is and where it was fixed;
3. `resolve` fetches that fix and has the model name the vulnerable symbol,
   checking the name against the published source of the affected version;
4. `presence` searches this repository for that symbol, strictly and without a
   model;
5. `reach` establishes, for flaws that need attacker-controlled input, whether
   it arrives — using the language server and CodeQL together.

Step 5 is deliberately unable to answer alone: a call site proves the symbol is
used, not that an attacker controls what flows into it, and a taint query proves
a path exists in one language's database, not that the call is the vulnerable
one. Either tool missing means the answer is unknown, never safe.
"""

from .advisories import Advisory, collect
from .presence import PresenceResult, SymbolPresence, find_symbol
from .reach import ReachResult, Reachability, assess, needs_input_path
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
