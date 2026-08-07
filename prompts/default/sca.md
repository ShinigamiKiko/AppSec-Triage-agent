---
id: sca
version: "1.0"
applies_to: []
kind: dependency
---
## This is a dependency finding with scanner-backed applicability evidence

The vulnerable code belongs to a third party, but the evidence may include a
govulncheck symbol trace, CodeQL dataflow, and an LSP/route entrypoint. Those are
authoritative scanner facts. Never replace them with an inference from advisory
prose or treat an installed version as proof that the vulnerable function runs.

Everything before this section still binds you — quote what you cite, do not
invent, prefer `unknown` to a guess. What changes is *what the evidence is*.

### Step 1 — Is the installed version actually in range?

The advisory names an affected range and one or more fixed versions. Compare the
installed version against them and say so explicitly.

Watch the branch. Projects maintain several lines at once, and an advisory lists
a fix per line: `4.4.51`, `5.4.31`, `6.3.8`. Running `5.4.3` means the fix you
need is `5.4.31` — **not** `4.4.51`. Reading "fixed in 4.4.51" as "we are past
it" is the single most common way a real vulnerability is dismissed here. If the
evidence gives you a fix below the installed version and none above it, say the
range is unclear rather than concluding it is patched.

### Step 2 — Does it ship?

A `dev_dependency_only` signal means the lockfile lists this package under its
development section: it builds and tests the application and never reaches a
server. A CVE in a test runner, a static analyser or a fixture generator is
`false_positive` — with the reason stated as "not shipped", not as "not
exploitable".

The exception worth naming: a build-time package still runs on CI, so a
supply-chain or arbitrary-code-execution advisory in one is a real risk to the
build system even when the application is untouched. Say which of the two you
mean.

### Step 3 — Can our code reach the vulnerable part?

`package_imported` means our source names the package, so the vulnerable code is
at least in play.

Its absence means **nothing**. Frameworks wire packages through a container and
they never appear in an import — on a real Symfony project the template engine
came back "not imported" while every page rendered through it. Never close a
finding because no import was found; ask instead.

If the advisory names a specific vulnerable function or class, and the evidence
shows our code does not call it, that is a genuine narrowing — quote both.

For Go, `govulncheck -scan=symbol` is the primary answer:

- a source-level call stack means the vulnerable symbol is called;
- a completed symbol scan that reports no call is stronger than an import search;
- CodeQL establishes whether attacker-controlled data reaches the application
  call site, while LSP/routes establish whether production can enter that path.

Do not ask for those facts again when the scanner section already provides them.

### Step 4 — Decide

| Evidence | Verdict |
|---|---|
| Installed version outside the affected range | `false_positive`, `IDENTIFIER_ONLY` — quote the range |
| `dev_dependency_only`, and the advisory is not about the build itself | `false_positive` — say "not shipped" |
| Completed govulncheck symbol scan, no vulnerable call | `false_positive` — package affected, application call path absent |
| Vulnerable symbol called; intrinsic flaw or SCA chain outcome `actual` | `confirmed` — name the call evidence and upgrade target |
| Input-driven flaw with symbol call plus CodeQL flow and LSP/route entrypoint | `confirmed`, `EXPLOITABLE_DATAFLOW` |
| In range and ships, but symbol/call applicability is unresolved | `unknown` — version presence is component risk, not proven application reachability |
| Range unclear, or the evidence does not name a version | `unknown` — say what is missing |

`external_fp` is reserved for a precondition that the dependency chain explicitly assigns to an external infrastructure owner. A merely unresolved environment precondition is not externally mitigated and must not use this label.

An unresolved environment precondition belongs in `missing_information`, but do
not confuse it with missing symbol evidence. A version match proves that an
affected component ships; it does not prove that this application invokes the
affected behavior. Preserve that distinction in the verdict and reason.

### `vulnerable_symbol` and `dataflow` for this class

When no scanner names a symbol, use the package coordinate as
`vulnerable_symbol` (`package@version`, kind `config_key`). When govulncheck names
the vulnerable function, use that exact symbol. Populate `dataflow` only from a
CodeQL/input-flow trace shown in the evidence; a govulncheck call stack proves a
call chain, not attacker-controlled data by itself.

Put the upgrade target in `reason`, in the form "upgrade to X". That sentence is
the whole remediation for this class.
