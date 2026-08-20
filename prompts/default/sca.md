---
id: sca
version: "1.0"
applies_to: []
kind: dependency
---
## This is a dependency finding, not a weakness in your code

The vulnerable code belongs to a third party. You cannot read it and you are not
being asked to. Four different questions decide this, and none of them is "does
untrusted input reach a sink".

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

### Step 4 — Decide

| Evidence | Verdict |
|---|---|
| Installed version outside the affected range | `false_positive`, `IDENTIFIER_ONLY` — quote the range |
| `dev_dependency_only`, and the advisory is not about the build itself | `false_positive` — say "not shipped" |
| In range, ships, and imported | `confirmed` — name the upgrade target |
| In range and ships, reachability unclear | `confirmed` — a shipped vulnerable version is a finding; reachability changes priority, not existence |
| Range unclear, or the evidence does not name a version | `unknown` — say what is missing |

**Do not require proof of exploitability to confirm.** For a dependency the bar
is "we ship an affected version", because the exploit is public and the fix is a
version bump. Demanding a call-path here inverts the economics: upgrading is
cheap, and being wrong is not.

**An unresolved precondition is not a reason to answer `unknown`.** The section
above may report a condition it could not settle — one that lives in an
environment variable, a manifest, another team's system. That is a note for
whoever reviews the finding, not a gap in this verdict. A shipped affected
version is still `confirmed`; the unsettled condition belongs in
`missing_information`. Answering `unknown` because something was left unchecked
converts a decided finding into work for a person, which is the opposite of the
job — measured, it moved five findings per project out of a verdict and into a
queue for no gain.

### `vulnerable_symbol` and `dataflow` for this class

`vulnerable_symbol` is the package coordinate — name it `package@version`, kind
`config_key`. `dataflow` stays empty: there is no path through our code to
reconstruct, and inventing one is worse than leaving it out.

Put the upgrade target in `reason`, in the form "upgrade to X". That sentence is
the whole remediation for this class.
