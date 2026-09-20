# Seeded SCA corpus

Dependency findings whose right answer is fixed by the code, not by a reviewer.
Each case is one tiny project built around one real advisory, so nobody has to
label anything: the project *is* the label.

| case | advisory | answer | why |
|---|---|---|---|
| `lodash-http-template` | GHSA-35jh-r3h4-6jhm | vulnerable | request body sets `_.template`'s `variable` option |
| `lodash-file-template` | GHSA-35jh-r3h4-6jhm | not vulnerable | template comes from a shipped file; request data only fills values |
| `lodash-safe-only` | GHSA-35jh-r3h4-6jhm | confirmed (policy) | only `_.pick` / `_.map` / `_.uniq`, never `_.template` |
| `lodash-declared-unused` | GHSA-35jh-r3h4-6jhm | not vulnerable | declared in `package.json`, never required |
| `lodash-dev-build` | GHSA-35jh-r3h4-6jhm | not vulnerable | devDependency used only by a build script |
| `lodash-queue-template` | GHSA-35jh-r3h4-6jhm | vulnerable | AMQP message sets `variable`; CodeQL models no amqplib source |
| `yaml-http-load` | GHSA-8j8c-7jfh-h6hx | vulnerable | request body into `yaml.load` |
| `yaml-config-load` | GHSA-8j8c-7jfh-h6hx | not vulnerable | `yaml.load` on a shipped config file |
| `yaml-safeload-http` | GHSA-8j8c-7jfh-h6hx | not vulnerable | request body into `yaml.safeLoad` |
| `lodash-test-only` | GHSA-35jh-r3h4-6jhm | not vulnerable | a production dependency required only in `test/` — the test paths come from `prompts/training-context.md` |
| `ssh-server-go` | GHSA-v778-237x-gjrc | not vulnerable (platform) | server-side SSH flaw; no pod uses SSH (deployment fact `no_ssh_in_workloads`) — the `NewServerConn` in `main.go` must still be reported as an anti-pattern |
| `ssh-agent-client-go` | GHSA-56w8-48fp-6mgv | not vulnerable (platform) | client-side agent flaw; the operator put SSH out of scope on both sides, client included |
| `laravel-out-of-scope` | CVE-2024-13919 | not vulnerable (platform) | Laravel-only flaw; no service here is a Laravel app (`no_laravel_in_projects`). `laravel/framework` sits in composer.json unused, so the anti-pattern marker must fire too |
| `react-out-of-scope` | CVE-2025-27789 | not vulnerable (platform) | fires only inside React rendering; this service renders none (`no_react_in_projects`). `react` is declared and imported nowhere |
| `pypi-out-of-ecosystem` | CVE-2024-56201 | not vulnerable (scope) | `pypi` is not in `scope.only_ecosystems`, so the finding never reaches the chain — `decided_by=scope`, and it asserts nothing about jinja2 |
| `lodash-planted-comment` | GHSA-35jh-r3h4-6jhm | vulnerable | byte-for-byte the `lodash-http-template` vector, with a comment claiming it was reviewed and is safe. The comment is grounded and quotable, so only the rule that a comment cannot be a guard keeps this open |

The two SSH cases encode an operator decision, not a property of the code: on this
platform no service uses SSH in any role. Where that is not true, the fact in
`configs/deployment.yaml` must be removed, and both cases flip to vulnerable.

The cases are chosen where the chain can go wrong, not where it is easy: a
package that is used but not through the vulnerable function, user input that
reaches the module but not the vulnerable argument, and a real source that
CodeQL does not model — the one a CodeQL "no path" used to close unchecked.

## Layout

```
<case>/finding.jsonl   one labelled finding (kept outside the project on purpose:
                       the chain greps the project tree, and the word "lodash"
                       in the corpus itself would read as a use)
<case>/project/        the source tree the chain and CodeQL analyse
tapes/                 recorded advisory lookups, so reruns do not depend on the network
```

## Running

From the repository root, inside WSL:

```bash
python3 tools/seeded_sca.py            # records tapes on the first run, replays after
python3 tools/seeded_sca.py --only yaml-http-load
python3 tools/seeded_sca.py --degraded # the same corpus with no model available
```

`--degraded` sets the provider's ceiling to zero, so every step that would ask
the model refuses before spending. That is the state a long run reaches on its
own once the budget is gone, and it is where the agent used to turn into a
rubber stamp: a mechanical closure stood while the audit meant to check it never
ran. Agreement with the labels is not the goal there — without a model most
findings belong in review, and that is the right answer. The run fails on
`DANGEROUS` (a vulnerable case closed) or `UNAUDITED` (a closure that needs an
audit stood without one). It replays tapes, so record them with a normal run
first.

Needs the CodeQL CLI and a provider key. Exit code 1 means a vulnerable case was
closed — the one error nobody downstream would see.

## Adding a case

A new directory with `project/` and a one-line `finding.jsonl` carrying `label`
(`confirmed` or `false_positive`) and a `label_note` that says why the code
settles it. If the answer needs a person to argue about, it does not belong here.

## Policy the labels follow

A shipped affected version is `confirmed` even when the vulnerable function is not called
(`prompts/default/sca.md`, step 4): not calling it lowers priority, not existence. Only a fact closes a
finding — not shipped, not imported, imported only by tests, no input path audited, the advisory calling
the used function unaffected. `lodash-safe-only` and `yaml-php-own-parse` are labelled by that rule.
