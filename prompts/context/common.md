# Project Context

This context is attached to every model request, together with the part for each
ecosystem listed in `APPSEC_ECOSYSTEMS` (`npm.md`, `go.md`, ... in this directory).
It is not a replacement for the system prompt. Use it to avoid spending analysis
on technologies and deployment modes that are outside this project, but always
prefer concrete evidence from the finding and repository over assumptions here.

## Platform

- Linux (Alpine) containers; deployment may run on Kubernetes.
- docker-compose files describe a developer's machine, not the production
  deployment. A finding in one is a false positive, and nothing read from one
  (`--host`, debug ports, local databases) says anything about production.

## Not Applicable Unless Repository Evidence Says Otherwise

- SSH server or SSH client functionality.
- Kubernetes API client functionality. Kubernetes is a deployment platform,
  not an application dependency.
- MongoDB, Elasticsearch, Kafka, gRPC, and GraphQL.
- Windows-only runtime behavior.
- Docker SDK or Docker Engine API calls from the application.
- TLS termination handled by the application itself when TLS is terminated at
  the ingress.
- Advanced x509 policy-mapping, ECH, or PSK-specific behavior without a direct
  call/configuration in the repository.

## Test And Non-Production Paths

Code under the paths below is test code, not production code. Findings there are
test-scope findings: treat them as false positives unless the evidence explicitly
shows that the test code is shipped or invoked by production code. A dependency
imported only from these paths is not used by the shipped application.

This list is also read by the agent's own code — the dependency search, the
CodeQL import gate, the condition search and the SAST heuristics use exactly
these patterns, from this file and every ecosystem file next to it, whatever
`APPSEC_ECOSYSTEMS` says. Edit them here, and only here. A pattern ending in `/`
is a directory name matched against any segment of a path; any other pattern is
a file-name glob. The language-specific patterns live in the ecosystem files.

Only conventions the whole language or its standard test runner uses belong
here. Every pattern added makes more code count as test code, which makes a
closure easier to reach — a name one project happens to use is not a reason to
widen the list for everybody.

Directories, any ecosystem:

- `test/`
- `tests/`
- `testing/`
- `spec/`
- `specs/`
- `fixture/`
- `fixtures/`
- `mocks/`
- `e2e/`
- `features/`

File names, any ecosystem:

- `*.feature`

## Triage Rules

- A dependency being present is not enough: check version, actual use, call
  reachability, and the advisory precondition.
- A govulncheck or Wolfee closure is strong evidence, but an LLM audit must
  still consider reflection, callbacks, interface dispatch, generated code,
  plugins, and build constraints.
- A reachable call is not automatically exploitable. Check whether attacker
  controlled input reaches the vulnerable operation and whether deployment
  conditions required by the advisory are present.
- OSV, EPSS, and CISA KEV data are supporting evidence. A network timeout is
  missing evidence, not evidence that the vulnerability is absent.
