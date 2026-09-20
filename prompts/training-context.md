# Project Context

This file is project-specific context, not a replacement for the system prompt.
It is attached to every model request. Use it to avoid spending analysis on
technologies and deployment modes that are outside this project, but always
prefer concrete evidence from the finding and repository over assumptions here.

## Stack

- Go application.
- Fiber REST API.
- PostgreSQL through GORM and Redis.
- RabbitMQ for messaging.
- MinIO/S3 for object storage.
- Uber FX for dependency injection.
- Linux Alpine containers; deployment may run on Kubernetes.

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
CodeQL import gate and the SAST heuristics use exactly these patterns. Edit it
here, and only here. A pattern ending in `/` is a directory name matched against
any segment of a path; any other pattern is a file-name glob.

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

Directories, JavaScript and TypeScript:

- `__tests__/`
- `__mocks__/`
- `__fixtures__/`
- `__snapshots__/`
- `cypress/`

Directories, Go — the toolchain itself ignores this one:

- `testdata/`

File names, Go:

- `*_test.go`

File names, Python:

- `*_test.py`
- `test_*.py`
- `conftest.py`

File names, PHP, Java and C# — the CamelCase suffix convention:

- `*Test.*`
- `*Tests.*`
- `*TestCase.*`
- `*Spec.*`
- `*.phpt`

File names, JavaScript and TypeScript:

- `*.test.*`
- `*.spec.*`
- `*-test.*`
- `*-spec.*`
- `*.cy.*`
- `*.stories.*`

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
