# Go

## Stack

- Go application.
- Fiber REST API.
- PostgreSQL through GORM and Redis.
- RabbitMQ for messaging.
- MinIO/S3 for object storage.
- Uber FX for dependency injection.

## Test And Non-Production Paths

Directories, Go — the toolchain itself ignores this one:

- `testdata/`

File names, Go:

- `*_test.go`

## Analysis

- govulncheck compiles the program and reports a call trace from the application to
  the vulnerable symbol; CodeQL for Go answers the same question when it runs.
- An HTTP/2 flaw cannot fire over a client whose transport sets `TLSClientConfig`
  without `ForceAttemptHTTP2`: Go then leaves HTTP/2 off.
- Settings worth searching when a reached call is judged: `ForceAttemptHTTP2`,
  `TLSClientConfig`, `InsecureSkipVerify`, `http.Transport{` — the transport is
  often built in another file than the call.
- Modules are in the module cache or `vendor/`.

## Calls a Call Graph Misses

`reflect.ValueOf`, `MethodByName`, `plugin.Open`, `//go:generate`, `//go:build`
tags, `exec.Command`, and interface values filled from a registry.

## Govulncheck Authoritative Trace Gate

For a finding whose scanner is `govulncheck`, a trace with at least two positioned
frames including `source` and `sink` is an authoritative confirmation. Do not
replace it with `unknown`, or close it because a dependency chain did not find
another signal. The caller may ask for a refutation, but accept `false_positive`
only when every quoted evidence entry is copied exactly from the supplied package
context and the reason identifies a concrete contradiction to the trace or package
facts. Missing evidence, provider errors, malformed JSON, `unknown`, and any answer
that does not explicitly refute the trace preserve the confirmed baseline.
