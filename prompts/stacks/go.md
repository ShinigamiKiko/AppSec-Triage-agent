---
id: go
version: "1.0"
name: Go (net/http, chi, gin, echo, gRPC)
detect:
  files: ["go.mod"]
  contains:
    - "module "
# Every Go service, whatever the router. A Fiber service also gets fiber.md: that profile
# sorts first, so its map is shown first and this one adds only paths it did not show.
where:
  entry points: ["main.go", "cmd/", "*/cmd/"]
  HTTP routing and handlers: ["router/", "*/router/", "routes/", "*/routes/", "handlers/", "*/handlers/", "handler/", "*/handler/", "*/http/", "*/transport/", "server/", "*/server/", "controllers/", "*/controllers/"]
  gRPC and API contracts: ["api/", "*/api/", "proto/", "*/proto/", "*/grpc/", "grpc/", "*/pb/"]
  auth and middleware: ["middleware/", "*/middleware/", "middlewares/", "*/middlewares/", "auth/", "*/auth/", "*/interceptor/", "*/interceptors/"]
  request input and validation: ["dto/", "*/dto/", "*/request/", "*/requests/", "*/validator/", "*/validation/"]
  business logic: ["service/", "*/service/", "services/", "*/services/", "usecase/", "*/usecase/", "*/usecases/"]
  persistence and queries: ["repository/", "*/repository/", "*/repositories/", "storage/", "*/storage/", "*/store/", "*/db/", "*/postgres/", "*/queries/", "migrations/", "*/migrations/", "sqlc.yaml"]
  outbound calls: ["*/client/", "*/clients/", "*/gateway/", "*/integration/", "*/integrations/"]
  configuration: ["config/", "*/config/", "configs/"]
where_exclude: ["*/testdata", "testdata", "*/mocks", "mocks", "docs", "*/docs", "third_party"]
---
**Request input.** `r.URL.Query()`, `r.FormValue()`, `r.PostFormValue()`, `r.PathValue()`, `r.Header`,
`r.Cookie()`, `json.NewDecoder(r.Body).Decode()`; router helpers `chi.URLParam`, `mux.Vars`, gin
`c.Param` / `c.Query` / `c.ShouldBind*`, echo `c.Param` / `c.Bind`; in gRPC, every field of the
request message and the incoming `metadata`.

**Where a route is mounted decides who reaches it.** Middleware protects only what it wraps:
`mux.Handle("/x", auth(h))`, a chi or gin group with `Use(auth)`. gin and Fiber apply `Use` only to
routes registered after it; chi refuses `Use` after routes. A route on the root router while auth
sits on a group is public. In gRPC, an interceptor passed to `grpc.NewServer` covers every method;
check how it decides which `FullMethod`s skip authentication.

**SQL binds values.** `database/sql`, `sqlx`, `pgx` with `$1` / `?` placeholders and sqlc-generated
queries are safe. Injection is `fmt.Sprintf` or `+` into `Query`, `QueryRow`, `Exec`, and identifiers
from input (`ORDER BY`, table or column names) — placeholders cannot bind those.

**Commands.** `exec.Command(name, args...)` runs no shell: input in `args` is not command injection.
It is when the program is `sh -c` / `bash -c` with input in the script, when input picks the program,
or when an argument starting with `-` is read as an option (argument injection).

**Paths.** `filepath.Join(base, input)` and `filepath.Clean` do not confine — `../` still escapes.
Confinement is `os.Root` (Go 1.24), `filepath.IsLocal`, or a prefix check after `filepath.Abs`.
`http.FileServer` and `http.ServeFile` reject `..` in the URL path, not in a path built from a query
parameter.

**Templates.** `html/template` escapes by context, including `href` (`javascript:` becomes
`#ZgotmplZ`). `text/template` escapes nothing: HTML rendered with it is XSS. `template.HTML(input)`,
`template.JS`, `template.URL` switch escaping off for that value.

**Redirects and outbound requests.** `http.Redirect(w, r, input, …)` is an open redirect.
`http.Get(input)` or a client request to a URL from input is SSRF. `InsecureSkipVerify: true`
disables certificate checks on outbound TLS.

**Errors and resources.** `http.Error(w, err.Error(), 500)` sends internal errors to the client.
Decoding `r.Body` without `http.MaxBytesReader` reads any size; an `http.Server` without
`ReadHeaderTimeout` holds slow connections — behind an ingress, its limits apply first. A map written
from handlers without a mutex crashes the process (`concurrent map writes`).
