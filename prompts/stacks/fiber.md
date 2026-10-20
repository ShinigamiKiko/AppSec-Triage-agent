---
id: fiber
version: "1.0"
name: Go / Fiber
detect:
  files: ["go.mod"]
  contains:
    - "github.com/gofiber/fiber"
where:
  route registration: ["routes/", "*/routes/", "router/", "*/router/", "*/fiber_app.go", "main.go", "cmd/"]
  handlers: ["handlers/", "*/handlers/", "handler/", "*/handler/", "controllers/", "*/controllers/"]
  auth and middleware: ["middleware/", "*/middleware/", "middlewares/", "*/middlewares/", "auth/", "*/auth/"]
  request input binding and validation: ["dto/", "*/dto/", "request/", "*/request/", "requests/", "*/requests/", "validator/", "*/validator/", "validation/", "*/validation/"]
  business logic: ["service/", "*/service/", "services/", "*/services/", "usecase/", "*/usecase/", "*/processor/", "*/port/"]
  persistence and queries: ["storage/", "*/storage/", "repository/", "*/repository/", "repositories/", "*/repositories/", "*/db/", "migrations/", "*/migrations/"]
  configuration and wiring: ["config/", "*/config/", "*/di/", "*/appcfg/"]
where_exclude: ["*/testdata", "testdata", "docs", "*/mocks", "mocks"]
---
**Request input.** `c.Params()`, `c.Query()`, `c.Body()`, `c.BodyParser()`, `c.QueryParser()`,
`c.FormValue()`, `c.FormFile()`, `c.Get(header)`, `c.Cookies()`, and anything decoded from them.
`c.IP()` and `X-Forwarded-For` are client-controlled unless `fiber.Config{ProxyHeader,
EnableTrustedProxyCheck, TrustedProxies}` restricts them.

**Registration order is the security boundary.** Middleware added with `app.Use()` or `group.Use()`
runs only for routes registered after it on that app or group. A route registered on `app` while
auth sits on `api := app.Group("/api", auth)` is outside auth. Check where each route is mounted, not
only that an auth middleware exists.

**Values from the context are reused.** Unless `fiber.Config{Immutable: true}`, strings returned by
`c.Params`, `c.Query`, `c.Get` and friends point into a buffer Fiber reuses for the next request.
Kept beyond the handler — stored in a map or cache, passed to a goroutine — without
`utils.CopyString` / `strings.Clone`, they change under you and can show one user's data to another.

**GORM binds values.** `db.Where("name = ?", v)` is safe. Injection is in `fmt.Sprintf` / `+` into
`Where`, `Raw`, `Exec`, `Order`, `Group`, `Select`, `Joins`, and in `db.First(&x, id)` /
`db.Find(&x, id)` when `id` is a string from input — GORM treats a string there as an SQL condition.

**Errors.** Fiber's default error handler sends `err.Error()` to the client: database and internal
errors leak unless `fiber.Config{ErrorHandler}` maps them. `c.Status(500).SendString(err.Error())`
does the same by hand.

**Exposure.** Swagger UI (`swaggo`, `/swagger/*`) and `/metrics` registered on the public app are
reachable by anyone who reaches the service. `cors.New(cors.Config{AllowOrigins: "*",
AllowCredentials: true})` is a misconfiguration.
