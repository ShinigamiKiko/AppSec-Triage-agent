---
id: laravel
version: "1.0"
name: Laravel / Eloquent (PHP)
detect:
  files: ["composer.json", "composer.lock"]
  contains:
    - '"laravel/framework"'
    - '"laravel/lumen-framework"'
where:
  routes and controllers: ["routes/", "app/Http/Controllers/", "app/*/Controllers/"]
  access control: ["app/Http/Kernel.php", "app/Http/Middleware/", "app/Policies/", "app/Providers/AuthServiceProvider.php", "config/auth.php", "config/jwt.php", "config/sanctum.php", "config/cors.php"]
  request input binding and validation: ["app/Http/Requests/", "app/Rules/", "app/Dto/", "app/DTO/", "app/Data/"]
  output (API resources, Blade): ["app/Http/Resources/", "resources/views/"]
  persistence and queries: ["app/Models/", "app/Repositories/", "database/migrations/", "config/database.php"]
  async and CLI entry points: ["app/Jobs/", "app/Listeners/", "app/Console/Commands/", "app/Console/Kernel.php"]
  error handling: ["app/Exceptions/Handler.php"]
  service wiring and business logic: ["app/Providers/", "app/Services/", "config/services.php", "config/app.php"]
---
**Request input.** `$request->input()`, `->query()`, `->all()`, `->get()`, `->json()`, the `request()`
helper, route parameters, `$request->file()`, headers and cookies. Cookies are encrypted by
`EncryptCookies` unless listed in its `$except`.

**Routes are the entry points, middleware decides who reaches them.** `routes/api.php` gets the `api`
group, `routes/web.php` the `web` group (session, CSRF); `RouteServiceProvider` mounts these and any
extra route file. Authentication and authorisation come from middleware on the route or its group
(`auth`, `auth:api`, `can:`, custom aliases in `app/Http/Kernel.php` `$routeMiddleware`), from
`$this->authorize()` / `Gate::allows()` / policies in the controller. A route outside every
authenticated group is public.

**Validation.** A `FormRequest` (`app/Http/Requests/`) runs `rules()` and `authorize()` before the
controller. `$request->validated()` is the checked subset; `$request->all()` is everything the client
sent. Validation constrains shape, not safety: a validated string is still attacker-chosen.

**Mass assignment.** `Model::create($request->all())`, `->fill()`, `->update($request->all())` write
every column the model allows: `$fillable` limits it, `$guarded = []` allows all — then a client can
set `is_admin`, `role`, `user_id`.

**Eloquent and the query builder bind values.** Injection lives in `DB::raw()`, `whereRaw`,
`selectRaw`, `orderByRaw`, `havingRaw`, `DB::statement` / `DB::select` with interpolated strings, and
in column names from input (`orderBy($request->input('sort'))`, `->where($request->input('field'), …)`)
— identifiers are not bound; only an allowlist makes them safe.

**Blade.** `{{ $value }}` is escaped (`htmlspecialchars`); `{!! $value !!}` is raw. Escaping does not
make a URL safe: `href="{{ $url }}"` with `javascript:` runs on click, and `redirect($input)`,
`redirect()->to($input)`, `redirect()->away($input)` are open redirects.

**Configuration.** `env()` is read in `config/*.php`; elsewhere it returns null once config is cached.
`.env.example` holds placeholders. `APP_KEY` in a committed `.env` is a real secret: it signs cookies
and encrypted payloads. `APP_DEBUG=true` in production shows stack traces and environment values,
and with an old Ignition it was remote code execution (CVE-2021-3129).

**CSRF.** The `web` group verifies tokens except paths in `VerifyCsrfToken::$except`. The `api` group
does not, by design — a finding only when an API route authenticates by session cookie.
