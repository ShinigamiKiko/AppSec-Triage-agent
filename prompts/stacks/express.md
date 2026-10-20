---
id: express
version: "1.0"
name: Express (Node.js)
detect:
  files: ["package.json"]
  contains:
    - '"express"'
where:
  route handlers: ["routes/", "*/routes/", "controllers/", "*/controllers/", "handlers/", "*/handlers/", "api/", "*/api/"]
  auth and middleware: ["auth/", "*/auth/", "middleware/", "*/middleware/", "middlewares/", "*/middlewares/", "passport*", "*/passport*"]
  app wiring and entry point: ["app.js", "app.ts", "server.js", "server.ts", "index.js", "index.ts", "*/app.js", "*/app.ts", "*/server.js", "*/server.ts", "bin/www"]
  input validation: ["validators/", "*/validators/", "validation/", "*/validation/", "schemas/", "*/schemas/"]
  data access: ["models/", "*/models/", "db/", "*/db/", "repositories/", "*/repositories/", "migrations/"]
  business logic: ["services/", "*/services/"]
  views and output: ["views/", "*/views/", "templates/", "*/templates/"]
# Express often shares a tree with a frontend. Its client router, store and components are not
# server code: measured on a Vue + Express repository, `*/auth/` matched a Vuex store module.
# `router/` is left out of the patterns for the same reason — it is Vue's convention, not Express's.
where_exclude: ["*/store", "store", "*/stores", "*/components", "*/pages", "*/layouts", "*/assets", "public", "*/public", "*/router"]
---
**Request input.** `req.params`, `req.query`, `req.body`, `req.headers`, `req.cookies`, uploaded
files, and anything parsed from them. `express.urlencoded({ extended: true })` parses with `qs`, so
`req.body` can hold nested objects and arrays an attacker shaped.

**The route registration is the entry point.** A handler passed to `app.get/post/...`, `router.*`
or mounted with `app.use(path, router)` is reached by every matching request. Middleware registered
before it — authentication, validation — runs first; middleware registered after it does not.

**Output.** `res.send()` of HTML built from input, unescaped template output (`<%- %>`, `{{{ }}}`,
`!{}`) are XSS. `res.redirect(input)` is an open redirect. `res.sendFile(path)` with input is path
traversal unless `{ root }` confines it.
