---
id: vue
version: "1.0"
name: Vue / Nuxt (frontend)
detect:
  files: ["package.json"]
  contains:
    - '"vue"'
    - '"nuxt"'
where:
  pages and client routes: ["pages/", "src/pages/", "app/pages/", "src/app/pages/", "router/", "src/router/", "app/router.options.*", "*/app/router.options.*"]
  route guards and client auth: ["middleware/", "src/middleware/", "app/middleware/", "src/app/middleware/", "plugins/auth*", "src/plugins/auth*", "store/auth*", "src/store/auth*", "src/store/modules/auth*", "stores/auth*", "src/stores/auth*", "composables/useAuth*", "src/composables/useAuth*", "src/features/auth*", "src/features/login*"]
  calls to the backend: ["api/", "src/api/", "src/*/api/", "services/", "src/services/", "composables/", "src/composables/", "app/composables/", "plugins/axios*", "src/plugins/axios*", "axios.*", "*/axios.*"]
  server routes (run on the backend): ["server/api/", "server/routes/", "server/middleware/", "src/server/"]
  rendering (v-html, bound URLs): ["components/", "src/components/", "app/components/", "layouts/", "src/layouts/", "src/app/layouts/", "src/widgets/", "src/features/", "src/entities/", "src/shared/ui/"]
  client state: ["store/", "src/store/", "stores/", "src/stores/"]
  build and runtime config: ["nuxt.config.*", "src/nuxt.config.*", "vite.config.*", "vue.config.*", "app.config.*", "src/app/app.config.*"]
# `src/app/`, `src/shared/`, `src/features/`, `src/widgets/`, `src/entities/` are Feature-Sliced
# Design, which a Nuxt 3 frontend here uses instead of the flat Nuxt layout.
---
**Rendering.** `{{ value }}` and `v-text` are escaped. XSS lives in `v-html`, direct `innerHTML`,
`:href` / `:src` bound to a value that can be a `javascript:` URL, and `<component :is>` chosen
from user data.

**A client check is not access control.** A route guard in `middleware/` or a `v-if` hides UI; only
the backend enforces access. A missing guard is a finding only when the server trusts the client.

**What ships to the browser is public.** `VITE_*`, `NUXT_PUBLIC_*`, `publicRuntimeConfig` and
anything imported into a component end up in the bundle. A secret there is a real leak; a public
API key or URL there is by design.

**Nuxt server routes** under `server/api/` and `server/routes/` run on the server and read the
request (`getQuery`, `readBody`, `getRouterParams`): judge them as backend code.
