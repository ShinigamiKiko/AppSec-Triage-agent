# AppSecTriage — self-contained analysis image.
#
# Bundles the CLI plus the full toolchain it drives, so a CI job can do:
#     docker run --rm \
#         -v "$CI_PROJECT_DIR:/src:ro" -v "$CI_PROJECT_DIR/appsec-out:/out" \
#         --env-file .env \
#         appsec-triage:latest \
#         run /src -p deepseek -o /out --fail-on confirmed
#
# Exit codes the job can branch on:
#     0  success, gate clean (or no --fail-on)
#     1  --fail-on gate tripped (findings remain) — block the merge
#     2  setup/LSP-mandatory failure (a required language server did not come up)
#
# The image is LARGE by nature: it carries CodeQL (~1 GB with query packs), a Go
# toolchain (gopls needs it at runtime), Node, PHP + Composer, and the Python
# scanners. That is the cost of "full analysis" in one artifact. Every heavy
# component is pinned via ARG below — bump these deliberately.

# --- Wolfee build stage -------------------------------------------------------
# Build from a release tag so the image contains the same scanner version on
# every rebuild. Only the resulting binary is copied into the runtime image.
FROM golang:1.26-alpine AS wolfee-builder

ARG WOLFEE_VERSION=1.7
ARG WOLFEE_REPO=https://github.com/ShinigamiKiko/wolfee-cli.git

RUN apk add --no-cache git make
WORKDIR /build/wolfee
RUN git clone --depth=1 --branch="${WOLFEE_VERSION}" "${WOLFEE_REPO}" . \
    && make build \
    && ./bin/wolfee version

FROM python:3.12-slim-bookworm AS main

# --- versions: bump deliberately, each is checked at build time ---------------
# CodeQL: the *bundle* (CLI + precompiled standard query packs) so analysis works
# offline. Tag must exist under github/codeql-action releases.
ARG CODEQL_BUNDLE_TAG=codeql-bundle-v2.25.6
# gopls sets the floor here, not Go's own release cadence: v0.23.0 requires
# Go >= 1.26, and with GOTOOLCHAIN=local the build fails outright instead of
# quietly pulling a newer toolchain. Bump this when gopls raises its floor.
ARG GO_VERSION=1.26.5
ARG PYLSP_VERSION=1.15.0
# phpactor is pulled as the "latest" phar; pin by swapping the URL below if a
# reproducible build is required.

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # phpactor default fallback path — the image bakes the phar here so no env is
    # strictly required, but PHPACTOR_PHAR is set anyway for clarity/override.
    PHPACTOR_PHAR=/opt/phpactor.phar \
    COMPOSER_HOME=/opt/composer \
    COMPOSER_ALLOW_SUPERUSER=1 \
    GOPATH=/root/go \
    GOTOOLCHAIN=local \
    PATH=/usr/local/go/bin:/root/go/bin:/opt/composer/vendor/bin:/usr/local/bin:$PATH

# --- OS packages: runtimes for the language servers + fetch tools -------------
# php-cli/php-xml/php-mbstring: phpactor + Psalm. nodejs/npm: ts-language-server.
# git/curl/unzip/ca-certificates: fetch + repo access. Debian bookworm ships
# PHP 8.2 — adequate for static analysis (phpactor/Psalm build their own index;
# they do not execute the target). Node comes from NodeSource below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git unzip xz-utils gnupg \
        php-cli php-xml php-mbstring php-tokenizer \
        composer \
    && rm -rf /var/lib/apt/lists/*

# Node from NodeSource, not from Debian: bookworm ships 18, and cdxgen calls
# `path.matchesGlob`, which arrived in Node 20. The apt version fails at import
# with a message about a missing export, which reads like a broken package
# rather than a version floor.
ARG NODE_MAJOR=22
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version

# --- Go toolchain (gopls resolves Go symbols against it at runtime) -----------
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz \
    && go version

# --- language servers ---------------------------------------------------------
# gopls (Go) — installed into /root/go/bin (on PATH).
ARG GOPLS_VERSION=v0.23.0
RUN go install "golang.org/x/tools/gopls@${GOPLS_VERSION}" && gopls version

# govulncheck powers Wolfee's Go call-graph reachability analysis.
RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
    && govulncheck -version

# typescript-language-server (+ the tsserver it wraps) for .ts/.tsx/.js/.jsx.
# Pinned: TypeScript 7 (the Go port) ships no tsserver.js, and the server never answers `initialize`.
RUN npm install -g typescript@5.9.3 typescript-language-server@5.3.0 \
    && typescript-language-server --version \
    && test -f "$(npm root -g)/typescript/lib/tsserver.js"

# cdxgen — the only source of the dependency graph. Without it a scan cannot
# tell a direct dependency from a transitive one, and the upgrade advice it
# prints ("update to X") is advice nobody can follow.
RUN npm install -g @cyclonedx/cdxgen \
    && cdxgen --version

# phpactor (PHP) — a single phar at the default fallback path.
RUN curl -fsSL https://github.com/phpactor/phpactor/releases/latest/download/phpactor.phar \
        -o /opt/phpactor.phar \
    && chmod +x /opt/phpactor.phar \
    && php /opt/phpactor.phar --version

# Psalm (PHP taint) as the official PHAR. Its own dependencies (amphp, Symfony
# Console, …) are prefixed inside the PHAR, so they never collide with the same
# libraries in the scanned project's vendor/ — Psalm loads that autoloader. The plain
# `vimeo/psalm` install died with "Cannot redeclare Amp\delay()" on a project that
# ships an older Psalm and amphp/amp of its own.
RUN composer global require "psalm/phar:^6" --no-interaction --no-progress \
    && ln -sf /opt/composer/vendor/bin/psalm.phar /usr/local/bin/psalm \
    && psalm --version

# --- language-server support ---------------------------------------------------
# pylsp is a *language server* (invoked as the `pylsp` console script, matching
# configs/lsp.yaml).
RUN pip install \
        "python-lsp-server==${PYLSP_VERSION}" \
    && pylsp --help >/dev/null

# CodeQL bundle (CLI + standard query packs). Large layer.
# Only the languages this agent is run on. The bundle carries ten, and the
# eight nobody uses here are 1.2 GB of the image. A language is whatever has
# a `<lang>-queries` pack, so a language a future bundle adds is dropped too
# rather than slipping through a fixed list. The shared libraries and the
# small generic extractors (html, xml, yaml, csv, properties) stay: Go and
# JavaScript analysis read config files through them.
# PHP needs nothing here — CodeQL does not support it; Psalm and phpactor do.
ARG CODEQL_LANGUAGES="go javascript"
RUN curl -fsSL "https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE_TAG}/codeql-bundle-linux64.tar.gz" \
        -o /tmp/codeql.tgz \
    && tar -xzf /tmp/codeql.tgz -C /opt && rm /tmp/codeql.tgz \
    && for pack in /opt/codeql/qlpacks/codeql/*-queries; do \
         lang="$(basename "$pack" -queries)"; \
         case " ${CODEQL_LANGUAGES} " in *" $lang "*) continue ;; esac; \
         rm -rf "/opt/codeql/$lang" /opt/codeql/qlpacks/codeql/"$lang"-*; \
       done \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && codeql version --format terse \
    && for lang in ${CODEQL_LANGUAGES}; do \
         codeql resolve languages | grep -q "^$lang " \
           || { echo "CodeQL lost $lang while being trimmed" >&2; exit 1; }; \
       done

# Wolfee provides SCA inventory and Go reachability traces for the triage run.
COPY --from=wolfee-builder /build/wolfee/bin/wolfee /usr/local/bin/wolfee
RUN wolfee version

# --- the agent itself ---------------------------------------------------------
# Editable install on purpose: config.py derives REPO_ROOT from the package's
# location, and configs/ rules/ prompts/ live alongside the package — a plain
# site-packages install would leave the CLI unable to find them. Keeping the repo
# at /app and installing -e means REPO_ROOT == /app, with all profiles present.
WORKDIR /app
COPY . /app
RUN pip install -e . \
    && appsec-triage doctor || true   # smoke: prints the toolchain matrix, never fails the build

# Verdict on the mounted repo goes here; mount a volume so artifacts survive the job.
VOLUME ["/out"]

# `run` / `triage` / `scan` / `queue` / `doctor` are all reachable as subcommands.
ENTRYPOINT ["appsec-triage"]
CMD ["doctor"]
