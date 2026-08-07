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

FROM python:3.12-slim-bookworm

# --- versions: bump deliberately, each is checked at build time ---------------
# CodeQL: the *bundle* (CLI + precompiled standard query packs) so analysis works
# offline. Tag must exist under github/codeql-action releases.
ARG CODEQL_BUNDLE_TAG=codeql-bundle-v2.25.6
# gopls sets the floor here, not Go's own release cadence: v0.23.0 requires
# Go >= 1.26, and with GOTOOLCHAIN=local the build fails outright instead of
# quietly pulling a newer toolchain. Bump this when gopls raises its floor.
ARG GO_VERSION=1.26.5
ARG GOVULNCHECK_VERSION=v1.6.0
ARG GITLEAKS_VERSION=8.21.2
ARG SEMGREP_VERSION=1.168.0
ARG BANDIT_VERSION=1.9.4
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
# gopls (Go) and govulncheck symbol reachability — installed into /root/go/bin.
ARG GOPLS_VERSION=v0.23.0
RUN go install "golang.org/x/tools/gopls@${GOPLS_VERSION}" \
    && go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" \
    && gopls version \
    && govulncheck -version

# typescript-language-server (+ the tsserver it wraps) for .ts/.tsx/.js/.jsx.
RUN npm install -g typescript typescript-language-server \
    && typescript-language-server --version

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

# Psalm (PHP taint) — global Composer install; binary lands on PATH via COMPOSER_HOME.
RUN composer global require "vimeo/psalm:^6" --no-interaction --no-progress \
    && psalm --version

# --- scanners -----------------------------------------------------------------
# Python scanners + pylsp share the image's Python. pylsp is a *language server*
# (invoked as the `pylsp` console script, matching configs/lsp.yaml).
RUN pip install \
        "semgrep==${SEMGREP_VERSION}" \
        "bandit==${BANDIT_VERSION}" \
        "python-lsp-server==${PYLSP_VERSION}" \
    && semgrep --version && bandit --version && pylsp --help >/dev/null

# gitleaks (secrets) — static binary.
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tgz \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tgz \
    && gitleaks version

# CodeQL bundle (CLI + standard query packs). Large layer.
RUN curl -fsSL "https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE_TAG}/codeql-bundle-linux64.tar.gz" \
        -o /tmp/codeql.tgz \
    && tar -xzf /tmp/codeql.tgz -C /opt && rm /tmp/codeql.tgz \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && codeql version --format terse

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
