FROM golang:1.26-alpine AS wolfee-builder

ARG WOLFEE_VERSION=1.7
ARG WOLFEE_REPO=https://github.com/ShinigamiKiko/wolfee-cli.git

RUN apk add --no-cache git make
WORKDIR /build/wolfee
RUN git clone --depth=1 --branch="${WOLFEE_VERSION}" "${WOLFEE_REPO}" . \
    && make build \
    && ./bin/wolfee version

FROM python:3.12-slim-bookworm AS main

ARG CODEQL_BUNDLE_TAG=codeql-bundle-v2.27.1
ARG GO_VERSION=1.26.5
ARG PYLSP_VERSION=1.15.0

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PHPACTOR_PHAR=/opt/phpactor.phar \
    COMPOSER_HOME=/opt/composer \
    COMPOSER_ALLOW_SUPERUSER=1 \
    GOPATH=/root/go \
    GOTOOLCHAIN=local \
    PATH=/usr/local/go/bin:/root/go/bin:/opt/composer/vendor/bin:/usr/local/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git unzip xz-utils gnupg \
        php-cli php-xml php-mbstring php-tokenizer \
        composer \
    && rm -rf /var/lib/apt/lists/*

ARG NODE_MAJOR=22
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version

RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz \
    && go version

ARG GOPLS_VERSION=v0.23.0
RUN go install "golang.org/x/tools/gopls@${GOPLS_VERSION}" && gopls version

RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
    && govulncheck -version

RUN npm install -g typescript@5.9.3 typescript-language-server@5.3.0 \
    && typescript-language-server --version \
    && test -f "$(npm root -g)/typescript/lib/tsserver.js"

RUN npm install -g @cyclonedx/cdxgen \
    && cdxgen --version

RUN npm install -g yarn@1.22.22 \
    && yarn --version

RUN curl -fsSL https://github.com/phpactor/phpactor/releases/latest/download/phpactor.phar \
        -o /opt/phpactor.phar \
    && chmod +x /opt/phpactor.phar \
    && php /opt/phpactor.phar --version

RUN composer global require "psalm/phar:^6" --no-interaction --no-progress \
    && ln -sf /opt/composer/vendor/bin/psalm.phar /usr/local/bin/psalm \
    && psalm --version

# Opengrep (patterns + intra-file taint) — runs before Psalm on PHP code, as an extra
# pass, not instead of it. The rule packs are fetched here, at build time, so a scan
# never needs the network for them (configs/scanners/opengrep.yaml points at them).
ARG OPENGREP_VERSION=v1.27.1
RUN case "$(uname -m)" in aarch64|arm64) arch=aarch64 ;; *) arch=x86 ;; esac \
    && curl -fsSL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_${arch}" \
        -o /usr/local/bin/opengrep \
    && chmod +x /usr/local/bin/opengrep \
    && opengrep --version \
    && mkdir -p /opt/opengrep-rules \
    && for pack in security-audit owasp-top-ten; do \
         curl -fsSL "https://semgrep.dev/c/p/${pack}" -o "/opt/opengrep-rules/${pack}.yaml" || exit 1; \
       done

RUN pip install \
        "python-lsp-server==${PYLSP_VERSION}" \
    && pylsp --help >/dev/null

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

ARG CODEQL_EXTRA_PACKS="trailofbits/go-queries githubsecuritylab/codeql-javascript-queries githubsecuritylab/codeql-go-extensions"
ENV APPSEC_CODEQL_PACKS=/opt/codeql-packs
RUN codeql pack download --dir="${APPSEC_CODEQL_PACKS}" ${CODEQL_EXTRA_PACKS} \
    && codeql resolve qlpacks --additional-packs="${APPSEC_CODEQL_PACKS}" | grep -E "trailofbits|githubsecuritylab"

COPY --from=wolfee-builder /build/wolfee/bin/wolfee /usr/local/bin/wolfee
RUN wolfee version

WORKDIR /app
COPY . /app
RUN pip install -e . \
    && appsec-triage doctor || true   # smoke: prints the toolchain matrix, never fails the build

VOLUME ["/out"]

ENTRYPOINT ["appsec-triage"]
CMD ["doctor"]
