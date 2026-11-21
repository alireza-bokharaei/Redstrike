# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26
ARG NODE_VERSION=22

FROM golang:${GO_VERSION}-bookworm AS go-toolchain
# Keep compiler + standard library, not the upstream test/documentation tree.
RUN rm -rf /usr/local/go/test /usr/local/go/doc

FROM node:${NODE_VERSION}-bookworm-slim AS js-toolchain
WORKDIR /opt/redgate-tools
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM python:3.12-slim-bookworm AS python-deps
COPY requirements.lock /tmp/requirements.lock
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install --require-hashes -r /tmp/requirements.lock

# Small read-only control plane: no Go compiler, Node runtime or frontend server.
# Python/Bash validation, missions, MCP checks, graphs, Go HTTP evidence and
# retests work here. Go/JS script validation fails closed when tools are absent.
FROM python:3.12-slim-bookworm AS lite
ARG REDGATE_VERSION=2.3.0
LABEL org.opencontainers.image.title="Redstrike Gateway" \
      org.opencontainers.image.version="${REDGATE_VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    REDGATE_SKILLS_DIR=/app/skills REDGATE_DEMO_MODE=false \
    REDGATE_ARTIFACT_DIR=/app/data/artifacts
RUN apt-get update && apt-get install -y --no-install-recommends bash shellcheck ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10000 redgate \
    && useradd -u 10000 -g redgate -d /tmp -s /usr/sbin/nologin redgate \
    && mkdir -p /app/data/artifacts /tmp/sandbox && chown -R redgate:redgate /app/data /tmp/sandbox
COPY --from=python-deps /install /usr/local
WORKDIR /app
COPY gateway /app/gateway
COPY mcp_server/__init__.py mcp_server/tools.py /app/mcp_server/
COPY config /app/config
COPY skills /app/skills
COPY VERSION /app/VERSION
COPY LICENSE /usr/share/doc/redgate/LICENSE
USER 10000:10000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).close()"]
# Mission workers live in this process; do not use multiple uvicorn workers.
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

# Default compatible flavor: all four script-language validators. npm itself and
# the entire global Node installation are intentionally NOT copied into runtime.
FROM lite AS full
USER root
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=js-toolchain /usr/local/bin/node /usr/local/bin/node
COPY --from=js-toolchain /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
COPY --from=js-toolchain /opt/redgate-tools/node_modules /opt/redgate-tools/node_modules
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /opt/redgate-tools/node_modules/eslint/bin/eslint.js /usr/local/bin/eslint \
    && node --version && eslint --version && /usr/local/go/bin/go version
ENV PATH="/usr/local/go/bin:${PATH}"
USER 10000:10000
