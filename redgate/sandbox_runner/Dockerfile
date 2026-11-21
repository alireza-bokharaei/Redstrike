# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26
ARG NODE_VERSION=22
FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src
COPY sandbox_runner/go.mod ./
COPY sandbox_runner/*.go ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sandbox-runner . \
    && rm -rf /usr/local/go/test /usr/local/go/doc

# Native runner needs only CA roots; HTTP evidence does not invoke a shell.
FROM debian:bookworm-slim AS evidence
ARG REDGATE_VERSION=2.3.0
LABEL org.opencontainers.image.title="Redstrike Sandbox Runner" \
      org.opencontainers.image.version="${REDGATE_VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 sandbox \
    && useradd -u 10001 -g sandbox -d /tmp -s /usr/sbin/nologin sandbox \
    && mkdir -p /tmp/sandbox && chown -R sandbox:sandbox /tmp/sandbox
COPY --from=builder /out/sandbox-runner /usr/local/bin/sandbox-runner
COPY --from=builder /usr/local/go/LICENSE /usr/share/doc/golang/LICENSE
COPY LICENSE /usr/share/doc/redgate/LICENSE
ENV REDGATE_SANDBOX_ADDR=0.0.0.0:8002 REDGATE_SANDBOX_ROOT=/tmp/sandbox \
    REDGATE_SANDBOX_EVIDENCE_ONLY=true
USER 10001:10001
EXPOSE 8002
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/sandbox-runner", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sandbox-runner"]

# Lightweight read-only workspace flavor: Python/Bash adapters + native evidence,
# without Go compiler/Node. Other languages are refused, never silently skipped.
FROM evidence AS lite
ENV REDGATE_SANDBOX_EVIDENCE_ONLY=false
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 bash curl util-linux \
    && rm -rf /var/lib/apt/lists/*
USER 10001:10001

FROM node:${NODE_VERSION}-bookworm-slim AS js-runtime

# Default: preserve support for Python/Bash/Go/JavaScript sandbox adapters.
FROM lite AS full
USER root
COPY --from=builder /usr/local/go /usr/local/go
COPY --from=js-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=js-runtime /usr/local/LICENSE /usr/share/doc/nodejs/LICENSE
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && node --version && /usr/local/go/bin/go version
ENV PATH="/usr/local/go/bin:${PATH}" GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
# Do not ship an unused precompiled standard-library cache in the image.
# First-use compilation can take longer; validation/runner timeouts fail closed.
USER 10001:10001
