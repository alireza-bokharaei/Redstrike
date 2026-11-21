# syntax=docker/dockerfile:1.7
FROM python:3.12-slim-bookworm AS python-deps
COPY requirements.lock /tmp/requirements.lock
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install --require-hashes -r /tmp/requirements.lock

FROM python:3.12-slim-bookworm
ARG REDGATE_VERSION=2.3.0
LABEL org.opencontainers.image.title="Redstrike MCP Tools" \
      org.opencontainers.image.version="${REDGATE_VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends dnsutils nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 mcpuser \
    && useradd -u 10002 -g mcpuser -s /usr/sbin/nologin mcpuser
COPY --from=python-deps /install /usr/local
WORKDIR /app
COPY mcp_server /app/mcp_server
COPY LICENSE /usr/share/doc/redgate/LICENSE
USER 10002:10002
EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=2).close()"]
CMD ["uvicorn", "mcp_server.http_server:app", "--host", "0.0.0.0", "--port", "8001"]
