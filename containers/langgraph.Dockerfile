FROM python:3.13-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.8.15 /uv /usr/local/bin/uv

# The workspace (packages/autobot) + the graph config. Source-tree pyprojects
# carry the 0.0.0 sentinel; tag-stamped metadata matters for PyPI wheels, not
# for this runtime container.
COPY pyproject.toml langgraph.json README.md uv.lock ./
COPY packages/ packages/

# langgraph-cli comes from the dev dependency-group; the server image needs
# it at runtime, so install it into the venv explicitly.
RUN uv sync --no-dev --frozen --package autobot && \
    uv pip install --python /app/.venv/bin/python "langgraph-cli[inmem]>=0.2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PATH=/app/.venv/bin:$PATH

EXPOSE 2024

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:2024/ok >/dev/null 2>&1 || exit 1

CMD ["langgraph", "dev", "--host", "0.0.0.0", "--port", "2024", "--no-browser"]
