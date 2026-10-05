# syntax=docker/dockerfile:1

# ---- base: runtime dependencies only ----
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Run as an unprivileged user. If the app is ever compromised, the attacker
# doesn't get root inside the container.
RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY requirements.txt .
RUN pip install -r requirements.txt

# ---- dev: adds test/lint tools, auto-reload ----
FROM base AS dev
COPY requirements-dev.txt pyproject.toml ./
RUN pip install -r requirements-dev.txt
# /app is owned by root (the app user can't modify its own code), so send the linter cache to /tmp.
ENV RUFF_CACHE_DIR=/tmp/.ruff_cache
COPY app ./app
COPY tests ./tests
COPY db ./db
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ---- prod: only application code, no test tooling ----
FROM base AS prod
# Production settings are the default for this image, not something a deploy must remember.
ENV ENVIRONMENT=production
COPY app ./app
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
