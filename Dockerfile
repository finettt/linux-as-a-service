FROM python:3.11-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml pyproject.toml
COPY uv.lock uv.lock
RUN uv sync --locked
COPY src/ src/
COPY wsgi.py wsgi.py
COPY config.yaml config.yaml


CMD ["uv", "run", "gunicorn", "--workers", "1", "--bind","0.0.0.0:8000", "wsgi:app"]