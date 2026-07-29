# AGENTS.md

## Cursor Cloud specific instructions

This is a single web app: a FastAPI + Jinja2 backend with a PostgreSQL database
(server-rendered HTML + htmx, no JS build step). End-to-end testing requires two
services: **PostgreSQL** and the **Uvicorn** dev server. Resend (email) is
optional; most flows work without it and automated tests mock it.

Standard install/lint/test/run commands live in `README.md` and `pyproject.toml`;
prefer those. The notes below are the non-obvious, environment-specific caveats.

### Starting services

- **Docker is not managed by systemd here.** Start the daemon manually before
  using Postgres: run `sudo dockerd` as a background process (e.g. in a tmux
  session), then wait until `sudo docker info` succeeds. Docker CLI commands
  require `sudo`.
- **Postgres** runs via Docker Compose: `sudo docker compose up -d`. It reads
  `DB_USER`/`DB_PASSWORD`/`DB_NAME`/`DB_PORT` from `.env` (port 5432).
- **Dev server**: `uv run python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload`.
  Tables and default roles/permissions are created automatically on startup via
  the FastAPI lifespan handler, so no manual migration step is needed.

### Environment file

- `.env` is required and git-ignored, so it is not in a fresh checkout. If it is
  missing, recreate it: `cp .env.example .env`, set `SECRET_KEY` to a 32+ byte
  value (`openssl rand -base64 32`), and set `DB_NAME` (e.g.
  `fastapi-jinja2-postgres-webapp`). The pytest suite sets its own env vars in
  `tests/conftest.py` and does not read `SECRET_KEY`/`DB_NAME` from `.env`, but it
  does need a running Postgres.

### Testing

- The pytest suite (`uv run pytest tests/`) needs Postgres running and Playwright
  Chromium installed (`uv run playwright install --with-deps chromium`). A full
  run takes ~3 minutes. Tests use PostgreSQL (no SQLite fallback) and drop/recreate
  a `webapp-test-db` database each run.
- If dropping tables fails due to a schema change, reset the DB with
  `sudo docker compose down -v && sudo docker compose up -d`.
