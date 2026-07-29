# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- version list -->

## v1.1.8 (2026-07-14)

### Bug Fixes

- **ci**: Keep Test workflow push triggers unfiltered
  ([#229](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/229),
  [`2a88198`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/2a88198586079c45761afc69995a84586c76899d))

### Code Style

- **footer**: Improve site footer layout and typography
  ([#226](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/226),
  [`85b5fe9`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/85b5fe92b266ae7459631c336275c82eeba3a610))

### Documentation

- Document stripe branch and add propagate/CI support
  ([#229](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/229),
  [`2a88198`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/2a88198586079c45761afc69995a84586c76899d))


## v1.1.7 (2026-07-06)

### Bug Fixes

- Address PR review nits for frontend test suite
  ([`4659d3b`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/4659d3b427b6f865ea87046d080b97e3a63042dd))


## v1.1.6 (2026-07-02)

### Bug Fixes

- Add Postgres-backed rate limiter for multi-worker deployments
  ([#222](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/222),
  [`d46bddf`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/d46bddf8f6dbf33e7b573d1175ab0a1d16ae52ad))

- Remove duplicate get_client_ip definition
  ([#222](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/222),
  [`d46bddf`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/d46bddf8f6dbf33e7b573d1175ab0a1d16ae52ad))


## v1.1.5 (2026-07-02)

### Bug Fixes

- Enforce avatar upload size limit before buffering body
  ([#220](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/220),
  [`73cdebe`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/73cdebe0e94a8caeb7b8d229aee9e60aa0571fc5))

- Run async upload-limit tests outside pytest event loop
  ([#220](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/220),
  [`73cdebe`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/73cdebe0e94a8caeb7b8d229aee9e60aa0571fc5))


## v1.1.4 (2026-07-02)

### Bug Fixes

- Honor X-Forwarded-For for rate limits behind trusted proxies
  ([#221](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/221),
  [`aeac6e5`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/aeac6e511cec581fc0598bef807b18224c19e6f6))


## v1.1.3 (2026-07-02)

### Bug Fixes

- Add CSRF tokens and convert account recovery to POST
  ([#223](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/223),
  [`b33ab5c`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/b33ab5cd4dc1fee8e73357487e0ec5cac0b34856))


## v1.1.2 (2026-07-02)

### Bug Fixes

- Revoke sessions on password reset
  ([#215](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/215),
  [`523fc48`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/523fc487daacf6a52e2bfab106f58831e2b3f846))


## v1.1.1 (2026-07-01)

### Bug Fixes

- Broken screenshot link
  ([#213](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/213),
  [`28e1222`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/28e12220b476476be829c97963437fd38e538069))

- Convert screenshot to WebP and update doc links
  ([#213](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/213),
  [`28e1222`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/28e12220b476476be829c97963437fd38e538069))


## v1.1.0 (2026-07-01)

### Documentation

- Migrate documentation from raw Quarto to Great Docs
  ([#211](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/211),
  [`8514c59`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/8514c5977b12754022f18f7e069a4fb3c05fa0f4))

### Features

- New frontend theme!
  ([#212](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/212),
  [`777fe83`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/777fe83b24b47504c0f801c41a12407f31895733))


## v1.0.2 (2026-06-30)

### Bug Fixes

- Align ownership cascades with account deletion
  ([#210](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/210),
  [`7c79c5b`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/7c79c5b16c424ce5103f714daa74bc9746bea5d8))


## v1.0.1 (2026-06-30)

### Bug Fixes

- Address review nits on invitation warning pages
  ([`03e08c9`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/03e08c9fdbf022ece4a82b53121a0734db601108))

- Harden profile-form htmx swap tests against CI timing flakiness
  ([`03e08c9`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/03e08c9fdbf022ece4a82b53121a0734db601108))

### Refactoring

- Drop overflow-x clip in favor of geometry-based regression tests
  ([`350af44`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/350af447d7693d64d6e0ac95d0e15f9fa01e01d3))


## v1.0.0 (2026-06-23)

### Chores

- Release v0.1.30 [skip ci]
  ([`8740166`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/87401665003a8863d28f7c583bc0ac57fdf1f8cb))

### Continuous Integration

- Add semantic-release workflow and conventional commit enforcement
  ([#203](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/pull/203),
  [`e9ab2ad`](https://github.com/Promptly-Technologies-LLC/fastapi-jinja2-postgres-webapp/commit/e9ab2ad60e1a06b20fc3fe1bcdb91fb958b50e6b))
