# daas-auth

**OAuth2 authentication and authorization for DESIGN DaaS, in Python (FastAPI). A drop-in replacement for the PHP auth backend.**

daas-auth is an HTTP service on `127.0.0.1:5003`. It keeps the paths, status codes and JSON shapes of the PHP backend it replaces, so the orchestrator (`design-daas`) and the frontend (`design-daas-application-frontend`) work with it unchanged.

## Features

- **OAuth2 password and refresh grants** (RFC 6749) with opaque bearer tokens. Only their SHA-256 is stored.
- **Refresh rotation with reuse detection.** Reusing a retired refresh token revokes the whole login.
- **Short lifetimes.** Access and refresh tokens last 2 h; a login ends after at most 8 h.
- **Argon2id password hashing.** PHP's bcrypt hashes still verify and are upgraded on the next login.
- **Password policy.** 15–128 characters, and an optional Have I Been Pwned check (fails open).
- **Login throttling.** 429 after 30 failed logins per address or 100 per account in 15 min.
- **Default deny.** Every route needs a bearer token unless it is explicitly public.
- **Scopes** `user` and `admin`; a missing scope gets `403 insufficient_scope`.
- **Audit trail** in `activity_log`, and a nightly token purge command.

## Prerequisites

| Requirement | Why |
|---|---|
| Python **3.13+** | `requires-python` and the lock file |
| [uv](https://docs.astral.sh/uv/) | Installs the locked dependencies |
| Docker with Compose v2 | Runs MariaDB 10.11 (`compose.yaml`) and the tests' database |
| GNU make | `make check`, `make fmt` |

To run the whole platform, you also need the two companion repositories, cloned next to this one:

- [`design-daas`](https://github.com/Van-Hien/design-daas): the orchestrator (Quart). It logs in as the admin and validates user tokens against this service.
- [`design-daas-application-frontend`](https://github.com/Van-Hien/design-daas-application-frontend): the React UI. Its origin must be listed in `DAAS_AUTH_CORS_ORIGINS`.

## Installation

> These steps have not yet been run on an empty host. 
> In particular, `.env.example` selects SQLite, so `.env` and `.env.migrate` need the MariaDB URLs and passwords before `alembic` and `seed` (see the next section).

```bash
git clone https://github.com/Van-Hien/daas-auth-python.git
cd daas-auth-python
uv sync                                   # install the locked dependencies into .venv/

cp .env.example .env                      # service settings
cp .env.db.example .env.db                # MariaDB passwords; fill in with: openssl rand -hex 24
cp .env.migrate.example .env.migrate      # schema changes only

docker compose up -d --wait mariadb       # MariaDB on 127.0.0.1:3318
uv run alembic upgrade head               # create the schema
uv run daas-auth seed --email admin@example.com --name "Administrator"   # first admin + test-client; asks for the password
uv run uvicorn daas_auth.api.app:create_app --factory --host 127.0.0.1 --port 5003 \
  --proxy-headers --forwarded-allow-ips 127.0.0.1

curl -s http://127.0.0.1:5003/health      # expect 200
```

`seed` runs only on an empty database. The password is prompted for, never passed as an option, so it stays out of the shell history.

In production, run uvicorn under systemd behind nginx with TLS, and run `uv run daas-auth purge-tokens` nightly.

### A `.env` for MariaDB

`.env.example` starts the service on SQLite. For MariaDB, `.env` looks like this:


```dotenv
# Required. The service's own account (daas_app). Password from .env.db.
DAAS_AUTH_DATABASE_URL=mysql+pymysql://daas_app:CHANGE_ME@127.0.0.1:3318/daas_auth
# Development alternative (SQLite, not for production):
# DAAS_AUTH_DATABASE_URL=sqlite:///./var/dev.sqlite3

# Optional. Browser origins allowed to call the API (JSON list).
# DAAS_AUTH_CORS_ORIGINS=["https://front1.cluster.local:8443"]

# Optional. Set to false on a host without internet access.
DAAS_AUTH_CHECK_PWNED_PASSWORDS=true
```

Settings are read once at startup, so restart the service after a change. A missing required value stops the start.

## Usage

Get a token as the seeded public client `test-client` (no secret needed). `--data-urlencode` keeps special characters such as `+` intact:

```bash
curl -s http://127.0.0.1:5003/oauth2/user/token \
  -d grant_type=password -d client_id=test-client -d scope=user \
  --data-urlencode "username=anna@example.com" \
  --data-urlencode "password=a long passphrase here"

curl -s http://127.0.0.1:5003/oauth2/user/session -H "Authorization: Bearer <access_token>"   # user_id, name, scopes

curl -s -X POST http://127.0.0.1:5003/oauth2/user/revoke \
  -d client_id=test-client --data-urlencode "token=<refresh_token>"                           # logout
```

Refresh with `grant_type=refresh_token` and `refresh_token=...`. Each refresh returns a new pair; the old refresh token stops working.

To protect an endpoint in another service, call `GET /oauth2/user/session` with the caller's bearer and use the answer. Do not read tokens yourself.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DAAS_AUTH_DATABASE_URL` | yes | — | SQLAlchemy URL of the service (`mysql+pymysql://…` in production, `sqlite:///…` for development) |
| `DAAS_AUTH_CORS_ORIGINS` | no | `["https://front1.cluster.local:8443"]` | Browser origins allowed to call the API |
| `DAAS_AUTH_CHECK_PWNED_PASSWORDS` | no | `true` | Breach check for new passwords; `false` without internet |
| `DAAS_MIGRATE_DATABASE_URL` | for migrations | — | `.env.migrate`; the `daas_migrate` account, used by Alembic only |
| `DAAS_IMPORT_USER`, `_PASSWORD`, `_DATABASE`, `_HOST`, `_PORT` | for `import-php` | host `127.0.0.1`, port `3316` | `.env.import`; PHP's database, read once |

Token lifetimes and login limits are constants in code (`domain/tokens.py`, `domain/throttle.py`), not settings.

Never print or log `Settings`, `.env` or `.env.db`. They hold database passwords.

## Development and testing

```bash
make check     # the gate every commit must pass: mypy, ruff, format, import-linter, pytest, pip-audit
make fmt       # format and apply ruff's safe fixes
```

`make check` starts a throwaway MariaDB on port 3319 (in RAM), runs the six gates, and removes the database. The tests never touch the live database.

Run part of the suite:

```bash
uv run pytest tests/test_refresh.py            # one file
uv run pytest tests/test_token.py -k disabled  # the tests whose name contains "disabled"
```

Tests marked `mariadb` are skipped unless the test database is running:

```bash
docker compose --profile test up -d --wait mariadb-test
uv run pytest
docker compose --profile test rm -fsv mariadb-test
```

Layering is enforced by `make check`: `domain/` must not import `api/`, and route modules must not import each other. SQL built from strings is rejected by the linter, so use the ORM only.

**Warning:** `docker compose down -v` deletes the live database (users, tokens, history). Plain `down` keeps it.

## License

MIT, see [LICENSE](LICENSE).
