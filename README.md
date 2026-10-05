# SWE Auth

A security-focused authentication service built with Python (FastAPI), PostgreSQL, Redis, and Docker.

> Status: **Phase 1 (core auth) complete.** Next: Phase 2 hardening.

## Quick start (Windows PowerShell)

```powershell
# 1. Create your secrets file
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # run twice; paste into POSTGRES_PASSWORD and REDIS_PASSWORD

# 2. Start everything
docker compose up --build

# 3. Try it (new terminal)
curl.exe http://127.0.0.1:8000/health
# Or open the interactive docs (development only): http://127.0.0.1:8000/docs

# 4. Run the full test suite and linter inside the container
docker compose exec app pytest
docker compose exec app ruff check .
```

If you started the stack before `db/init/002_test_database.sql` existed, the test database
won't exist yet. Reset once with `docker compose down -v` (this deletes local data), then `up` again.

To also run the session tests against the real Redis container:
`docker compose exec -e TEST_REDIS_URL=redis://:<REDIS_PASSWORD>@redis:6379/15 app pytest tests/test_sessions.py`

## API

| Endpoint | Body | Success | Notes |
|---|---|---|---|
| `POST /auth/register` | `{"email", "password"}` | 201 `{id, email}` | Password: 15-256 characters. Does not log in. |
| `POST /auth/login` | `{"email", "password"}` | 200 `{id, email}` + `__Host-session` cookie | Same 401 for unknown email and wrong password |
| `POST /auth/logout` | none | 204 | Revokes the session server-side |
| `GET /auth/me` | none | 200 `{id, email}` | 401 without a valid session |
| `GET /health` | none | 200 | Liveness |
| `GET /ready` | none | 200 / 503 | Checks Postgres and Redis |

## Project layout

```
app/
  main.py                 App factory, security headers, error handlers, /health, /ready
  config.py               Settings from env vars (fail closed, secrets masked)
  db.py                   Connection pool + parameterized-query and short-borrow rules
  cache.py                Redis client
  dependencies.py         Current-user dependency
  routes/auth.py          register / login / logout / me
  repositories/users.py   All SQL for the users table
  security/
    passwords.py          Argon2id, NIST policy, hashing concurrency cap, timing equalization
    sessions.py           Server-side sessions in Redis
    cookies.py            __Host- session cookie
db/init/                  Schema + test database
tests/                    Security-behavior tests (169), incl. a real-server load test
```

## Phase 1 roadmap

| Step | What | Status |
|---|---|---|
| 0 | Scaffold: Docker, config, DB/Redis wiring | ✅ |
| 1 | Argon2id password hashing + policy | ✅ |
| 2 | Server-side sessions in Redis | ✅ |
| 3 | Secure session cookie | ✅ |
| 4 | User repository with parameterized queries | ✅ |
| 5 | Endpoints, concurrency limits, integration tests | ✅ |
| — | Independent security review: 6 findings, all fixed with regression tests | ✅ |

## Security decisions

- **Argon2id** (argon2-cffi, RFC 9106 low-memory profile: 64 MiB, t=3, p=4), above the OWASP minimum. Hashes upgrade automatically at login.
- **Password policy per NIST SP 800-63B-4.** 15-character minimum, no composition rules, NFC normalization, no truncation, 256-character cap.
- **No login enumeration.** Unknown email and wrong password return an identical status, body, and headers, and do the same Argon2 work. A dummy hash covers unknown emails, and a top-up covers cheap legacy hashes and corrupt hashes.
- **Server-side sessions** in Redis:
  - Tokens are 256-bit CSPRNG values. Redis stores only their SHA-256.
  - Timeouts: 30-minute idle and 8-hour absolute (OWASP ranges).
  - Logout and "sign out everywhere" take effect instantly.
  - Race-safe: `SET XX` on refresh, `GETDEL` on logout, WATCH transactions for rotation and sign-out-everywhere.
- **Login destroys any incoming session** and creates a fresh one (session fixation and swapping defense).
- **Cookie:** `__Host-session`; HttpOnly; Secure; SameSite=Lax; Path=/; no Domain. Production refuses insecure cookies.
- **SQL injection:** literal SQL with parameters only, enforced by ruff S608 and an AST test. DB guardrails: citext UNIQUE email, UUID keys, and a CHECK that only accepts Argon2id hashes.
- **Availability:**
  - At most 4 concurrent Argon2 hashes, then 503 + Retry-After.
  - DB connections are borrowed briefly, inside handlers, never during hashing. The pool times out after 5 s with a 503.
  - `/health` never needs a worker thread.
- **No leaks in errors.** 422s never echo input. Unexpected 500s are generic and still carry security headers.
- **Headers on every response:** `Cache-Control: no-store`, `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`.
- **Fail closed and least exposure.** Required settings (including `ENVIRONMENT`) have no defaults. Postgres and Redis aren't published to the host. The app binds to 127.0.0.1 and runs as non-root. API docs are off in production.

## Known gaps (tracked)

| Gap | Planned fix | Phase |
|---|---|---|
| No per-IP/per-account rate limiting | Redis sliding-window limits, progressive delays | 2 |
| Registration 409 reveals existing emails | Email verification flow | 2 |
| No CSRF tokens (relies on SameSite=Lax + JSON-only) | CSRF tokens | 2 |
| No breached-password check | HIBP k-anonymity check | 2 |
| No email verification / password reset | Hashed single-use tokens; sign out everywhere on reset | 2 |
| No cap on sessions per user | Cap and evict the oldest | 2 |
| Single factor only | TOTP + recovery codes, step-up re-auth | 3 |
| No audit logging | Structured security events | 4 |
| App uses the Postgres superuser role | Least-privilege role | 4 |
| `docker-entrypoint-initdb.d` instead of migrations | Versioned migrations | 4 |
| Transitive dependencies not hash-locked | `pip-compile --generate-hashes` | 4 |
| No TLS / reverse proxy / CSP / body size limits | Deployment hardening | 4 |
| Pepper not decided | Threat model decision | 4 |
