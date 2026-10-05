# SWE Auth

[![CI](https://github.com/GHoelle/swe-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/GHoelle/swe-auth/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An authentication service in Python, built to the specifications it should be built to: Argon2id
password hashing per RFC 9106, a password policy per NIST SP 800-63B-4, server-side sessions with
instant revocation, and 169 tests that assert security *behavior* rather than coverage.

The interesting parts are the ones that are easy to get wrong:

- **Login responses are indistinguishable** whether the email is unknown or the password is wrong —
  same status, same body, same headers, same Argon2 work. Verified in the transcript below.
- **Sessions live server-side in Redis**, keyed by SHA-256 of the token, so a database dump contains
  no usable session tokens and logout takes effect immediately rather than at token expiry.
- **Password hashing is concurrency-bounded.** Each Argon2id hash holds 64 MiB for ~100 ms, so an
  unbounded login endpoint is a memory-exhaustion DoS. At most 4 run at once; the rest get 503.
- **A found-and-fixed concurrency bug.** A security review caught a thread-pool/connection-pool
  deadlock that froze the whole service, `/health` included, under ~50 concurrent logins. See
  [Deadlock, measured](#deadlock-measured).

> **Status:** Phase 1 (core auth) complete, 169 tests passing in CI. Phase 2 hardening — rate
> limiting, CSRF, email verification, password reset, breached-password checks — is in progress.
> Known gaps are tracked [below](#known-gaps-tracked) rather than left for a reader to find.

---

## It actually runs

Real output from the service, not an illustration. An account is registered, then the two failure
modes a login can have are compared:

```console
$ curl -X POST localhost:8000/auth/register -H 'Content-Type: application/json' \
      -d '{"email":"alice@example.com","password":"correct-horse-battery-staple"}'
HTTP 201
{"id":"e977f481-22d6-4344-9588-4fd58d3adda8","email":"alice@example.com"}

$ # wrong password for an account that exists
$ curl -i -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
      -d '{"email":"alice@example.com","password":"wrong-password-here-xx"}'
HTTP/1.1 401 Unauthorized
content-length: 39
content-type: application/json
cache-control: no-store
x-content-type-options: nosniff
referrer-policy: no-referrer
x-frame-options: DENY

{"detail":"Invalid email or password."}

$ # an email with no account at all
$ curl -i -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
      -d '{"email":"nobody@example.com","password":"wrong-password-here-xx"}'
HTTP/1.1 401 Unauthorized
content-length: 39
content-type: application/json
cache-control: no-store
x-content-type-options: nosniff
referrer-policy: no-referrer
x-frame-options: DENY

{"detail":"Invalid email or password."}
```

Diffing the two responses (excluding `Date`) produces no output — they are byte-identical. Timing
matches too, because an unknown email still performs a full Argon2 verification against a dummy
hash, and a stored hash cheaper than the current parameters gets topped up to the current cost:

```console
wrong-password  0.142788s     unknown-email   0.152150s
wrong-password  0.125497s     unknown-email   0.141359s
wrong-password  0.143427s     unknown-email   0.139418s
wrong-password  0.147134s     unknown-email   0.142195s
wrong-password  0.131362s     unknown-email   0.135553s
```

An attacker can learn nothing about who has an account from either the content or the clock.
Session revocation is server-side, so it is immediate:

```console
$ curl -i -X POST localhost:8000/auth/login -d '{"email":"alice@example.com","password":"correct-horse-battery-staple"}'
HTTP/1.1 200 OK
set-cookie: session=OeZSXGbZFX87O2Ets...(truncated); HttpOnly; Path=/; SameSite=lax

$ curl -b jar.txt localhost:8000/auth/me
{"id":"e977f481-22d6-4344-9588-4fd58d3adda8","email":"alice@example.com"}      HTTP 200

$ curl -b jar.txt -X POST localhost:8000/auth/logout
HTTP 204

$ curl -b jar.txt localhost:8000/auth/me          # same cookie, immediately after
{"detail":"Not authenticated."}                                                HTTP 401
```

This transcript was captured over plain HTTP with `SESSION_COOKIE_SECURE=false`, which is why the
cookie is named `session`. The real cookie is `__Host-session` with `Secure`; the `__Host-` prefix
is only valid alongside `Secure`, so the name adapts rather than silently shipping a cookie
browsers would reject. Production refuses to start with insecure cookies at all.

## Quick start

Requires Docker. Two commands:

```bash
./scripts/bootstrap.sh          # writes .env with freshly generated secrets
docker compose up --build
```

<details>
<summary>Windows PowerShell</summary>

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1
docker compose up --build
```

Windows blocks unsigned `.ps1` files by default, so calling `.\scripts\bootstrap.ps1`
directly fails with "running scripts is disabled on this system." The form above relaxes
the policy for that one invocation only — it does not change the machine's policy, which
is what `Set-ExecutionPolicy` would do. Read the script first; it is 40 lines.
</details>

Then:

```bash
curl localhost:8000/health                       # liveness
curl localhost:8000/ready                        # checks Postgres and Redis
#    http://localhost:8000/docs                  interactive API docs (development only)

docker compose exec app pytest                   # all 169 tests
docker compose exec app ruff check .
```

There are no default credentials to forget to change: `ENVIRONMENT`, `DATABASE_URL` and
`REDIS_URL` are required with no fallbacks, and Compose refuses to start without them. That is
why setup needs a generator script instead of being zero-config.

If you started the stack before `db/init/002_test_database.sql` existed, reset once with
`docker compose down -v` (this deletes local data), then `up` again.

## API

| Endpoint | Body | Success | Notes |
|---|---|---|---|
| `POST /auth/register` | `{"email", "password"}` | 201 `{id, email}` | Password 15–256 characters. Does not log in. |
| `POST /auth/login` | `{"email", "password"}` | 200 `{id, email}` + session cookie | Identical 401 for unknown email and wrong password |
| `POST /auth/logout` | none | 204 | Revokes the session server-side |
| `GET /auth/me` | none | 200 `{id, email}` | 401 without a valid session |
| `GET /health` | none | 200 | Liveness; touches no dependency |
| `GET /ready` | none | 200 / 503 | Checks Postgres and Redis |

## Attack to test

Every claim above corresponds to a test. A reviewer can verify any row in one `pytest -k` run.

| Attack or failure mode | Test |
|---|---|
| Account enumeration via login | `test_wrong_password_and_unknown_email_are_indistinguishable` (`test_auth_api.py`) |
| Enumeration via response timing | `test_unknown_email_still_does_a_full_argon2_verification` (`test_auth_api.py`) |
| Session fixation / session swapping | `test_login_destroys_planted_session_and_never_inherits_it` (`test_auth_api.py`) |
| Revocation race on sign-out-everywhere | `test_sign_out_everywhere_during_rotation_cannot_leave_a_live_session` (`test_sessions.py`) |
| In-flight request resurrecting a dead session | `test_in_flight_request_cannot_resurrect_a_logged_out_session` (`test_sessions.py`) |
| Session tokens readable in a Redis dump | `test_raw_token_is_never_stored_in_redis`, `test_redis_key_is_sha256_of_token` (`test_sessions.py`) |
| Forged or tampered session cookie | `test_me_rejects_forged_cookies` (`test_auth_api.py`) |
| SQL injection | `test_every_execute_call_uses_a_constant_sql_string`, `test_drop_table_payload_is_just_data` (`test_users_repository.py`) |
| Plaintext password reaching the database | `test_database_rejects_plaintext_password` (`test_users_repository.py`) |
| Cookie theft via XSS | `test_cookie_is_httponly_so_javascript_cannot_read_it` (`test_cookies.py`) |
| Cross-site POST (CSRF, partial) | `test_cookie_is_samesite_lax_to_block_cross_site_posts` (`test_cookies.py`), `test_login_only_accepts_json_content_type` (`test_auth_api.py`) |
| Mass assignment on register | `test_register_rejects_unexpected_fields_mass_assignment` (`test_auth_api.py`) |
| Password echoed in a validation error | `test_validation_errors_do_not_echo_the_password` (`test_auth_api.py`) |
| Memory exhaustion via login flood | `test_saturated_hashing_returns_503_not_a_crash` (`test_auth_api.py`) |
| Health check starved by a login flood | `test_liveness_answers_even_when_every_worker_thread_is_busy` (`test_concurrency.py`) |
| Connection-pool exhaustion | `test_database_pool_exhaustion_returns_fast_503` (`test_auth_api.py`) |
| Unauthenticated traffic reaching the database | `test_unauthenticated_flood_never_touches_the_database` (`test_concurrency.py`) |
| Deserialization attack on session data | `test_session_data_is_json_not_pickle` (`test_sessions.py`) |
| Redis outage failing open | `test_redis_outage_raises_instead_of_authenticating` (`test_sessions.py`) |
| Session outliving its account | `test_session_for_deleted_account_is_rejected_and_destroyed` (`test_auth_api.py`) |
| Silent password truncation | `test_no_truncation_long_passwords_differing_only_at_the_end` (`test_passwords.py`) |
| Insecure cookies in production | `test_production_refuses_insecure_cookies` (`test_cookies.py`) |
| Secrets in logs | `test_settings_repr_does_not_leak_secrets` (`test_app.py`) |

## Deadlock, measured

An independent security review of Phase 1 produced six findings. The most serious was not a
cryptographic mistake but an availability one, and it is the part of this project worth reading.

Database connections were handed to request handlers through a FastAPI `yield` dependency, so a
connection was held for the entire request — including the ~100 ms of Argon2 hashing. Sync handlers
run in a bounded thread pool. Under load, every worker thread ended up holding a connection and
waiting on a hash while new requests queued for threads that would never free up.

Under the reviewer's scenario of roughly 50 concurrent logins the service stopped answering for
30 seconds or more, and `/health` timed out at 45 seconds alongside everything else — so an external
monitor would have reported the service as down, not slow.

The fix was structural rather than a bigger pool: connections are borrowed briefly *inside* handlers
with `with pool.connection()` and never held across hashing, Redis is checked before Postgres so
unauthenticated traffic never reaches the database, the pool times out at 5 s and returns 503, and
`/health` is `async` so it needs no worker thread. After the fix, the same load produced correct
status codes throughout and `/health` answered in 0.5–2.2 s.

Both behaviors are locked in by `tests/test_concurrency.py`, which parks every worker thread
deterministically instead of depending on timing thresholds — an earlier version of that test was
flaky under CPU contention.

## Security decisions

- **Argon2id** (argon2-cffi, RFC 9106 low-memory profile: 64 MiB, t=3, p=4), above the OWASP
  minimum. Hashes upgrade automatically on successful login when parameters change.
- **Password policy per NIST SP 800-63B-4.** 15-character minimum, no composition rules, NFC
  normalization, length counted in code points, no truncation, 256-character cap.
- **No login enumeration.** Identical status, body, headers and work for unknown email and wrong
  password, including a top-up when the stored hash is cheaper than current parameters or corrupt.
- **Server-side sessions** in Redis: 256-bit CSPRNG tokens, only their SHA-256 stored, 30-minute
  idle and 8-hour absolute timeouts (OWASP ranges), `SET XX` on refresh, `GETDEL` on logout, and
  WATCH/MULTI transactions for rotation and sign-out-everywhere.
- **Login destroys any incoming session** and creates a fresh one. It never rotates the attacker's
  session ID, which would inherit their `user_id` — session fixation and login CSRF.
- **Cookie:** `__Host-session`, HttpOnly, Secure, SameSite=Lax, Path=/, no Domain, no Max-Age, so
  the server alone decides lifetime. SameSite=Strict is stronger; Lax was chosen for email-link UX
  and is accepted by OWASP.
- **SQL injection:** parameterized queries only, enforced by ruff S608 *and* an AST test that
  rejects any non-literal SQL string. Database-level guardrails: `citext` UNIQUE email, UUID keys,
  and a CHECK constraint that only accepts Argon2id hashes.
- **Availability as a security property:** bounded hash concurrency, short connection borrows, fast
  503s with `Retry-After` instead of unbounded queueing, dependency-free liveness.
- **No leaks in errors.** 422 responses never echo input — FastAPI's default handler echoes the
  submitted password, which is why there is a custom one. Unexpected 500s are generic and still
  carry security headers, added by pure ASGI middleware so they survive handler crashes.
- **Fail closed.** `ENVIRONMENT`, `DATABASE_URL` and `REDIS_URL` are required with no defaults. A
  missing `ENVIRONMENT` used to mean development, with docs exposed and insecure cookies permitted.
- **Least exposure.** Postgres and Redis are not published to the host, the app binds to 127.0.0.1,
  the container runs as non-root, and API docs are disabled in production.

## Project layout

```
app/
  main.py                 App factory, security headers, error handlers, /health, /ready
  config.py               Settings from env vars (fail closed, secrets masked)
  db.py                   Connection pool, parameterized-query and short-borrow rules
  cache.py                Redis client
  dependencies.py         Current-user dependency
  routes/auth.py          register / login / logout / me
  repositories/users.py   All SQL for the users table
  security/
    passwords.py          Argon2id, NIST policy, concurrency cap, timing equalization
    sessions.py           Server-side sessions in Redis
    cookies.py            __Host- session cookie
db/init/                  Schema + disposable test database
tests/                    169 security-behavior tests
.github/workflows/ci.yml  Tests on 3.11 and 3.12 against real Postgres and Redis, plus lint
```

CI runs the suite against real service containers, not mocks, and fails the build if any test is
*skipped* — a green check on a partial run would be worse than a red one.

## Known gaps (tracked)

Phase 1 covers core authentication only. These are known and scheduled, not oversights:

| Gap | Planned fix | Phase |
|---|---|---|
| No per-IP/per-account rate limiting | Redis sliding window, progressive delay, no hard lockout (lockout is a DoS on the victim) | 2 |
| Registration 409 reveals existing emails | Email verification; identical response either way | 2 |
| No CSRF tokens (relies on SameSite=Lax + JSON-only) | Synchronizer tokens in the session, plus an Origin check | 2 |
| No breached-password check | HIBP k-anonymity range API, failing open by design | 2 |
| No email verification or password reset | Hashed single-use tokens, sign-out-everywhere on reset | 2 |
| No cap on sessions per user | Cap and evict oldest | 2 |
| Single factor only | TOTP + recovery codes, step-up re-auth | 3 |
| No audit logging | Structured security events | 4 |
| App uses the Postgres superuser role | Least-privilege role | 4 |
| `docker-entrypoint-initdb.d` instead of migrations | Versioned migrations | 4 |
| Dependencies pinned but not hash-locked; CI actions pinned by tag | `pip-compile --generate-hashes`; actions pinned by SHA | 4 |
| No TLS, reverse proxy, CSP or body size limits | Deployment hardening | 4 |
| Pepper not decided | Threat model decision | 4 |

Not deployed publicly: an auth endpoint without rate limiting should not be exposed to the
internet, so a live demo waits for Phase 2.

## License

MIT — see [LICENSE](LICENSE).
