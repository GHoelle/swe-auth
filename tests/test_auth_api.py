"""End-to-end security tests for the auth endpoints.

Uses real PostgreSQL (TEST_DATABASE_URL) and in-memory Redis, through real HTTP requests.
The client talks to https://testserver, so Secure cookies behave as in a browser.
"""

import threading

import fakeredis
import pytest
import redis
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout

from app.config import Settings
from app.main import create_app
from app.repositories import users
from app.security import passwords
from app.security.sessions import SessionStore
from tests.helpers import FakeClock, SpyHasher

IDLE = 30 * 60
ABSOLUTE = 12 * 60 * 60
COOKIE = "__Host-session"
ALICE = {"email": "alice@example.com", "password": "correct horse battery staple"}
BOB = {"email": "bob@example.com", "password": "bob's very long passphrase"}


# --- Fixtures ------------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pg_pool(_schema, test_database_url):
    pool = ConnectionPool(
        test_database_url, min_size=1, max_size=4, kwargs={"row_factory": dict_row}, open=False
    )
    pool.open(wait=True, timeout=10)
    yield pool
    pool.close()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def app(pg_pool, clock):
    with pg_pool.connection() as conn:
        conn.execute("TRUNCATE users")
    settings = Settings(
        environment="test",
        database_url="postgresql://unused",
        redis_url="redis://unused",
        session_idle_timeout_seconds=IDLE,
        session_absolute_timeout_seconds=ABSOLUTE,
    )
    application = create_app(settings)
    # Inject test resources instead of running the startup lifespan.
    application.state.db_pool = pg_pool
    application.state.redis = fakeredis.FakeRedis(decode_responses=True)
    application.state.sessions = SessionStore(
        application.state.redis,
        idle_timeout_seconds=IDLE,
        absolute_timeout_seconds=ABSOLUTE,
        clock=clock,
    )
    yield application
    passwords.configure_hashing_limits(4, 1.0)  # undo any test changes


def new_client(app) -> TestClient:
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def client(app):
    return new_client(app)


def plant_cookie(client: TestClient, token: str) -> None:
    """Put a session cookie in a client exactly where a browser would store it."""
    client.cookies.set(COOKIE, token, domain="testserver.local", path="/")


def register(client, creds=ALICE):
    return client.post("/auth/register", json=creds)


def login(client, creds=ALICE):
    return client.post("/auth/login", json=creds)


def stored_hash(pg_pool, email):
    with pg_pool.connection() as conn:
        return conn.execute(
            "SELECT password_hash FROM users WHERE email = %s", (email,)
        ).fetchone()["password_hash"]


# --- Register ------------------------------------------------------------------------------


def test_register_creates_account_and_returns_only_id_and_email(client):
    resp = register(client)
    assert resp.status_code == 201
    body = resp.json()
    assert set(body) == {"id", "email"}
    assert body["email"] == ALICE["email"]
    assert "argon2" not in resp.text


def test_register_stores_argon2id_hash_not_plaintext(client, pg_pool):
    register(client)
    h = stored_hash(pg_pool, ALICE["email"])
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert ALICE["password"] not in h


def test_register_does_not_log_the_user_in(client):
    resp = register(client)
    assert "set-cookie" not in resp.headers
    assert client.get("/auth/me").status_code == 401


def test_register_rejects_short_password_without_echoing_it(client):
    secret = "short-secret"  # 12 characters
    resp = register(client, {"email": "a@example.com", "password": secret})
    assert resp.status_code == 422
    assert "at least 15" in resp.text
    assert secret not in resp.text


def test_register_duplicate_email_in_different_case_is_rejected(client):
    assert register(client).status_code == 201
    resp = register(client, {**ALICE, "email": "ALICE@Example.com"})
    assert resp.status_code == 409


@pytest.mark.parametrize("email", ["not-an-email", "a@", "@example.com", "a" * 250 + "@x.com"])
def test_register_rejects_invalid_email(client, email):
    assert register(client, {"email": email, "password": ALICE["password"]}).status_code == 422


def test_register_rejects_unexpected_fields_mass_assignment(client):
    resp = register(client, {**ALICE, "is_admin": True})
    assert resp.status_code == 422


def test_quote_in_email_works_end_to_end(client):
    creds = {"email": "o'brien@example.com", "password": ALICE["password"]}
    assert register(client, creds).status_code == 201
    assert login(client, creds).status_code == 200


# --- Validation errors never echo secrets ------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "password": "my-real-password-do-not-leak"},
        {"email": "a@example.com", "password": "my-real-password-do-not-leak" * 50},  # > 1024
        {"email": "a@example.com", "password": "my-real-password-do-not-leak", "extra": 1},
    ],
)
@pytest.mark.parametrize("path", ["/auth/register", "/auth/login"])
def test_validation_errors_do_not_echo_the_password(client, path, payload):
    resp = client.post(path, json=payload)
    assert resp.status_code == 422
    assert "my-real-password-do-not-leak" not in resp.text
    assert '"input"' not in resp.text


# --- CSRF-related request hardening --------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"data": ALICE},  # what an HTML <form> sends (application/x-www-form-urlencoded)
        {
            "content": '{"email":"alice@example.com","password":"correct horse battery staple"}',
            "headers": {"content-type": "text/plain"},
        },  # a "simple" cross-site request
    ],
)
def test_login_only_accepts_json_content_type(client, kwargs):
    register(client)
    resp = client.post("/auth/login", **kwargs)
    assert resp.status_code == 422
    assert "set-cookie" not in resp.headers


def test_login_is_post_only(client):
    assert client.get("/auth/login").status_code == 405


# --- Login ----------------------------------------------------------------------------------------


def test_login_sets_hardened_session_cookie(client):
    register(client)
    resp = login(client)
    assert resp.status_code == 200
    assert resp.json()["email"] == ALICE["email"]

    set_cookie = resp.headers["set-cookie"]
    lowered = set_cookie.lower()
    assert set_cookie.startswith(f"{COOKIE}=")
    assert "httponly" in lowered
    assert "secure" in lowered
    assert "samesite=lax" in lowered
    assert "path=/" in lowered
    assert "domain=" not in lowered
    assert "max-age" not in lowered


def test_wrong_password_and_unknown_email_are_indistinguishable(client):
    register(client)
    wrong_password = login(client, {**ALICE, "password": "wrong password but long enough"})
    unknown_email = login(client, {**ALICE, "email": "nobody@example.com"})

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json() == {"detail": "Invalid email or password."}
    ignore = {"date", "content-length"}
    assert {k: v for k, v in wrong_password.headers.items() if k not in ignore} == {
        k: v for k, v in unknown_email.headers.items() if k not in ignore
    }


def test_unknown_email_still_does_a_full_argon2_verification(client, monkeypatch):
    """Timing equalization: both failure paths must call Argon2 verify exactly once."""
    register(client)
    spy = SpyHasher(passwords._hasher)
    monkeypatch.setattr(passwords, "_hasher", spy)
    calls = spy.verify_calls

    login(client, {**ALICE, "password": "wrong password but long enough"})
    assert len(calls) == 1
    login(client, {**ALICE, "email": "nobody@example.com"})
    assert len(calls) == 2
    # And the dummy hash uses the same cost parameters as real hashes.
    assert calls[1].startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_failed_login_sets_no_cookie(client):
    register(client)
    resp = login(client, {**ALICE, "password": "wrong password but long enough"})
    assert "set-cookie" not in resp.headers


def test_login_email_is_case_insensitive(client):
    register(client)
    assert login(client, {**ALICE, "email": "Alice@EXAMPLE.com"}).status_code == 200


def test_login_destroys_planted_session_and_never_inherits_it(app):
    """Session swapping / fixation: an attacker plants THEIR logged-in session cookie."""
    attacker = new_client(app)
    register(attacker, BOB)
    login(attacker, BOB)
    attacker_token = attacker.cookies[COOKIE]

    victim = new_client(app)
    register(victim)
    plant_cookie(victim, attacker_token)
    assert victim.get("/auth/me").json()["email"] == BOB["email"]  # planted cookie is live

    resp = login(victim)

    assert resp.status_code == 200
    assert victim.cookies[COOKIE] != attacker_token  # fresh session ID replaced it
    assert victim.get("/auth/me").json()["email"] == ALICE["email"]  # victim's own account
    assert app.state.sessions.get(attacker_token) is None  # planted session is dead


def test_login_upgrades_outdated_password_hash(client, pg_pool):
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(ALICE["password"])
    with pg_pool.connection() as conn:
        users.create_user(conn, ALICE["email"], weak)
    assert login(client).status_code == 200
    assert stored_hash(pg_pool, ALICE["email"]).startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_saturated_hashing_returns_503_not_a_crash(client):
    register(client)
    passwords.configure_hashing_limits(1, 0.05)
    slot = passwords._limiter
    assert slot.acquire(timeout=1)  # simulate a hash already running
    try:
        resp = login(client)
    finally:
        slot.release()
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "1"
    assert "set-cookie" not in resp.headers


def test_hashing_concurrency_limit_is_never_exceeded(app, monkeypatch):
    register(new_client(app))
    passwords.configure_hashing_limits(2, 10.0)
    spy = SpyHasher(passwords._hasher)
    monkeypatch.setattr(passwords, "_hasher", spy)

    statuses = []
    threads = [
        threading.Thread(target=lambda: statuses.append(login(new_client(app)).status_code))
        for _ in range(6)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert statuses == [200] * 6  # all succeed, just queued
    assert len(spy.verify_calls) == 6
    assert spy.peak == 2  # never more than 2 hashes at the same time


# --- /auth/me ------------------------------------------------------------------------


def test_me_requires_a_session(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Not authenticated."}


@pytest.mark.parametrize("value", ["garbage", "A" * 43, "", "' OR 1=1 --"])
def test_me_rejects_forged_cookies(client, value):
    plant_cookie(client, value)
    assert client.get("/auth/me").status_code == 401


def test_me_returns_the_logged_in_user_without_secrets(client):
    register(client)
    login(client)
    resp = client.get("/auth/me")
    assert resp.status_code == 200
    assert set(resp.json()) == {"id", "email"}


def test_me_rejects_session_after_idle_timeout(client, clock):
    register(client)
    login(client)
    clock.advance(IDLE)
    assert client.get("/auth/me").status_code == 401


def test_activity_keeps_session_alive(client, clock):
    register(client)
    login(client)
    for _ in range(3):
        clock.advance(IDLE - 60)
        assert client.get("/auth/me").status_code == 200


def test_me_rejects_session_after_absolute_timeout_even_if_active(client, clock):
    register(client)
    login(client)
    while clock.elapsed < ABSOLUTE - 600:
        clock.advance(600)
        assert client.get("/auth/me").status_code == 200
    clock.advance(600)
    assert client.get("/auth/me").status_code == 401


def test_session_for_deleted_account_is_rejected_and_destroyed(app, client, pg_pool):
    register(client)
    login(client)
    token = client.cookies[COOKIE]
    with pg_pool.connection() as conn:
        conn.execute("DELETE FROM users")
    assert client.get("/auth/me").status_code == 401
    assert app.state.sessions.get(token) is None


# --- Logout --------------------------------------------------------------------------


def test_logout_revokes_the_session_on_the_server(app, client):
    register(client)
    login(client)
    stolen_token = client.cookies[COOKIE]  # imagine an attacker copied this

    replay = new_client(app)
    plant_cookie(replay, stolen_token)
    assert replay.get("/auth/me").status_code == 200  # control: the stolen token works...

    assert client.post("/auth/logout").status_code == 204

    assert replay.get("/auth/me").status_code == 401  # ...until the user logs out


def test_logout_clears_the_cookie(client):
    register(client)
    login(client)
    resp = client.post("/auth/logout")
    set_cookie = resp.headers["set-cookie"].lower()
    assert set_cookie.startswith(COOKIE.lower() + "=")
    assert "max-age=0" in set_cookie
    assert "path=/" in set_cookie and "secure" in set_cookie
    assert COOKIE not in client.cookies


def test_logout_without_a_session_is_harmless(client):
    assert client.post("/auth/logout").status_code == 204


def test_logout_only_ends_the_current_device(app):
    laptop, phone = new_client(app), new_client(app)
    register(laptop)
    login(laptop)
    login(phone)
    laptop.post("/auth/logout")
    assert phone.get("/auth/me").status_code == 200


def test_logout_is_post_only(client):
    # A GET logout could be triggered by an <img> tag on any website.
    assert client.get("/auth/logout").status_code == 405


# --- Response headers ----------------------------------------------------------------


@pytest.mark.parametrize("path", ["/health", "/auth/me"])
def test_security_headers_on_success_and_error_responses(client, path):
    resp = client.get(path)
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["x-frame-options"] == "DENY"


def test_login_response_is_not_cacheable(client):
    register(client)
    assert login(client).headers["cache-control"] == "no-store"


# --- Failure modes ---------------------------------------------------------------------------


class _BrokenRedis:
    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise redis.exceptions.ConnectionError("Error 111 connecting to redis:6379.")

        return fail


def test_unexpected_500_is_generic_and_still_has_security_headers(app):
    client = TestClient(app, base_url="https://testserver")
    app.state.sessions = SessionStore(
        _BrokenRedis(), idle_timeout_seconds=IDLE, absolute_timeout_seconds=ABSOLUTE
    )
    plant_cookie(client, "A" * 43)

    resp = client.get("/auth/me")

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error."}
    assert "redis" not in resp.text.lower()  # no internal details leak
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"


class _ExhaustedPool:
    def connection(self, *args, **kwargs):
        raise PoolTimeout("couldn't get a connection after 5.00 sec")


def test_database_pool_exhaustion_returns_fast_503(app, client):
    register(client)
    login(client)
    app.state.db_pool = _ExhaustedPool()

    resp = client.get("/auth/me")

    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "1"
    assert resp.headers["cache-control"] == "no-store"
    assert "connection" not in resp.text
