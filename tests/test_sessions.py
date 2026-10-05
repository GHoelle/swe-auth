"""Security tests for server-side sessions.

By default these run against fakeredis (in-memory, no server needed). To run the same
tests against a real Redis, set TEST_REDIS_URL to a DEDICATED database. It gets wiped.
    docker compose exec -e TEST_REDIS_URL=redis://:<password>@redis:6379/15 app pytest
"""

import hashlib
import json
import os

import fakeredis
import pytest
import redis
from pydantic import ValidationError

from app.config import Settings
from app.security.sessions import Session, SessionStore
from tests.helpers import FakeClock

IDLE = 30 * 60
ABSOLUTE = 12 * 60 * 60
ALICE = "6f1d8e8a-4a55-4c3b-9d0e-1b2a3c4d5e6f"
BOB = "0a9b8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"


def stay_active_until(store, clock, token, elapsed_target):
    """Simulate a request every 10 minutes until `elapsed_target` seconds after login."""
    while clock.elapsed < elapsed_target:
        clock.advance(min(600, elapsed_target - clock.elapsed))
        assert store.get(token) is not None


@pytest.fixture
def redis_client():
    url = os.environ.get("TEST_REDIS_URL")
    client = (
        redis.Redis.from_url(url, decode_responses=True)
        if url
        else fakeredis.FakeRedis(decode_responses=True)
    )
    client.flushdb()
    yield client
    client.flushdb()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store(redis_client, clock):
    return SessionStore(
        redis_client, idle_timeout_seconds=IDLE, absolute_timeout_seconds=ABSOLUTE, clock=clock
    )


def session_key(token: str) -> str:
    return "session:" + hashlib.sha256(token.encode()).hexdigest()


# --- Token generation and storage ---------------------------------------------------


def test_token_has_256_bits_of_entropy_and_is_url_safe(store):
    token = store.create(ALICE)
    # 32 random bytes, base64url-encoded without padding, is 43 characters.
    assert len(token) == 43
    assert all(c.isalnum() or c in "-_" for c in token)


def test_tokens_are_unique(store):
    tokens = {store.create(f"user-{i}") for i in range(1000)}
    assert len(tokens) == 1000


def test_raw_token_is_never_stored_in_redis(store, redis_client):
    token = store.create(ALICE)
    for key in redis_client.scan_iter():
        assert token not in key
        value = (
            redis_client.get(key)
            if redis_client.type(key) == "string"
            else " ".join(redis_client.smembers(key))
        )
        assert token not in value


def test_redis_key_is_sha256_of_token(store, redis_client):
    token = store.create(ALICE)
    assert redis_client.exists(session_key(token)) == 1


def test_session_data_is_json_not_pickle(store, redis_client):
    token = store.create(ALICE)
    data = json.loads(redis_client.get(session_key(token)))
    assert data["user_id"] == ALICE


# --- Lookup -------------------------------------------------------------------------


def test_valid_token_returns_session(store):
    token = store.create(ALICE)
    session = store.get(token)
    assert isinstance(session, Session)
    assert session.user_id == ALICE


def test_unknown_but_well_formed_token_is_rejected(store):
    assert store.get("A" * 43) is None


def test_tampered_token_is_rejected(store):
    token = store.create(ALICE)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert store.get(tampered) is None


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "short",
        "A" * 42,
        "A" * 44,
        "A" * 5000,
        "A" * 42 + "=",
        "../" * 14 + "A",
        "A" * 42 + "é",
        12345,
        b"A" * 43,
    ],
)
def test_malformed_tokens_are_rejected(store, bad):
    assert store.get(bad) is None
    store.destroy(bad)  # must not raise either
    assert store.rotate(bad) is None


# --- Idle timeout -------------------------------------------------------------------


def test_activity_keeps_session_alive_sliding_window(store, clock):
    token = store.create(ALICE)
    for _ in range(5):
        clock.advance(IDLE - 1)
        assert store.get(token) is not None


def test_session_expires_after_idle_timeout(store, clock, redis_client):
    token = store.create(ALICE)
    clock.advance(IDLE)
    assert store.get(token) is None
    assert redis_client.exists(session_key(token)) == 0  # cleaned up, not just ignored


def test_redis_ttl_matches_idle_timeout(store, redis_client):
    token = store.create(ALICE)
    assert IDLE - 2 <= redis_client.ttl(session_key(token)) <= IDLE


# --- Absolute timeout ---------------------------------------------------------------


def test_session_expires_at_absolute_timeout_even_when_active(store, clock):
    token = store.create(ALICE)
    stay_active_until(store, clock, token, ABSOLUTE - 1)  # busy all day long
    clock.advance(1)
    assert store.get(token) is None


def test_redis_ttl_never_extends_past_absolute_deadline(store, clock, redis_client):
    token = store.create(ALICE)
    stay_active_until(store, clock, token, ABSOLUTE - 60)
    assert redis_client.ttl(session_key(token)) <= 60


# --- Rotation (session fixation defense) --------------------------------------------


def test_rotate_kills_old_token_and_issues_new_one(store):
    old = store.create(ALICE)
    new = store.rotate(old)
    assert new is not None and new != old
    assert store.get(old) is None
    assert store.get(new).user_id == ALICE


def test_rotation_does_not_reset_absolute_timeout(store, clock):
    token = store.create(ALICE)
    stay_active_until(store, clock, token, ABSOLUTE - 100)
    token = store.rotate(token)
    clock.advance(100)
    assert store.get(token) is None


def _run_during_rotate_swap(monkeypatch, store, action):
    """Run `action` once, after rotate() has checked the old session but before the new
    session is written (the moment it queues the new session's SET)."""
    real_queue_save = store._queue_save
    fired = False

    def queue_save_then_act(*args, **kwargs):
        nonlocal fired
        if not fired:
            fired = True
            action()
        return real_queue_save(*args, **kwargs)

    monkeypatch.setattr(store, "_queue_save", queue_save_then_act)


def test_sign_out_everywhere_during_rotation_cannot_leave_a_live_session(store, monkeypatch):
    token = store.create(ALICE)
    _run_during_rotate_swap(monkeypatch, store, lambda: store.destroy_all_for_user(ALICE))

    new_token = store.rotate(token)

    monkeypatch.undo()
    assert new_token is None or store.get(new_token) is None
    assert store.get(token) is None


def test_logout_during_rotation_cannot_leave_a_live_session(store, monkeypatch, redis_client):
    token = store.create(ALICE)
    _run_during_rotate_swap(monkeypatch, store, lambda: store.destroy(token))

    new_token = store.rotate(token)

    monkeypatch.undo()
    assert new_token is None or store.get(new_token) is None


def test_concurrent_rotations_of_one_token_leave_exactly_one_live_session(store, monkeypatch):
    token = store.create(ALICE)
    inner: list[str | None] = []
    _run_during_rotate_swap(monkeypatch, store, lambda: inner.append(store.rotate(token)))

    outer = store.rotate(token)

    monkeypatch.undo()
    live = [t for t in (inner[0], outer) if t is not None and store.get(t) is not None]
    assert len(live) == 1


def test_expired_sessions_are_pruned_from_the_user_index(store, redis_client):
    old_tokens = [store.create(ALICE) for _ in range(5)]
    for t in old_tokens:
        redis_client.delete(session_key(t))  # what Redis TTL expiry does

    store.create(ALICE)

    assert redis_client.scard("user_sessions:" + ALICE) == 1


def test_pruning_keeps_live_sessions(store, redis_client):
    live = [store.create(ALICE) for _ in range(3)]
    store.create(ALICE)
    assert redis_client.scard("user_sessions:" + ALICE) == 4
    assert all(store.get(t) is not None for t in live)


def test_login_creates_fresh_session_ids_every_time(store):
    # Login must call create(), which never reuses an ID, so a planted ID can't be upgraded.
    assert store.create(ALICE) != store.create(ALICE)


# --- Logout ------------------------------------------------------------------------


def test_destroy_logs_out_that_session(store, redis_client):
    token = store.create(ALICE)
    store.destroy(token)
    assert store.get(token) is None
    assert redis_client.exists(session_key(token)) == 0


def test_destroy_is_idempotent(store):
    token = store.create(ALICE)
    store.destroy(token)
    store.destroy(token)


def test_destroy_only_affects_one_session(store):
    laptop = store.create(ALICE)
    phone = store.create(ALICE)
    store.destroy(laptop)
    assert store.get(phone) is not None


def test_destroy_all_for_user_logs_out_everywhere_but_not_other_users(store, redis_client):
    alice_sessions = [store.create(ALICE) for _ in range(3)]
    bob = store.create(BOB)

    store.destroy_all_for_user(ALICE)

    assert all(store.get(t) is None for t in alice_sessions)
    assert store.get(bob) is not None
    assert redis_client.exists("user_sessions:" + ALICE) == 0


def test_in_flight_request_cannot_resurrect_a_logged_out_session(store, redis_client, monkeypatch):
    token = store.create(ALICE)
    real_get = redis_client.get

    def get_then_concurrent_logout(key):
        value = real_get(key)
        store.destroy(token)  # logout lands between our read and our write
        return value

    monkeypatch.setattr(redis_client, "get", get_then_concurrent_logout)
    assert store.get(token) is None
    monkeypatch.undo()
    assert redis_client.exists(session_key(token)) == 0


# --- Fail closed ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "corrupt",
    [
        "not json",
        "[]",
        json.dumps({"user_id": ALICE}),
        json.dumps({"user_id": 42, "created_at": 1.0, "last_seen_at": 1.0}),
        json.dumps({"user_id": "", "created_at": 1.0, "last_seen_at": 1.0}),
        json.dumps({"user_id": ALICE, "created_at": True, "last_seen_at": 1.0}),
        json.dumps({"user_id": ALICE, "created_at": "yesterday", "last_seen_at": 1.0}),
    ],
)
def test_corrupt_session_data_is_rejected_and_removed(store, redis_client, corrupt):
    token = store.create(ALICE)
    redis_client.set(session_key(token), corrupt)
    assert store.get(token) is None
    assert redis_client.exists(session_key(token)) == 0


def test_redis_outage_raises_instead_of_authenticating():
    unreachable = redis.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)
    store = SessionStore(unreachable, idle_timeout_seconds=IDLE, absolute_timeout_seconds=ABSOLUTE)
    with pytest.raises(redis.exceptions.ConnectionError):
        store.get("A" * 43)


# --- Configuration -----------------------------------------------------------------


def test_store_rejects_invalid_timeouts(redis_client):
    with pytest.raises(ValueError):
        SessionStore(redis_client, idle_timeout_seconds=0, absolute_timeout_seconds=10)
    with pytest.raises(ValueError):
        SessionStore(redis_client, idle_timeout_seconds=100, absolute_timeout_seconds=10)


def test_settings_reject_absolute_timeout_shorter_than_idle(monkeypatch):
    monkeypatch.setenv("SESSION_IDLE_TIMEOUT_SECONDS", "3600")
    monkeypatch.setenv("SESSION_ABSOLUTE_TIMEOUT_SECONDS", "60")
    with pytest.raises(ValidationError):
        Settings()
