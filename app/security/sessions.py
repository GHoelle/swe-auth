"""Server-side sessions stored in Redis.

HOW IT WORKS
    On login, the server generates a random session token and sends it to the browser
    in a cookie (Step 3). The browser holds ONLY that random token. Everything else
    (which user it is, when the session started) lives on the server, in Redis.

WHY SERVER-SIDE SESSIONS INSTEAD OF JWTs
    Revocation is instant. Logout deletes the Redis key, and the token is dead everywhere.
    A stateless JWT stays valid until it expires, even after logout or a password change,
    unless you add a server-side denylist. At that point you've rebuilt server-side
    sessions, with extra complexity.

TOKEN GENERATION
    secrets.token_urlsafe(32) reads 32 bytes (256 bits) from the operating system's
    cryptographically secure random number generator. OWASP asks for at least 64 bits
    of entropy. Never use the `random` module: its Mersenne Twister generator can be
    predicted after observing enough outputs.

STORE A HASH OF THE TOKEN, NOT THE TOKEN
    The Redis key is "session:" + SHA-256(token). If someone can read Redis (a leaked
    backup, a misconfigured replica, an SSRF bug), they get hashes they can't turn back
    into working cookies.
    Why is a FAST hash fine here when passwords need slow Argon2id? A token is 256 random
    bits, so there is nothing to guess and brute force is hopeless no matter how fast
    the hash is. Slow hashing only matters for low-entropy secrets that humans pick.
    Bonus: lookups go by hash, so response timing can't reveal "how much of the token
    matched". That means no constant-time comparison is needed.

TIMEOUTS (OWASP Session Management Cheat Sheet)
    Idle timeout: the session dies after N minutes with no requests (for example, a
    laptop left open in a library).
    Absolute timeout: the session dies N hours after login, even if it's still in use.
    This caps how long a stolen token stays useful.
    The Redis TTL enforces both automatically. The code also checks the timestamps
    itself, as defense in depth.

ROTATION (defends against session fixation)
    Session fixation: an attacker gets a session ID they know into the victim's browser,
    then waits for the victim to log in, which turns the attacker's ID into an
    authenticated one. Defense: never keep a session ID across a privilege change.
    Login always calls `create` (a brand-new ID). `rotate` issues a fresh ID for later
    privilege changes, such as the MFA step-up in Phase 3.

SERIALIZATION
    JSON, never pickle. Unpickling data that an attacker can write means remote code
    execution.
"""

import hashlib
import json
import math
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass

import redis
from fastapi import Request

TOKEN_BYTES = 32
# token_urlsafe(32) always produces exactly 43 characters from this alphabet.
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")

_SESSION_KEY_PREFIX = "session:"
_USER_INDEX_PREFIX = "user_sessions:"


@dataclass(frozen=True, slots=True)
class Session:
    user_id: str
    created_at: float  # Unix time of login. Never changes, even on rotation.
    last_seen_at: float  # Unix time of the most recent request.


class SessionStore:
    """Create, look up, rotate, and destroy sessions.

    The Redis client must be created with decode_responses=True (see app/cache.py).
    """

    def __init__(
        self,
        client: redis.Redis,
        *,
        idle_timeout_seconds: int,
        absolute_timeout_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive")
        if absolute_timeout_seconds < idle_timeout_seconds:
            raise ValueError("absolute_timeout_seconds must be >= idle_timeout_seconds")
        self._redis = client
        self._idle = idle_timeout_seconds
        self._absolute = absolute_timeout_seconds
        # Injectable clock, so tests can "fast-forward" hours without sleeping.
        self._clock = clock

    # ---- public API --------------------------------------------------------------

    def create(self, user_id: str) -> str:
        """Start a new session for a user who just authenticated. Returns the raw token.

        The raw token exists only in this return value and in the user's cookie.
        """
        token = secrets.token_urlsafe(TOKEN_BYTES)
        now = self._clock()
        session = Session(user_id=user_id, created_at=now, last_seen_at=now)
        token_hash = _hash_token(token)

        self._prune_index(user_id)
        pipe = self._redis.pipeline(transaction=True)
        self._queue_save(pipe, token_hash, session, now)
        pipe.sadd(_USER_INDEX_PREFIX + user_id, token_hash)
        pipe.expire(_USER_INDEX_PREFIX + user_id, self._absolute)
        pipe.execute()
        return token

    def get(self, token: str | None) -> Session | None:
        """Return the session for a token, or None if it's invalid or expired.

        A valid lookup also counts as activity and resets the idle timer.
        Fails closed: if Redis is unreachable this RAISES (so the request errors out)
        rather than returning something that could be mistaken for "logged in".
        """
        if not _is_well_formed(token):
            return None
        token_hash = _hash_token(token)
        key = _SESSION_KEY_PREFIX + token_hash

        session = _parse(self._redis.get(key))
        if session is None:
            self._redis.delete(key)  # remove corrupt data if present; no-op otherwise
            return None

        now = self._clock()
        if self._is_expired(session, now):
            self._delete(token_hash, session.user_id)
            return None

        refreshed = Session(session.user_id, session.created_at, last_seen_at=now)
        # xx=True means "only update if the key still exists". Without it, a request that
        # started just before logout could write the session back AFTER logout deleted it,
        # bringing a logged-out session back to life.
        updated = self._redis.set(
            key, _serialize(refreshed), ex=self._ttl_seconds(refreshed, now), xx=True
        )
        return refreshed if updated else None

    def rotate(self, token: str | None) -> str | None:
        """Replace a valid session's token with a new one. Returns the new token.

        created_at is kept, so rotating can't be used to dodge the absolute timeout.

        RACE (found by the security review): the first version checked the session, then
        swapped tokens in a separate step. If "sign out everywhere" ran in between (say, a
        password reset), the swap still wrote the NEW session afterwards, and the attacker
        kept a working token. Now the check and the swap are one optimistic transaction:
        WATCH the old key, read it, then MULTI/EXEC. If anything touches the old key in
        between (logout, sign-out-everywhere, another rotate, a refresh), Redis aborts the
        EXEC and redis-py retries from the read, which then sees the session is gone.
        """
        if not _is_well_formed(token):
            return None
        old_hash = _hash_token(token)  # type: ignore[arg-type]  # validated above
        old_key = _SESSION_KEY_PREFIX + old_hash
        new_token = secrets.token_urlsafe(TOKEN_BYTES)
        new_hash = _hash_token(new_token)

        def swap(pipe: redis.client.Pipeline) -> bool:
            session = _parse(pipe.get(old_key))  # runs immediately, while WATCHing old_key
            now = self._clock()
            if session is None or self._is_expired(session, now):
                return False
            index_key = _USER_INDEX_PREFIX + session.user_id
            pipe.multi()  # from here, commands are queued and run atomically at EXEC
            pipe.delete(old_key)
            pipe.srem(index_key, old_hash)
            self._queue_save(pipe, new_hash, session, now)
            pipe.sadd(index_key, new_hash)
            pipe.expire(index_key, self._absolute)
            return True

        swapped = self._redis.transaction(swap, old_key, value_from_callable=True)
        return new_token if swapped else None

    def destroy(self, token: str | None) -> None:
        """Log out one session. Safe to call with a missing, invalid, or already-dead token."""
        if not _is_well_formed(token):
            return
        token_hash = _hash_token(token)
        # GETDEL reads and deletes in one atomic step, so nothing can use the session in between.
        session = _parse(self._redis.getdel(_SESSION_KEY_PREFIX + token_hash))
        if session is not None:
            self._redis.srem(_USER_INDEX_PREFIX + session.user_id, token_hash)

    def destroy_all_for_user(self, user_id: str) -> None:
        """Log out every session for a user ("sign out everywhere").

        Used after a password change or reset (Phase 2), so a stolen session can't
        outlive the stolen password.
        """
        index_key = _USER_INDEX_PREFIX + user_id

        def delete_all(pipe: redis.client.Pipeline) -> None:
            token_hashes = pipe.smembers(index_key)
            pipe.multi()
            for token_hash in token_hashes:
                pipe.delete(_SESSION_KEY_PREFIX + token_hash)
            pipe.delete(index_key)

        # WATCH the index. If a new session gets added while we're reading it, Redis aborts
        # the transaction and redis-py retries, so no session can slip through.
        self._redis.transaction(delete_all, index_key)

    # ---- internals ---------------------------------------------------------------

    def _is_expired(self, session: Session, now: float) -> bool:
        idle_for = now - session.last_seen_at
        age = now - session.created_at
        return idle_for >= self._idle or age >= self._absolute

    def _ttl_seconds(self, session: Session, now: float) -> int:
        """Redis expiry: whichever comes first, the idle deadline or the absolute deadline."""
        remaining_absolute = self._absolute - (now - session.created_at)
        return max(1, math.ceil(min(self._idle, remaining_absolute)))

    def _queue_save(self, pipe, token_hash: str, session: Session, now: float) -> None:
        refreshed = Session(session.user_id, session.created_at, last_seen_at=now)
        pipe.set(
            _SESSION_KEY_PREFIX + token_hash,
            _serialize(refreshed),
            ex=self._ttl_seconds(refreshed, now),
        )

    def _prune_index(self, user_id: str) -> None:
        """Remove index entries whose session already expired.

        Sessions usually end by Redis TTL expiry, which doesn't touch the per-user index,
        and each login used to refresh the index TTL. So the set could grow forever (found
        by the security review). Safe without a transaction: a token hash is random and
        never reused, and an entry is always added in the same MULTI as its session key,
        so "entry exists but key doesn't" can only mean the session is permanently gone.
        """
        index_key = _USER_INDEX_PREFIX + user_id
        token_hashes = list(self._redis.smembers(index_key))
        if not token_hashes:
            return
        pipe = self._redis.pipeline(transaction=False)
        for token_hash in token_hashes:
            pipe.exists(_SESSION_KEY_PREFIX + token_hash)
        alive = pipe.execute()
        dead = [h for h, is_alive in zip(token_hashes, alive, strict=True) if not is_alive]
        if dead:
            self._redis.srem(index_key, *dead)

    def _delete(self, token_hash: str, user_id: str) -> None:
        pipe = self._redis.pipeline(transaction=True)
        pipe.delete(_SESSION_KEY_PREFIX + token_hash)
        pipe.srem(_USER_INDEX_PREFIX + user_id, token_hash)
        pipe.execute()


async def get_session_store(request: Request) -> SessionStore:
    """FastAPI dependency (async: no I/O, so it shouldn't occupy a worker thread)."""
    return request.app.state.sessions


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _is_well_formed(token: object) -> bool:
    # Reject garbage before touching Redis: wrong type, wrong length, odd characters.
    return isinstance(token, str) and _TOKEN_PATTERN.fullmatch(token) is not None


def _serialize(session: Session) -> str:
    return json.dumps(asdict(session))


def _parse(raw: str | bytes | None) -> Session | None:
    """Turn stored JSON into a Session. Anything unexpected returns None (fail closed)."""
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    user_id = data.get("user_id")
    created_at = data.get("created_at")
    last_seen_at = data.get("last_seen_at")
    if not isinstance(user_id, str) or not user_id:
        return None
    for value in (created_at, last_seen_at):
        # bool is a subclass of int in Python, so exclude it explicitly.
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
    return Session(user_id=user_id, created_at=float(created_at), last_seen_at=float(last_seen_at))
