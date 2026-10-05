"""Password policy and Argon2id password hashing.

WHY ARGON2ID
    Fast hashes like SHA-256 are the wrong tool for passwords. If the database leaks,
    a GPU can try billions of SHA-256 guesses per second. Argon2id (winner of the 2015
    Password Hashing Competition, specified in RFC 9106) is deliberately slow and
    *memory-hard*: every guess needs a big chunk of RAM, which is what makes GPU and
    custom-hardware (ASIC) cracking expensive. The "id" variant mixes Argon2i (resists
    side-channel attacks) and Argon2d (resists GPU cracking).

WHY argon2-cffi
    It wraps the official reference C implementation. We never write crypto ourselves.
    The library also generates a random 16-byte salt for every hash, so two users with
    the same password get different hashes, and precomputed "rainbow tables" don't work.

PARAMETERS
    RFC 9106 "low memory" profile: 64 MiB memory, 3 iterations, 4 lanes. That's above
    the OWASP minimum (19 MiB, 2 iterations, 1 lane). The parameters are stored *inside*
    the hash string, for example:
        $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    That's what lets us raise the cost later and upgrade old hashes when users log in
    (see `verify_password`).

POLICY (NIST SP 800-63B-4)
    - At least 15 characters, because the password is currently the only factor.
      (NIST allows 8 once MFA is required, which comes in Phase 3.)
    - No composition rules ("must include a symbol"). They push people toward
      predictable patterns like Password1!, and they don't add real strength.
    - Any Unicode is allowed. Length is counted in code points, after NFC normalization.
    - The whole password is verified, never truncated. (bcrypt silently ignores
      everything past 72 bytes. Argon2 has no such limit.)
    - A blocklist of breached passwords is also a NIST requirement. That's the
      HIBP check in Phase 2.
"""

import logging
import secrets
import threading
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cache

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.profiles import RFC_9106_LOW_MEMORY

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 15
# Well above NIST's "allow at least 64".
# Note: this cap is NOT what protects us from CPU exhaustion. Argon2 first compresses
# the password with BLAKE2b, which is very fast, so a 10 MB password hashes only ~15%
# slower than a 15-character one (measured). The real denial-of-service lever is the
# fixed cost of EVERY attempt (~100 ms of CPU, 64 MiB of RAM), no matter the length.
# That's handled by limiting how many hashes run at once (see "Concurrency limit" below)
# and by rate limiting (Phase 2). The cap just keeps input sizes sane and predictable.
MAX_PASSWORD_LENGTH = 256

_hasher = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)


class PasswordPolicyError(ValueError):
    """The password doesn't meet policy. The message is safe to show to users."""


class PasswordHashingBusyError(RuntimeError):
    """Too many password hashes are already running. The API turns this into HTTP 503."""


# ---- Concurrency limit ---------------------------------------------------------------
#
# Every Argon2 operation holds 64 MiB of RAM for ~100 ms. FastAPI runs up to 40 sync
# requests at once, so 40 simultaneous logins would need ~2.5 GB. A semaphore lets only
# N hashes run at a time (4 x 64 MiB = 256 MiB). A request that can't get a slot within
# the timeout fails fast with PasswordHashingBusyError instead of piling up. Under attack
# the service degrades to "try again shortly" instead of crashing for everyone.
#
# This is a resource cap, not rate limiting: it protects the server, not user accounts.
# Per-IP and per-account rate limits come in Phase 2.

_limiter = threading.BoundedSemaphore(4)
_queue_timeout_seconds = 1.0


def configure_hashing_limits(max_concurrency: int, queue_timeout_seconds: float) -> None:
    """Called once at app startup with values from settings."""
    global _limiter, _queue_timeout_seconds
    if max_concurrency < 1 or queue_timeout_seconds <= 0:
        raise ValueError("max_concurrency must be >= 1 and queue_timeout_seconds > 0")
    _limiter = threading.BoundedSemaphore(max_concurrency)
    _queue_timeout_seconds = queue_timeout_seconds


@contextmanager
def _hashing_slot() -> Iterator[None]:
    limiter = _limiter  # keep a reference so we release the same semaphore we acquired
    if not limiter.acquire(timeout=_queue_timeout_seconds):
        raise PasswordHashingBusyError
    try:
        yield
    finally:
        limiter.release()


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    # Set when the password was correct but the stored hash uses outdated parameters.
    # The caller should save this new hash in place of the old one.
    upgraded_hash: str | None = None


def normalize_password(password: str) -> str:
    """Apply Unicode NFC normalization.

    "é" can be typed as one code point (U+00E9) or as "e" plus a combining accent
    (U+0065 U+0301). They look identical, but they're different bytes, so they'd
    produce different hashes. Different keyboards and operating systems send
    different forms. Normalizing first means the user can still log in from any device.
    """
    return unicodedata.normalize("NFC", password)


def validate_password(password: str) -> None:
    """Raise PasswordPolicyError if the password doesn't meet policy."""
    length = len(normalize_password(password))  # len() on str counts code points
    if length < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )
    if length > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters long."
        )


def hash_password(password: str) -> str:
    """Check the policy, then return an Argon2id hash string ready to store.

    The policy check lives here, not in the route handler, so no code path can
    store a password that skipped validation.
    """
    validate_password(password)  # cheap check first, before taking a hashing slot
    with _hashing_slot():
        return _hasher.hash(normalize_password(password))


def verify_password(stored_hash: str, password: str) -> VerificationResult:
    """Check a login attempt against a stored hash.

    Never raises for a wrong password or a bad hash. It just returns ok=False, so a
    caller can't accidentally let someone in by forgetting to catch an exception.
    The one exception is PasswordHashingBusyError when the server is saturated, and an
    uncaught exception still fails closed: the request errors out, nobody gets logged in.
    """
    normalized = normalize_password(password)

    # The policy minimum doesn't apply at login (policies change, and old passwords should
    # keep working). The size cap does apply, so input stays bounded on every code path.
    if len(normalized) > MAX_PASSWORD_LENGTH:
        return VerificationResult(ok=False)

    with _hashing_slot():
        try:
            # argon2-cffi compares the hashes in constant time, so response timing
            # doesn't reveal how many bytes matched.
            _hasher.verify(stored_hash, normalized)
        except VerifyMismatchError:
            if _cheaper_than_current(stored_hash):
                _spend_current_cost(normalized)
            return VerificationResult(ok=False)
        except (InvalidHashError, VerificationError):
            # The stored value is corrupt or isn't an Argon2 hash. Fail closed and alert
            # operators, but never log the hash or the password.
            logger.error("Stored password hash is invalid or unsupported")
            _spend_current_cost(normalized)
            return VerificationResult(ok=False)

        if _hasher.check_needs_rehash(stored_hash):
            return VerificationResult(ok=True, upgraded_hash=_hasher.hash(normalized))
        return VerificationResult(ok=True)


def _cheaper_than_current(stored_hash: str) -> bool:
    """True if this hash was made with lower cost settings than we use today."""
    try:
        params = extract_parameters(stored_hash)
    except InvalidHashError:
        return True
    return params.memory_cost * params.time_cost < _hasher.memory_cost * _hasher.time_cost


def _spend_current_cost(normalized_password: str) -> None:
    """Burn one verification at TODAY's cost. Caller must already hold a hashing slot.

    Why (found by the security review): after we raise the Argon2 settings, accounts that
    haven't logged in since still have cheap old hashes. A wrong password against a cheap
    hash failed in ~5 ms, while an unknown email took ~125 ms (dummy hash at current cost).
    That gap would let an attacker list which emails have accounts. Topping up failed
    checks on cheaper hashes to the current cost keeps every failure equally slow.
    """
    try:
        _hasher.verify(_dummy_hash(), normalized_password)
    except VerifyMismatchError:
        pass


# ---- Unknown users: equalize timing ---------------------------------------------------
#
# If login returned instantly for an unknown email but took ~100 ms for a real one, an
# attacker could time responses to learn which emails have accounts (account enumeration),
# then focus password guessing on those. So for an unknown email we still run a full
# Argon2id verification, against a dummy hash with the same parameters, and throw the
# result away. Both paths do the same work and return the same error.


@cache
def _dummy_hash() -> str:
    # Random, never stored or shown, so no password can ever match it.
    return _hasher.hash(secrets.token_urlsafe(32))


def warm_up() -> None:
    """Compute the dummy hash at startup, so the first unknown-email login isn't slower."""
    _dummy_hash()


def verify_password_for_unknown_user(password: str) -> VerificationResult:
    """Do the same work as a real verification, then fail."""
    verify_password(_dummy_hash(), password)
    return VerificationResult(ok=False)
