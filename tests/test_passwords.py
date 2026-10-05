"""Security tests for password hashing and policy.

Each test pins down one security property. If a future refactor breaks that
property (say, someone swaps in a faster hash or adds truncation), a test fails.
"""

import logging

import pytest
from argon2 import PasswordHasher

from app.security.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordPolicyError,
    hash_password,
    validate_password,
    verify_password,
)

GOOD_PASSWORD = "correct horse battery staple"


# --- Hash format and storage ---------------------------------------------------------


def test_hash_is_argon2id_with_expected_parameters():
    h = hash_password(GOOD_PASSWORD)
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_hash_does_not_contain_plaintext():
    h = hash_password(GOOD_PASSWORD)
    assert GOOD_PASSWORD not in h
    assert "horse" not in h


def test_same_password_gives_different_hashes_because_of_salt():
    assert hash_password(GOOD_PASSWORD) != hash_password(GOOD_PASSWORD)


# --- Verification --------------------------------------------------------------------


def test_correct_password_verifies():
    h = hash_password(GOOD_PASSWORD)
    result = verify_password(h, GOOD_PASSWORD)
    assert result.ok is True
    assert result.upgraded_hash is None


@pytest.mark.parametrize(
    "attempt",
    [
        "correct horse battery stapl",  # one character short
        "correct horse battery staplf",  # last character changed
        "Correct horse battery staple",  # different capitalization
        " correct horse battery staple",  # extra whitespace
        "",
    ],
)
def test_wrong_passwords_are_rejected(attempt):
    h = hash_password(GOOD_PASSWORD)
    assert verify_password(h, attempt).ok is False


def test_no_truncation_long_passwords_differing_only_at_the_end():
    # bcrypt only looks at the first 72 bytes, so these two would be "equal" there.
    prefix = "a" * 100
    h = hash_password(prefix + "X")
    assert verify_password(h, prefix + "Y").ok is False


@pytest.mark.parametrize("bad_hash", ["", "not-a-hash", "$argon2id$garbage", GOOD_PASSWORD])
def test_invalid_stored_hash_fails_closed_without_raising(bad_hash):
    assert verify_password(bad_hash, GOOD_PASSWORD).ok is False


def test_invalid_hash_log_does_not_leak_password(caplog):
    with caplog.at_level(logging.ERROR):
        verify_password("not-a-hash", GOOD_PASSWORD)
    assert GOOD_PASSWORD not in caplog.text


# --- Unicode normalization -----------------------------------------------------------


def test_composed_and_decomposed_unicode_verify_the_same():
    composed = "café au lait every morning"  # é as a single code point
    decomposed = "café au lait every morning"  # e + combining acute accent
    assert composed != decomposed  # different strings in Python...

    h = hash_password(composed)
    assert verify_password(h, decomposed).ok is True  # ...but the same password


def test_length_is_counted_in_code_points_not_bytes():
    # 15 emoji = 15 characters but 60 UTF-8 bytes. Should be accepted.
    validate_password("\U0001f510" * MIN_PASSWORD_LENGTH)


# --- Policy --------------------------------------------------------------------------


def test_minimum_length_boundary():
    with pytest.raises(PasswordPolicyError):
        validate_password("a" * (MIN_PASSWORD_LENGTH - 1))
    validate_password("a" * MIN_PASSWORD_LENGTH)


def test_maximum_length_boundary():
    validate_password("a" * MAX_PASSWORD_LENGTH)
    with pytest.raises(PasswordPolicyError):
        validate_password("a" * (MAX_PASSWORD_LENGTH + 1))


def test_nist_minimum_maximum_of_64_is_allowed():
    validate_password("a" * 64)


def test_no_composition_rules():
    # All lowercase, no digits, no symbols: allowed, per NIST SP 800-63B-4.
    validate_password("thisisonlylowercaseletters")


def test_hash_password_enforces_policy():
    with pytest.raises(PasswordPolicyError):
        hash_password("short")


def test_policy_error_message_does_not_echo_password():
    secret = "tooshort123"
    with pytest.raises(PasswordPolicyError) as exc:
        validate_password(secret)
    assert secret not in str(exc.value)


# --- Rehash on login -----------------------------------------------------------------


def test_outdated_hash_is_upgraded_after_successful_login():
    weak_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    old_hash = weak_hasher.hash(GOOD_PASSWORD)

    result = verify_password(old_hash, GOOD_PASSWORD)

    assert result.ok is True
    assert result.upgraded_hash is not None
    assert result.upgraded_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert verify_password(result.upgraded_hash, GOOD_PASSWORD).ok is True


def test_outdated_hash_is_not_upgraded_on_failed_login():
    weak_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    old_hash = weak_hasher.hash(GOOD_PASSWORD)

    result = verify_password(old_hash, "wrong password entirely")

    assert result.ok is False
    assert result.upgraded_hash is None


# --- Timing equalization (no account enumeration by response time) -----------------------


@pytest.fixture
def spy(monkeypatch):
    from app.security import passwords
    from tests.helpers import SpyHasher

    spy_hasher = SpyHasher(passwords._hasher)
    monkeypatch.setattr(passwords, "_hasher", spy_hasher)
    return spy_hasher


CURRENT_PARAMS = "$argon2id$v=19$m=65536,t=3,p=4$"


def test_wrong_password_on_current_hash_does_exactly_one_verification(spy):
    h = hash_password(GOOD_PASSWORD)
    verify_password(h, "wrong password but long enough")
    assert len(spy.verify_calls) == 1


def test_wrong_password_on_cheap_old_hash_is_topped_up_to_current_cost(spy):
    cheap = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(GOOD_PASSWORD)
    assert verify_password(cheap, "wrong password but long enough").ok is False
    assert len(spy.verify_calls) == 2
    assert spy.verify_calls[1].startswith(CURRENT_PARAMS)


def test_corrupt_stored_hash_still_costs_a_full_verification(spy):
    assert verify_password("not-a-hash", GOOD_PASSWORD).ok is False
    assert any(call.startswith(CURRENT_PARAMS) for call in spy.verify_calls)


def test_unknown_user_check_costs_one_current_verification(spy):
    from app.security.passwords import verify_password_for_unknown_user

    assert verify_password_for_unknown_user(GOOD_PASSWORD).ok is False
    assert len(spy.verify_calls) == 1
    assert spy.verify_calls[0].startswith(CURRENT_PARAMS)


def test_oversized_login_attempt_does_no_hashing_at_all(spy):
    h = hash_password(GOOD_PASSWORD)
    assert verify_password(h, "a" * (MAX_PASSWORD_LENGTH + 1)).ok is False
    assert spy.verify_calls == []
