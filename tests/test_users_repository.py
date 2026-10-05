"""Security tests for the user repository. Runs against real PostgreSQL (TEST_DATABASE_URL)."""

import ast
import uuid
from pathlib import Path

import pytest
from psycopg import errors

from app.repositories import users
from app.security.passwords import hash_password

REPO_FILE = Path(__file__).resolve().parent.parent / "app" / "repositories" / "users.py"


@pytest.fixture(scope="module")
def a_hash() -> str:
    # One real Argon2id hash reused across tests (hashing is deliberately slow).
    return hash_password("correct horse battery staple")


# --- Static check: SQL is never built from strings ----------------------------------


def test_every_execute_call_uses_a_constant_sql_string():
    """Fails if anyone writes cur.execute(f"...") or cur.execute("..." + x) in the repo.

    Implicitly concatenated literals ("a " "b") are fine: Python joins them at compile time.
    """
    tree = ast.parse(REPO_FILE.read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    ]
    assert calls, "expected to find execute() calls"
    for call in calls:
        sql = call.args[0]
        assert isinstance(sql, ast.Constant) and isinstance(sql.value, str), (
            f"line {call.lineno}: SQL must be a string literal with %s placeholders"
        )


# --- Create and read ---------------------------------------------------------------------


def test_create_user_returns_public_user_without_hash(db_conn, a_hash):
    user = users.create_user(db_conn, "alice@example.com", a_hash)
    assert isinstance(user.id, uuid.UUID)
    assert user.email == "alice@example.com"
    assert not hasattr(user, "password_hash")


def test_user_ids_are_random_uuids_not_sequential(db_conn, a_hash):
    first = users.create_user(db_conn, "a@example.com", a_hash)
    second = users.create_user(db_conn, "b@example.com", a_hash)
    assert first.id.version == 4 and second.id.version == 4
    assert first.id != second.id


def test_lookup_by_email_is_case_insensitive(db_conn, a_hash):
    users.create_user(db_conn, "Alice@Example.com", a_hash)
    creds = users.get_credentials_by_email(db_conn, "alice@EXAMPLE.COM")
    assert creds is not None
    assert creds.password_hash == a_hash


def test_credentials_repr_hides_password_hash(db_conn, a_hash):
    users.create_user(db_conn, "alice@example.com", a_hash)
    creds = users.get_credentials_by_email(db_conn, "alice@example.com")
    assert a_hash not in repr(creds)
    assert "argon2" not in repr(creds)


def test_get_user_by_id(db_conn, a_hash):
    created = users.create_user(db_conn, "alice@example.com", a_hash)
    assert users.get_user_by_id(db_conn, str(created.id)) == created


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "", "1", "' OR '1'='1", str(uuid.uuid4())])
def test_get_user_by_id_with_unknown_or_malformed_id_returns_none(db_conn, a_hash, bad_id):
    users.create_user(db_conn, "alice@example.com", a_hash)
    assert users.get_user_by_id(db_conn, bad_id) is None
    db_conn.execute("SELECT 1")  # connection still healthy


def test_update_password_hash(db_conn, a_hash):
    user = users.create_user(db_conn, "alice@example.com", a_hash)
    new_hash = hash_password("a completely different passphrase")
    users.update_password_hash(db_conn, user.id, new_hash)
    assert users.get_credentials_by_email(db_conn, "alice@example.com").password_hash == new_hash


# --- Uniqueness ---------------------------------------------------------------------------


def test_duplicate_email_differing_only_in_case_is_rejected(db_conn, a_hash):
    users.create_user(db_conn, "alice@example.com", a_hash)
    with pytest.raises(users.EmailAlreadyRegisteredError):
        users.create_user(db_conn, "ALICE@example.com", a_hash)


def test_connection_is_still_usable_after_duplicate_email(db_conn, a_hash):
    # Without the savepoint, Postgres would reject every later query in this transaction.
    users.create_user(db_conn, "alice@example.com", a_hash)
    with pytest.raises(users.EmailAlreadyRegisteredError):
        users.create_user(db_conn, "alice@example.com", a_hash)
    assert users.create_user(db_conn, "bob@example.com", a_hash).email == "bob@example.com"


# --- SQL injection --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "' OR '1'='1",
        "' OR 1=1 --",
        "alice@example.com' --",
        "x' UNION SELECT id, email, password_hash FROM users --",
        "%",  # LIKE wildcard: harmless because we use =, not LIKE
    ],
)
def test_injection_payloads_in_email_lookup_match_nothing(db_conn, a_hash, payload):
    users.create_user(db_conn, "alice@example.com", a_hash)
    assert users.get_credentials_by_email(db_conn, payload) is None


def test_quotes_in_email_are_stored_literally(db_conn, a_hash):
    # O'Brien is a real surname. Parameterized queries handle it with no escaping code.
    users.create_user(db_conn, "o'brien@example.com", a_hash)
    assert users.get_credentials_by_email(db_conn, "o'brien@example.com") is not None


def test_drop_table_payload_is_just_data(db_conn, a_hash):
    payload = "x@example.com'); DROP TABLE users; --"
    users.create_user(db_conn, payload, a_hash)
    assert users.get_credentials_by_email(db_conn, payload).email == payload
    db_conn.execute("SELECT count(*) FROM users")  # table still exists


# --- Database guardrails (defense in depth) ------------------------------------------------


def test_database_rejects_plaintext_password(db_conn):
    with pytest.raises(errors.CheckViolation):
        users.create_user(db_conn, "alice@example.com", "hunter2-plaintext")


def test_database_rejects_non_argon2id_hash(db_conn):
    bcrypt_like = "$2b$12$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    with pytest.raises(errors.CheckViolation):
        users.create_user(db_conn, "alice@example.com", bcrypt_like)


def test_database_rejects_overlong_email(db_conn, a_hash):
    with pytest.raises(errors.CheckViolation):
        users.create_user(db_conn, "a" * 250 + "@x.com", a_hash)
