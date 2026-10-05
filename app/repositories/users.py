"""Data access for the users table.

SQL INJECTION DEFENSE
    Every query here is a constant string with %s placeholders, and user data is passed
    separately as parameters:

        conn.execute("SELECT ... WHERE email = %s", (email,))

    psycopg sends the SQL text and the values to PostgreSQL separately (server-side
    binding). The database parses the query BEFORE it sees the values, so a value can
    never change the query's structure. An email like  ' OR '1'='1  is just a strange
    string that matches nothing.

    Never build SQL with f-strings, +, %, or .format(). Two automated checks enforce this:
    ruff's bandit rule S608, and test_users_repository.py, which inspects this file and
    fails if any execute() call gets anything other than a string literal.

    Note: %s here is NOT Python's % formatting. It's psycopg's placeholder syntax.

OTHER RULES IN THIS FILE
    - Explicit column lists, never SELECT *. A new column (say, an MFA secret) can't leak
      into an API response just because someone added it to the table.
    - Two return types. `User` has no password hash, so route code can't accidentally
      return one. `UserCredentials` is only for the login check.
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from psycopg import Connection, errors
from psycopg.rows import dict_row


@dataclass(frozen=True, slots=True)
class User:
    """Safe to return from the API."""

    id: UUID
    email: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class UserCredentials:
    """Only for verifying a login. Never return this from an endpoint."""

    id: UUID
    email: str
    # repr=False keeps the hash out of logs, tracebacks, and debugger output.
    password_hash: str = field(repr=False)


class EmailAlreadyRegisteredError(Exception):
    pass


def create_user(conn: Connection, email: str, password_hash: str) -> User:
    try:
        # conn.transaction() opens a SAVEPOINT. If the INSERT fails, only this statement is
        # rolled back, and the connection stays usable for the rest of the request.
        # (In PostgreSQL, one failed statement otherwise poisons the whole transaction.)
        with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s) "
                "RETURNING id, email, created_at",
                (email, password_hash),
            )
            row = cur.fetchone()
    except errors.UniqueViolation as exc:
        # citext makes the UNIQUE constraint case-insensitive, so Alice@x.com == alice@x.com.
        # The database enforces uniqueness atomically. Checking "does it exist?" first in
        # Python would be a race: two simultaneous signups could both pass the check.
        raise EmailAlreadyRegisteredError from exc
    assert row is not None  # noqa: S101  # RETURNING always yields a row on success
    return User(id=row["id"], email=row["email"], created_at=row["created_at"])


def get_credentials_by_email(conn: Connection, email: str) -> UserCredentials | None:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, email, password_hash FROM users WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return UserCredentials(id=row["id"], email=row["email"], password_hash=row["password_hash"])


def get_user_by_id(conn: Connection, user_id: str | UUID) -> User | None:
    # Validate in Python first. A malformed ID should simply mean "no such user", not a
    # database error (Postgres raises if you compare a uuid column to "not-a-uuid").
    try:
        uuid_value = user_id if isinstance(user_id, UUID) else UUID(str(user_id))
    except ValueError:
        return None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT id, email, created_at FROM users WHERE id = %s",
            (uuid_value,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return User(id=row["id"], email=row["email"], created_at=row["created_at"])


def update_password_hash(conn: Connection, user_id: UUID, password_hash: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET password_hash = %s, updated_at = now() WHERE id = %s",
            (password_hash, user_id),
        )
