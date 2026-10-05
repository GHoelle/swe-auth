"""Authentication endpoints: register, login, logout, me.

All state-changing endpoints are POST and accept only JSON bodies. Combined with the
SameSite=Lax cookie, that means a malicious site can't make a victim's browser send an
authenticated request here (CSRF). An HTML form can't send application/json, and a
cross-site fetch() with JSON triggers a CORS preflight, which we don't allow.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.dependencies import AppSettings, CurrentUser, DbPool, Sessions
from app.repositories import users
from app.repositories.users import User
from app.security.cookies import clear_session_cookie, read_session_token, set_session_cookie
from app.security.passwords import (
    PasswordPolicyError,
    hash_password,
    verify_password,
    verify_password_for_unknown_user,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# One message for "no such email" AND "wrong password". Different messages would tell an
# attacker which emails have accounts.
INVALID_CREDENTIALS = "Invalid email or password."


class Credentials(BaseModel):
    # Reject unexpected fields ({"email": ..., "password": ..., "is_admin": true}), so
    # adding a field to a model later can never be abused by mass assignment.
    model_config = ConfigDict(extra="forbid")

    email: Annotated[EmailStr, Field(max_length=254)]
    # A generous transport limit so absurd inputs are rejected cheaply. The real policy
    # (15-256 characters after normalization) lives in passwords.py: one source of truth.
    password: Annotated[str, Field(min_length=1, max_length=1024)]


class UserOut(BaseModel):
    """What the API returns about a user. Built explicitly, never from a DB row."""

    id: UUID
    email: str


def _to_out(user: User | users.UserCredentials) -> UserOut:
    return UserOut(id=user.id, email=user.email)


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: Credentials, pool: DbPool) -> UserOut:
    """Create an account. Does not log the user in.

    Known gap (fixed in Phase 2): 409 for an existing email reveals that the account
    exists. The fix is email verification, where every signup gets the same "check your
    inbox" response and the existing owner gets a notice instead.
    """
    try:
        # Hash BEFORE borrowing a DB connection: never hold a connection during slow work.
        password_hash = hash_password(body.password)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None

    try:
        # Leaving the `with` block commits, BEFORE we respond, so we never tell the client
        # "created" for a row that could still be rolled back.
        with pool.connection() as conn:
            user = users.create_user(conn, body.email, password_hash)
    except users.EmailAlreadyRegisteredError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An account with this email already exists."
        ) from None
    return _to_out(user)


@router.post("/login")
def login(
    body: Credentials,
    request: Request,
    response: Response,
    pool: DbPool,
    sessions: Sessions,
    settings: AppSettings,
) -> UserOut:
    with pool.connection() as conn:
        creds = users.get_credentials_by_email(conn, body.email)
    # The connection is back in the pool before the ~100 ms Argon2 work below.

    if creds is None:
        # Same Argon2 work as a real check, same error. Timing and message both look
        # identical to a wrong password (see passwords.verify_password_for_unknown_user).
        verify_password_for_unknown_user(body.password)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    result = verify_password(creds.password_hash, body.password)
    if not result.ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    if result.upgraded_hash:
        with pool.connection() as conn:
            users.update_password_hash(conn, creds.id, result.upgraded_hash)

    # Login is a trust boundary. Whatever session cookie arrived with this request might
    # have been planted by an attacker (session fixation / swapping), so destroy it and
    # start clean. Never rotate() here: rotate() would carry over the old session's data.
    secure = settings.session_cookie_secure
    sessions.destroy(read_session_token(request, secure=secure))
    token = sessions.create(str(creds.id))
    set_session_cookie(response, token, secure=secure)
    return _to_out(creds)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, sessions: Sessions, settings: AppSettings) -> Response:
    """End the session on the SERVER, then clear the cookie.

    Clearing only the cookie would not be a logout: anyone who copied the token could
    keep using it. Deleting the Redis key makes the token worthless everywhere.
    Always 204, even with no session, so logout is safe to call repeatedly.
    """
    secure = settings.session_cookie_secure
    sessions.destroy(read_session_token(request, secure=secure))
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookie(response, secure=secure)
    return response


@router.get("/me")
def me(user: CurrentUser) -> UserOut:
    return _to_out(user)
