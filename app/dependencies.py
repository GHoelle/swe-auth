"""Shared FastAPI dependencies for authenticated endpoints."""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from psycopg_pool import ConnectionPool

from app.config import Settings
from app.db import get_pool
from app.repositories import users
from app.repositories.users import User
from app.security.cookies import read_session_token
from app.security.sessions import SessionStore, get_session_store

NOT_AUTHENTICATED = "Not authenticated."


async def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


# Reusable dependency types. A route that declares `pool: DbPool` gets the connection pool
# and borrows a connection only for the lines that need it (see app/db.py for why).
DbPool = Annotated[ConnectionPool, Depends(get_pool)]
Sessions = Annotated[SessionStore, Depends(get_session_store)]
AppSettings = Annotated[Settings, Depends(get_app_settings)]


def get_current_user(
    request: Request, pool: DbPool, sessions: Sessions, settings: AppSettings
) -> User:
    """Resolve the logged-in user from the session cookie, or respond 401.

    Every failure (no cookie, garbage cookie, expired session, deleted account) gets the
    same 401 with the same message. The client learns nothing about WHY it failed.
    """
    token = read_session_token(request, secure=settings.session_cookie_secure)
    session = sessions.get(token)
    if session is None:
        # Rejected using Redis alone. Unauthenticated traffic never touches the database.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, NOT_AUTHENTICATED)

    with pool.connection() as conn:
        user = users.get_user_by_id(conn, session.user_id)
    if user is None:
        # The account was deleted while the session was still alive. Kill the orphaned
        # session so it can't be used again if a user with that ID ever reappears.
        sessions.destroy(token)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, NOT_AUTHENTICATED)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
