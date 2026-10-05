"""PostgreSQL connection pool (psycopg 3).

RULE 1: every query passes user data as parameters, never by building SQL strings.

    GOOD: conn.execute("SELECT * FROM users WHERE email = %s", (email,))
    BAD:  conn.execute(f"SELECT * FROM users WHERE email = '{email}'")

With parameters, psycopg sends the SQL and the values to Postgres separately,
so a value like  ' OR '1'='1  is just a weird email, never part of the query.
Ruff's bandit rule S608 flags string-built SQL.

RULE 2: borrow a connection INSIDE the handler, for as short a time as possible.

    with pool.connection() as conn:
        user = users.get_user_by_id(conn, user_id)
    # connection is back in the pool here, before any slow work

LESSON (found by the independent security review): the first version used a FastAPI
`yield` dependency that handed each request a connection. Sync dependencies and sync
handlers run in a shared pool of ~40 worker threads, and a yield dependency and its
handler run in DIFFERENT threads. Under load, all 40 threads ended up blocked waiting
for a DB connection, while the requests that already HAD connections couldn't get a
thread to run on. Nothing moved until the 30 s pool timeout, and even /health hung.
Roughly 50 concurrent unauthenticated requests were enough to freeze the server.

Borrowing the connection inside the handler means the thread that waits for a
connection is the same thread that uses it, so that deadlock can't form. We also:
    - never hold a connection during Argon2 hashing (~100 ms),
    - check the session in Redis before touching the database,
    - use a short pool timeout, so exhaustion becomes a fast 503 instead of a hang.
"""

from fastapi import Request
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

POOL_TIMEOUT_SECONDS = 5.0


def create_pool(
    dsn: str, *, max_size: int = 10, timeout: float = POOL_TIMEOUT_SECONDS
) -> ConnectionPool:
    pool = ConnectionPool(
        conninfo=dsn,
        min_size=1,
        max_size=max_size,
        # How long pool.connection() waits for a free connection before raising
        # PoolTimeout. The app turns that into HTTP 503 (see main.py).
        timeout=timeout,
        kwargs={"row_factory": dict_row},
        open=False,
    )
    # Wait for a real connection so a bad DATABASE_URL fails at startup, not on the first request.
    pool.open(wait=True, timeout=10)
    return pool


async def get_pool(request: Request) -> ConnectionPool:
    """FastAPI dependency. `async def` on purpose: it does no I/O, and FastAPI runs sync
    dependencies in the worker thread pool, which is exactly the resource we're protecting.

    Handlers borrow a connection with `with pool.connection() as conn:`. On leaving the
    block, the pool COMMITS if no exception was raised and ROLLS BACK if one was.
    """
    return request.app.state.db_pool
