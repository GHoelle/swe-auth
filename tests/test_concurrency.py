"""Availability tests under concurrent load, against a REAL uvicorn server.

These reproduce the deadlock found by the security review: holding a DB connection in a
FastAPI `yield` dependency while the handler waits for a second worker thread. The
TestClient can't show this, because the problem only appears when many requests share
one event loop's thread pool. So we start uvicorn in a background thread, with the thread
pool shrunk to 4 and the DB pool to 2 so the problem shows up with a few dozen requests.
"""

import asyncio
import socket
import threading
import time

import anyio
import fakeredis
import httpx
import pytest
import uvicorn
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from app.config import Settings
from app.main import create_app
from app.security.sessions import SessionStore

ALICE = {"email": "alice@example.com", "password": "correct horse battery staple"}
WORKER_THREADS = 4
DB_POOL_SIZE = 2
REQUESTS = 30


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(_schema, test_database_url):
    pool = ConnectionPool(
        test_database_url,
        min_size=1,
        max_size=DB_POOL_SIZE,
        timeout=3,
        kwargs={"row_factory": dict_row},
        open=False,
    )
    pool.open(wait=True, timeout=10)
    with pool.connection() as conn:
        conn.execute("TRUNCATE users")

    settings = Settings(
        environment="test",
        database_url="postgresql://unused",
        redis_url="redis://unused",
        session_cookie_secure=False,  # plain http in this test; cookie is named "session"
    )
    app = create_app(settings)
    app.state.db_pool = pool
    app.state.redis = fakeredis.FakeRedis(decode_responses=True)
    app.state.sessions = SessionStore(
        app.state.redis, idle_timeout_seconds=1800, absolute_timeout_seconds=43200
    )

    # Test-only endpoint that parks a worker thread until released.
    entered = threading.Semaphore(0)
    release = threading.Event()

    @app.get("/_test/occupy-worker-thread")
    def occupy_worker_thread() -> dict[str, str]:
        entered.release()
        release.wait(timeout=15)
        return {"status": "released"}

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, lifespan="off", log_level="critical")
    )

    async def serve() -> None:
        anyio.to_thread.current_default_thread_limiter().total_tokens = WORKER_THREADS
        await server.serve()

    thread = threading.Thread(target=asyncio.run, args=(serve(),), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            pytest.fail("uvicorn did not start")
        time.sleep(0.05)

    try:
        yield f"http://127.0.0.1:{port}", entered, release
    finally:
        release.set()

    server.should_exit = True
    thread.join(timeout=10)
    pool.close()


def _flood(base_url: str, path: str, cookies: dict[str, str] | None = None) -> tuple[list, float]:
    statuses: list[int | str] = []
    lock = threading.Lock()

    def hit() -> None:
        try:
            with httpx.Client(base_url=base_url, cookies=cookies, timeout=15) as client:
                code: int | str = client.get(path).status_code
        except httpx.HTTPError as exc:
            code = type(exc).__name__
        with lock:
            statuses.append(code)

    threads = [threading.Thread(target=hit) for _ in range(REQUESTS)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return statuses, time.monotonic() - start


def test_concurrent_authenticated_requests_do_not_deadlock(live_server):
    live_server, _, _ = live_server
    with httpx.Client(base_url=live_server) as client:
        assert client.post("/auth/register", json=ALICE).status_code == 201
        token = client.post("/auth/login", json=ALICE).cookies["session"]

    statuses, elapsed = _flood(live_server, "/auth/me", cookies={"session": token})

    assert statuses == [200] * REQUESTS, statuses
    assert elapsed < 8, f"took {elapsed:.1f}s; requests are queueing behind a deadlock"


def test_unauthenticated_flood_never_touches_the_database(live_server):
    live_server, _, _ = live_server
    statuses, elapsed = _flood(live_server, "/auth/me")
    assert statuses == [401] * REQUESTS, statuses
    assert elapsed < 8


def test_liveness_answers_even_when_every_worker_thread_is_busy(live_server):
    base_url, entered, release = live_server

    def occupy() -> None:
        httpx.get(f"{base_url}/_test/occupy-worker-thread", timeout=20)

    occupiers = [threading.Thread(target=occupy) for _ in range(WORKER_THREADS)]
    for t in occupiers:
        t.start()
    for _ in range(WORKER_THREADS):  # wait until ALL worker threads are parked
        assert entered.acquire(timeout=10)

    try:
        start = time.monotonic()
        resp = httpx.get(f"{base_url}/health", timeout=5)
        elapsed = time.monotonic() - start
    finally:
        release.set()
        for t in occupiers:
            t.join()

    assert resp.status_code == 200
    assert elapsed < 1, f"/health took {elapsed:.1f}s; it must not need a worker thread"
