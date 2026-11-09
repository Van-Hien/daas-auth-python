"""
Many parallel requests on a small connection pool: none may wait until the pool gives up.

A request gets its database session and runs its route in worker threads, one
step after the other. A thread that waits for a connection keeps its worker
slot; a request that already has a connection may need a worker slot for its
next step. With more requests than worker slots plus connections, both sides
can wait for each other until the pool times out, and the requests fail with 500.
"""

from concurrent.futures import ThreadPoolExecutor

import anyio
import anyio.to_thread
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient

PARALLEL = 20


def few_worker_threads() -> None:
    # Runs inside the client's event loop: the limit is per loop.
    anyio.to_thread.current_default_thread_limiter().total_tokens = 2


def test_parallel_session_checks_on_a_small_pool(
    app: FastAPI, admin_login: dict[str, str]
) -> None:
    # One connection and two worker threads: the smallest setup in which the
    # wait above can happen. pool_timeout 2 s instead of 30 s keeps a failure short.
    url = app.state.engine.url
    app.state.engine.dispose()
    app.state.engine = sa.create_engine(
        url, pool_pre_ping=True, pool_size=1, max_overflow=0, pool_timeout=2
    )
    app.state.db_slots = anyio.CapacityLimiter(1)  # as many slots as connections

    # One event loop for all requests, as in uvicorn. A failed request comes back
    # as 500 instead of raising in the test.
    with TestClient(app, raise_server_exceptions=False) as client:
        client.portal.call(few_worker_threads)  # type: ignore[union-attr]
        login = client.post("/oauth2/user/token", data=admin_login)
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        def check(_: int) -> int:
            return client.get("/oauth2/user/session", headers=headers).status_code

        # PARALLEL threads, each waiting for its answer: PARALLEL requests at once
        with ThreadPoolExecutor(max_workers=PARALLEL) as threads:
            statuses = list(threads.map(check, range(PARALLEL)))

    assert statuses == [200] * PARALLEL
