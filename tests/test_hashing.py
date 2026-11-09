"""
Logins hash on 4 threads of their own, never on anyio's shared pool.

Each thread that hashes keeps its freed 19 MiB Argon2 buffer for reuse. The
shared pool replaces idle threads with new ones, so hashing there made the
memory grow with every new thread; 4 threads that stay cap it at 4 buffers.
"""

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from daas_auth.api.routes import oauth
from daas_auth.domain.grants import token_response

PARALLEL = 8


def test_logins_hash_on_four_threads_of_their_own(
    app: FastAPI, admin_login: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    hashed_on: set[str] = set()
    real: Callable[..., Any] = token_response

    def recording(*args: Any, **kwargs: Any) -> Any:
        hashed_on.add(threading.current_thread().name)
        return real(*args, **kwargs)

    monkeypatch.setattr(oauth, "token_response", recording)
    with TestClient(app) as client:

        def login(_: int) -> int:
            return client.post("/oauth2/user/token", data=admin_login).status_code

        with ThreadPoolExecutor(max_workers=PARALLEL) as threads:
            statuses = list(threads.map(login, range(PARALLEL)))

    assert statuses == [200] * PARALLEL
    assert hashed_on, "no login reached the hash"
    assert all(name.startswith("hashing") for name in hashed_on), hashed_on
    assert len(hashed_on) <= 4
