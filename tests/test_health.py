from fastapi.testclient import TestClient

from daas_auth.api.app import create_app
from daas_auth.config import Settings


def test_health_returns_ok() -> None:
    app = create_app(Settings(database_url="sqlite://"))
    # "with" runs the app's start and shutdown, so the engine is closed afterwards.
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_docs_are_not_public() -> None:
    with TestClient(create_app(Settings(database_url="sqlite://"))) as client:
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path).status_code == 404
