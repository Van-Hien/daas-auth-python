from fastapi.testclient import TestClient

from daas_auth.api.app import create_app
from daas_auth.config import Settings


def test_health_returns_ok() -> None:
    app = create_app(Settings(database_url="sqlite://"))
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_docs_are_not_public() -> None:
    client = TestClient(create_app(Settings(database_url="sqlite://")))
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
