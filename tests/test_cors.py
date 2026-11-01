from fastapi.testclient import TestClient

FRONTEND = "https://front1.cluster.local:8443"  # the default of cors_origins


def preflight(client: TestClient, origin: str) -> dict[str, str]:
    """What the browser asks before its POST of the login form."""
    response = client.options(
        "/oauth2/user/token",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    return dict(response.headers)


def test_the_frontend_may_call_the_service(client: TestClient) -> None:
    assert preflight(client, FRONTEND)["access-control-allow-origin"] == FRONTEND
    response = client.get("/health", headers={"Origin": FRONTEND})
    assert response.headers["access-control-allow-origin"] == FRONTEND


def test_another_origin_may_not(client: TestClient) -> None:
    assert "access-control-allow-origin" not in preflight(
        client, "https://evil.example"
    )
