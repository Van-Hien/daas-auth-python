from collections.abc import Callable

from fastapi.testclient import TestClient

from daas_auth.domain.passwords import hash_password

PROBLEM = "application/problem+json"


def test_every_function_is_refused_with_a_400_problem(
    client: TestClient, admin: dict[str, str]
) -> None:
    response = client.get("/permissions/debug/1", headers=admin)
    assert response.status_code == 400
    assert response.headers["content-type"] == PROBLEM
    assert response.json()["detail"] == "No permission is defined for 'debug'."


def test_a_user_token_gets_403(
    client: TestClient,
    add_user: Callable[..., int],
    login: Callable[..., dict[str, str]],
) -> None:
    add_user("anna@x.de", hash_password("anna-pw-1"))
    headers = login("anna@x.de", "anna-pw-1", "user")
    assert client.get("/permissions/debug/1", headers=headers).status_code == 403


def test_no_token_gets_401(client: TestClient) -> None:
    assert client.get("/permissions/debug/1").status_code == 401
