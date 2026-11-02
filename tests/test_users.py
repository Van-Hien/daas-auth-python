from collections.abc import Callable

from fastapi.testclient import TestClient

from daas_auth.domain.passwords import hash_password

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]


def test_get_a_user(
    client: TestClient, admin: dict[str, str], add_user: Callable[..., int]
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"), enabled=False)
    response = client.get(f"/user/{anna}", headers=admin)
    assert response.status_code == 200
    assert response.json() == {
        "id": anna,
        "name": "anna",
        "email": "anna@x.de",
        "role": "user",
        "groups": [],
        "enabled": False,
    }


def test_an_admins_id_gives_the_admin(
    client: TestClient, admin: dict[str, str]
) -> None:
    me = client.get("/oauth2/user/session", headers=admin).json()["user_id"]
    assert client.get(f"/user/{me}", headers=admin).json() == {
        "id": me,
        "name": "Admin",
        "email": "admin@x.de",
        "role": "admin",
    }


def test_a_user_token_cannot_get_a_user(
    client: TestClient, login: Login, add_user: Callable[..., int]
) -> None:
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    response = client.get(
        f"/user/{anna}", headers=login("anna@x.de", "anna-pw-1", "user")
    )
    assert (response.status_code, response.json()["error"]) == (
        403,
        "insufficient_scope",
    )


def test_an_unknown_id_is_404_problem(
    client: TestClient, admin: dict[str, str]
) -> None:
    response = client.get("/user/999", headers=admin)
    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM
    assert response.json()["detail"] == "No account has the id 999."
