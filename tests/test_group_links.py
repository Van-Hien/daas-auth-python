from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog, DesktopGroupUserGroup

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]


def groups(client: TestClient, admin: dict[str, str]) -> tuple[int, int]:
    """
    A desktop group and a user group with different ids, so that a link with its
    two columns swapped cannot pass (R-3).
    """
    client.post("/user_group", json={"description": "spare"}, headers=admin)
    user_group = client.post("/user_group", json={"description": "u"}, headers=admin)
    desktop_group = client.post(
        "/desktop_group", json={"description": "d"}, headers=admin
    )
    return desktop_group.json()["id"], user_group.json()["id"]


def test_a_user_group_link_is_stored_once(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    dg, ug = groups(client, admin)
    assert dg != ug
    # The suite's row 21. PHP answers this and stores nothing (R-6).
    path = f"/desktop_group/{dg}/user_group/{ug}"
    response = client.post(path, json={}, headers=admin)
    assert (response.status_code, response.json()) == (
        200,
        [{"id": ug, "description": "u"}],
    )
    with Session(app.state.engine) as session:
        links = session.scalars(select(DesktopGroupUserGroup)).all()
        assert [(link.desktop_group_id, link.user_group_id) for link in links] == [
            (dg, ug)
        ]
        log = session.scalars(
            select(ActivityLog).order_by(ActivityLog.id.desc())
        ).first()
        assert log is not None
        assert (log.action, log.target_id, log.details) == (
            "desktop_group_update",
            dg,
            f"user group {ug} added",
        )
    again = client.post(path, json={}, headers=admin)
    assert (again.status_code, again.headers["content-type"]) == (409, PROBLEM)


def test_php_s_second_route_to_the_same_link(
    client: TestClient, admin: dict[str, str]
) -> None:
    dg, ug = groups(client, admin)
    response = client.post(f"/user_group/{ug}/{dg}", json={}, headers=admin)
    assert (response.status_code, response.json()) == (
        200,
        [{"id": dg, "description": "d", "desktopIds": []}],
    )
    # One link, whichever route made it.
    again = client.post(f"/desktop_group/{dg}/user_group/{ug}", headers=admin)
    assert again.status_code == 409
    missing = client.post(f"/user_group/{ug}/999", headers=admin)
    assert (missing.status_code, missing.headers["content-type"]) == (404, PROBLEM)


def test_a_user_group_link_is_removed(
    client: TestClient, admin: dict[str, str]
) -> None:
    dg, ug = groups(client, admin)
    path = f"/desktop_group/{dg}/user_group/{ug}"
    client.post(path, headers=admin)
    removed = client.delete(path, headers=admin)
    assert (removed.status_code, removed.json()) == (200, [])
    gone = client.delete(path, headers=admin)
    assert (gone.status_code, gone.headers["content-type"]) == (404, PROBLEM)


def test_a_desktop_goes_into_a_group_and_out_again(
    client: TestClient, admin: dict[str, str]
) -> None:
    dg, _ = groups(client, admin)
    desktop = client.post("/desktop", json={"description": "x"}, headers=admin).json()
    path = f"/desktop_group/{dg}/desktop/{desktop['id']}"
    added = client.post(path, headers=admin)
    assert (added.status_code, added.json()["desktopIds"]) == (200, [desktop["id"]])
    assert client.post(path, headers=admin).status_code == 409
    shown = client.get(f"/desktop/{desktop['id']}", headers=admin).json()
    assert shown["groups"] == [dg]

    removed = client.delete(path, headers=admin)
    assert (removed.status_code, removed.json()["desktopIds"]) == (200, [])
    gone = client.delete(path, headers=admin)
    assert (gone.status_code, gone.headers["content-type"]) == (404, PROBLEM)


def test_refusals_of_the_links(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    dg, ug = groups(client, admin)
    for path in (
        f"/desktop_group/999/user_group/{ug}",
        f"/desktop_group/{dg}/user_group/999",
        f"/desktop_group/{dg}/desktop/999",
        "/desktop_group/999/desktop/1",
    ):
        response = client.post(path, headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            404,
            PROBLEM,
        ), path
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    for method, path in (
        ("POST", f"/desktop_group/{dg}/user_group/{ug}"),
        ("DELETE", f"/desktop_group/{dg}/user_group/{ug}"),
        ("POST", f"/user_group/{ug}/{dg}"),
        ("POST", f"/desktop_group/{dg}/desktop/1"),
        ("DELETE", f"/desktop_group/{dg}/desktop/1"),
    ):
        assert client.request(method, path, headers=user).status_code == 403
