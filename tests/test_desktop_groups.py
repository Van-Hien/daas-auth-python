from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import DesktopGroupUserGroup, UserGroup

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]


def test_both_spellings_create_a_desktop_group(
    client: TestClient, admin: dict[str, str]
) -> None:
    desktop = client.post("/desktop", json={"description": "d"}, headers=admin).json()
    created = []
    # The suite's row 20: the frontend's path, then the one PHP declared (F-3).
    for path in ("/desktop_group", "/desktop-group"):
        body = {"description": path, "desktopIds": [desktop["id"]]}
        response = client.post(path, json=body, headers=admin)
        assert response.status_code == 200
        created.append(response.json())
    assert [g["desktopIds"] for g in created] == [[desktop["id"]]] * 2
    # Row 19, and the desktop shows both groups.
    assert client.get("/desktop_groups", headers=admin).json() == created
    shown = client.get(f"/desktop/{desktop['id']}", headers=admin).json()
    assert shown["groups"] == [g["id"] for g in created]
    one = client.get(f"/desktop_group/{created[0]['id']}", headers=admin)
    assert one.json() == created[0]


def test_refusals_of_desktop_groups(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    for body, status in (
        ({"description": "x", "desktopIds": [999]}, 422),  # never dropped (R-3)
        ({"description": " "}, 400),
    ):
        response = client.post("/desktop_group", json=body, headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            status,
            PROBLEM,
        ), body

    for response in (
        client.get("/desktop_group/999", headers=admin),
        client.delete("/desktop_group/999", headers=admin),
    ):
        assert (response.status_code, response.headers["content-type"]) == (
            404,
            PROBLEM,
        )
    group = client.post("/desktop_group", json={"description": "x"}, headers=admin)
    group_id = group.json()["id"]
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    for response in (
        client.get("/desktop_groups", headers=user),
        client.post("/desktop_group", json={"description": "x"}, headers=user),
        client.get(f"/desktop_group/{group_id}", headers=user),
        client.delete(f"/desktop_group/{group_id}", headers=user),
    ):
        assert response.status_code == 403


def test_deleting_a_desktop_group_keeps_desktops_and_user_groups(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    desktop = client.post("/desktop", json={"description": "d"}, headers=admin).json()
    group = client.post(
        "/desktop_group",
        json={"description": "x", "desktopIds": [desktop["id"]]},
        headers=admin,
    ).json()
    now = datetime(2026, 11, 3)
    with Session(app.state.engine) as session:
        session.add(UserGroup(id=7, description="u", created_at=now, updated_at=now))
        session.flush()  # no relationship orders the inserts, so the group first
        session.add(
            DesktopGroupUserGroup(
                desktop_group_id=group["id"],
                user_group_id=7,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()

    response = client.delete(f"/desktop_group/{group['id']}", headers=admin)
    assert (response.status_code, response.json()) == (200, "Desktop group deleted")
    assert client.get(f"/desktop/{desktop['id']}", headers=admin).json()["groups"] == []
    assert client.get("/user_groups", headers=admin).json() == [
        {"id": 7, "description": "u"}
    ]
    with Session(app.state.engine) as session:
        assert session.scalars(select(DesktopGroupUserGroup)).all() == []
