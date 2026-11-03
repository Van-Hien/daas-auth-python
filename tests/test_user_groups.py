from collections.abc import Callable
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog, DesktopGroup, DesktopGroupUserGroup

PROBLEM = "application/problem+json"
Login = Callable[..., dict[str, str]]


def last_action(app: FastAPI) -> tuple[str, str | None, int | None]:
    with Session(app.state.engine) as session:
        row = session.scalars(
            select(ActivityLog).order_by(ActivityLog.id.desc())
        ).first()
        assert row is not None
        return row.action, row.target_table, row.target_id


def test_an_admin_creates_a_user_group(
    app: FastAPI, client: TestClient, admin: dict[str, str]
) -> None:
    # The suite's row 14. Spaces at the ends are cut off.
    response = client.post(
        "/user_group", json={"description": "  Lab A "}, headers=admin
    )
    assert response.status_code == 200
    group = response.json()
    assert group == {"id": group["id"], "description": "Lab A"}
    assert last_action(app) == ("user_group_create", "user_groups", group["id"])
    listed = client.get("/user_groups", headers=admin).json()
    assert group in listed


def test_refusals_of_post_user_group(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    for body in ({"description": "   "}, {}, {"description": "x", "extra": 1}):
        response = client.post("/user_group", json=body, headers=admin)
        assert (response.status_code, response.headers["content-type"]) == (
            400,
            PROBLEM,
        )
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    denied = client.post("/user_group", json={"description": "x"}, headers=user)
    assert denied.status_code == 403


def test_patch_changes_the_description_and_the_members(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    group = client.post("/user_group", json={"description": "a"}, headers=admin)
    group_id = group.json()["id"]
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    bob = add_user("bob@x.de", hash_password("bob-pw-1"))

    # The suite's row 15: the dashboard sends the description only.
    renamed = client.patch(
        f"/user_group/{group_id}", json={"description": "b"}, headers=admin
    )
    assert renamed.json() == {"id": group_id, "description": "b"}
    assert last_action(app) == ("user_group_update", "user_groups", group_id)

    # PHP's userIds replaces the members.
    for members in ([anna, bob], [bob]):
        response = client.patch(
            f"/user_group/{group_id}", json={"userIds": members}, headers=admin
        )
        assert response.status_code == 200
        users = client.get("/users", headers=admin).json()
        assert sorted(u["id"] for u in users if group_id in u["groups"]) == members


def test_refusals_of_patch_user_group(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    group_id = client.post(
        "/user_group", json={"description": "a"}, headers=admin
    ).json()["id"]
    me = client.get("/oauth2/user/session", headers=admin).json()["user_id"]
    # A user id that doesn't exist, or an admin's: never dropped, 400.
    for user_ids in ([999], [me]):
        response = client.patch(
            f"/user_group/{group_id}", json={"userIds": user_ids}, headers=admin
        )
        assert (response.status_code, response.headers["content-type"]) == (
            400,
            PROBLEM,
        )
    missing = client.patch("/user_group/999", json={"description": "b"}, headers=admin)
    assert (missing.status_code, missing.headers["content-type"]) == (404, PROBLEM)
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    denied = client.patch(f"/user_group/{group_id}", json={}, headers=user)
    assert denied.status_code == 403


def test_deleting_a_user_group_keeps_its_users_and_desktop_groups(
    app: FastAPI,
    client: TestClient,
    admin: dict[str, str],
    add_user: Callable[..., int],
) -> None:
    group_id = client.post(
        "/user_group", json={"description": "a"}, headers=admin
    ).json()["id"]
    anna = add_user("anna@x.de", hash_password("anna-pw-1"))
    client.patch(f"/user_group/{group_id}", json={"userIds": [anna]}, headers=admin)
    now = datetime(2026, 11, 3)
    with Session(app.state.engine) as session:
        session.add(
            DesktopGroup(id=100, description="d", created_at=now, updated_at=now)
        )
        session.flush()  # no relationship orders the inserts, so the group first
        session.add(
            DesktopGroupUserGroup(
                desktop_group_id=100,
                user_group_id=group_id,
                created_at=now,
                updated_at=now,
            )
        )
        session.commit()

    response = client.delete(f"/user_group/{group_id}", headers=admin)
    assert (response.status_code, response.json()) == (200, "User group deleted")
    assert last_action(app) == ("user_group_delete", "user_groups", group_id)
    assert client.get("/user_groups", headers=admin).json() == []
    anna_now = client.get(f"/user/{anna}", headers=admin).json()
    assert anna_now["groups"] == []
    with Session(app.state.engine) as session:
        assert session.get(DesktopGroup, 100) is not None
        assert session.scalars(select(DesktopGroupUserGroup)).all() == []


def test_refusals_of_delete_user_group(
    client: TestClient,
    admin: dict[str, str],
    login: Login,
    add_user: Callable[..., int],
) -> None:
    missing = client.delete("/user_group/999", headers=admin)
    assert (missing.status_code, missing.headers["content-type"]) == (404, PROBLEM)
    group_id = client.post(
        "/user_group", json={"description": "a"}, headers=admin
    ).json()["id"]
    add_user("bob@x.de", hash_password("bob-pw-1"))
    user = login("bob@x.de", "bob-pw-1", "user")
    assert client.delete(f"/user_group/{group_id}", headers=user).status_code == 403
