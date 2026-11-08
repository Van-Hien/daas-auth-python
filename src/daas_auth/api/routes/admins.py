from fastapi import APIRouter, Depends
from sqlalchemy import select

from daas_auth.api.dependencies import (
    Acting,
    BreachCheck,
    DbSession,
    Now,
    require_scope,
)
from daas_auth.api.schemas import AdminCreate, AdminPublic
from daas_auth.domain import accounts
from daas_auth.domain.accounts import ADMINS
from daas_auth.models import User

admin_router = APIRouter(dependencies=[Depends(require_scope("admin"))])


@admin_router.post("/admin")
def admin_create(
    body: AdminCreate,
    session: DbSession,
    actor: Acting,
    at: Now,
    check_breaches: BreachCheck,
) -> AdminPublic:
    admin = accounts.create_account(
        session,
        name=body.name,
        email=body.email,
        password=body.password,
        role="admin",
        groups=[],
        check_breaches=check_breaches,
        actor=actor,
        now=at,
    )
    session.commit()
    return AdminPublic.model_validate(admin)


@admin_router.get("/admins")
def admin_list(session: DbSession) -> list[AdminPublic]:
    """
    Every admin, by id.
    """
    admins = session.scalars(select(User).where(User.id.in_(ADMINS)).order_by(User.id))
    return [AdminPublic.model_validate(admin) for admin in admins]


@admin_router.get("/admin/{admin_id}")
def admin_get(admin_id: int, session: DbSession) -> AdminPublic:
    return AdminPublic.model_validate(accounts.find_admin(session, admin_id))


@admin_router.delete("/admin/{admin_id}")
def admin_delete(admin_id: int, session: DbSession, actor: Acting, at: Now) -> str:
    accounts.delete_admin(session, admin_id, actor=actor, now=at)
    session.commit()
    return "admin deleted"  # PHP's answer, a JSON string
