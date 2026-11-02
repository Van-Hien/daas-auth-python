"""
Users and admins:
The accounts the admin dashboard reads, creates, changes and deletes.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.errors import Refused
from daas_auth.models import Role, User, UserRole, UserToUserGroup

# The ids of the accounts that hold the admin role.
ADMINS = select(UserRole.user_id).join(Role).where(Role.name == "admin")


def is_admin(session: Session, user_id: int) -> bool:
    return session.scalar(ADMINS.where(UserRole.user_id == user_id)) is not None


def find_account(session: Session, user_id: int) -> User:
    """
    A user or an admin.
    """
    account = session.get(User, user_id)
    if account is None:
        raise Refused(404, f"No account has the id {user_id}.")
    return account


def group_ids(session: Session, user_id: int) -> list[int]:
    return list(
        session.scalars(
            select(UserToUserGroup.user_group_id)
            .where(UserToUserGroup.user_id == user_id)
            .order_by(UserToUserGroup.user_group_id)
        )
    )
