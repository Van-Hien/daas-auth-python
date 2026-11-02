"""
activity_log rows. The service only ever inserts there, through record().
"""

from datetime import datetime
from enum import StrEnum

from sqlalchemy.orm import Session

from daas_auth.models import ActivityLog


class Action(StrEnum):
    # S105 takes TOKEN and PASSWORD in a name for a password; these are action names.
    LOGIN = "login"
    TOKEN_REFRESH = "token_refresh"  # noqa: S105
    PASSWORD_REHASH = "password_rehash"  # noqa: S105
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_ENABLE = "user_enable"
    USER_DISABLE = "user_disable"
    USER_DELETE = "user_delete"
    ADMIN_CREATE = "admin_create"
    ADMIN_DELETE = "admin_delete"
    APPLICATION_REQUEST = "application_request"


def record(
    session: Session,
    action: Action,
    *,
    ok: bool,
    now: datetime,
    reason: str | None = None,
    actor_id: int | None = None,
    actor_email: str | None = None,
    target_table: str | None = None,
    target_id: int | None = None,
    source_ip: str | None = None,
    details: str | None = None,
) -> None:
    """Add one row; the caller commits. Never pass a password, hash or token."""
    session.add(
        ActivityLog(
            action=action,
            result="ok" if ok else "failed",
            reason=reason,
            actor_email=actor_email,
            target_table=target_table,
            target_id=target_id,
            source_ip=source_ip,
            details=details,
            created_at=now,
            created_by=actor_id,
            updated_at=now,
            updated_by=actor_id,
        )
    )
