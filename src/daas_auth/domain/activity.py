"""
activity_log rows, and the audit columns of every change.
The service only ever inserts into activity_log, through record().
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, StrEnum
from typing import Any

from sqlalchemy.orm import Session

from daas_auth.models import ActivityLog


class Action(StrEnum):
    # S105 takes TOKEN and PASSWORD in a name for a password; these are action names.
    LOGIN = "login"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"  # noqa: S105
    TOKEN_PURGE = "token_purge"  # noqa: S105
    PASSWORD_REHASH = "password_rehash"  # noqa: S105
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_ENABLE = "user_enable"
    USER_DISABLE = "user_disable"
    USER_DELETE = "user_delete"
    ADMIN_CREATE = "admin_create"
    ADMIN_DELETE = "admin_delete"
    APPLICATION_REQUEST = "application_request"
    USER_GROUP_CREATE = "user_group_create"
    USER_GROUP_UPDATE = "user_group_update"
    USER_GROUP_DELETE = "user_group_delete"
    DESKTOP_CREATE = "desktop_create"
    DESKTOP_UPDATE = "desktop_update"
    DESKTOP_DELETE = "desktop_delete"
    DESKTOP_GROUP_CREATE = "desktop_group_create"
    DESKTOP_GROUP_DELETE = "desktop_group_delete"
    DESKTOP_GROUP_UPDATE = "desktop_group_update"


class RevokedReason(str, Enum):
    ROTATED = "rotated"
    LOGOUT = "logout"
    REUSED = "reused"
    PASSWORD_CHANGED = "password changed"  # noqa: S105


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


@dataclass(frozen=True)
class Actor:
    """
    The actor (probably admin) who makes a change,
    for the _by columns and activity_log.
    """

    id: int
    email: str
    source_ip: str | None


def stamp(actor: Actor, now: datetime) -> dict[str, Any]:
    # On insert, updated_* get the same values as created_*.
    return {
        "created_at": now,
        "created_by": actor.id,
        "updated_at": now,
        "updated_by": actor.id,
    }


def log_change(
    session: Session,
    action: Action,
    table: str,
    target_id: int,
    actor: Actor,
    now: datetime,
    details: str | None = None,
) -> None:
    """
    One ok row for a change an actor made to one row of table.
    """
    record(
        session,
        action,
        ok=True,
        now=now,
        actor_id=actor.id,
        actor_email=actor.email,
        target_table=table,
        target_id=target_id,
        source_ip=actor.source_ip,
        details=details,
    )
