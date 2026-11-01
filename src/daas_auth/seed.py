"""
Fill an empty database with the first admin data and test-client (`daas-auth seed`).
"""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from daas_auth.domain.emails import normalise_email
from daas_auth.domain.passwords import hash_password
from daas_auth.models import ActivityLog, OAuth2Client, Role, User, UserRole


class SeedRefused(Exception):
    """
    The database already has users or clients, so nothing was written.
    """


def seed_database(session: Session, *, email: str, name: str, password: str) -> int:
    """
    Create the admin and test-client in one transaction. Returns the admin's id.
    """
    for model in (User, OAuth2Client):
        if session.scalar(select(func.count()).select_from(model)):
            raise SeedRefused(f"{model.__tablename__} is not empty")
    # One time for every row, so created_at = updated_at (d). _by stays NULL:
    # nobody is logged in; the activity_log rows say what happened.
    now = datetime.now(UTC).replace(tzinfo=None)
    admin = User(
        guid=str(uuid4()),
        name=name,
        email=normalise_email(email),
        password=hash_password(password),
        enabled=True,
        created_at=now,
        updated_at=now,
    )
    session.add(admin)
    # flush sends the INSERT
    session.flush()
    admin_role = session.scalars(select(Role).where(Role.name == "admin")).one()
    session.add(
        UserRole(
            user_id=admin.id, role_id=admin_role.id, created_at=now, updated_at=now
        )
    )
    # The same values as PHP's row: a public client, no secret, no redirect URIs.
    session.add(
        OAuth2Client(
            identifier="test-client",
            version=1,
            name="DESIGN Frontend",
            redirect_uris="[]",
            is_confidential=False,
            created_at=now,
            updated_at=now,
        )
    )
    for table, target_id, details in (
        ("users", admin.id, None),
        ("oauth2_clients", None, "test-client"),
    ):
        session.add(
            ActivityLog(
                action="seed",
                result="ok",
                target_table=table,
                target_id=target_id,
                details=details,
                created_at=now,
                updated_at=now,
            )
        )
    session.commit()
    return admin.id
