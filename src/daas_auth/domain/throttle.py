"""
The login limit: too many guesses from one address, or at one account, and the
next attempt is refused before a password is hashed.

The attempts are already in activity_log, so the limit needs no table of its own,
and a restart does not reset it.
"""

from datetime import datetime, timedelta
from math import ceil

from sqlalchemy import func, select
from sqlalchemy.orm import InstrumentedAttribute, Session

from daas_auth.domain.activity import Action, record
from daas_auth.domain.errors import Refused
from daas_auth.models import ActivityLog

WINDOW = timedelta(minutes=15)
MAX_PER_ADDRESS = 30  # a person who mistypes stays far below this
MAX_PER_ACCOUNT = 100  # higher: anyone who knows the email can spend this limit
# What a guess leaves behind. A right password on a disabled account is no guess,
# and a refused attempt never counts, or waiting would not end the refusal.
GUESSES = ("unknown_user", "wrong_password")


def refuse_if_throttled(
    session: Session, *, email: str | None, source_ip: str | None, now: datetime
) -> None:
    """One activity_log row for each refusal, committed here: the request ends now."""
    limits = (
        (ActivityLog.source_ip, source_ip, MAX_PER_ADDRESS),
        (ActivityLog.actor_email, email, MAX_PER_ACCOUNT),
    )
    for column, value, limit in limits:
        if value is None:
            continue
        count, oldest = _guesses(session, column, value, now)
        if count >= limit:
            record(
                session,
                Action.LOGIN,
                ok=False,
                now=now,
                reason="throttled",
                actor_email=email,
                source_ip=source_ip,
            )
            session.commit()
            # The oldest guess leaves the window first, and one place is free again.
            wait = (oldest + WINDOW - now).total_seconds()
            raise Refused(
                429,
                "Too many failed logins. Try again later.",
                headers={"Retry-After": str(ceil(wait))},
            )


def _guesses(
    session: Session,
    column: InstrumentedAttribute[str | None],
    value: str,
    now: datetime,
) -> tuple[int, datetime]:
    row = session.execute(
        select(func.count(), func.min(ActivityLog.created_at)).where(
            column == value,
            ActivityLog.created_at > now - WINDOW,
            ActivityLog.action == Action.LOGIN,
            ActivityLog.reason.in_(GUESSES),
        )
    ).one()
    return row[0], row[1]
