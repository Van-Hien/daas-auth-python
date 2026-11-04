"""
Desktop groups: which desktops belong together, and which user groups may use them.

Every change stamps the audit columns and writes one activity_log row; the route commits.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from daas_auth.domain.errors import Refused, refuse_unknown
from daas_auth.models import DesktopGroup


def find_desktop_group(session: Session, group_id: int) -> DesktopGroup:
    group = session.get(DesktopGroup, group_id)
    if group is None:
        raise Refused(404, f"No desktop group has the id {group_id}.")
    return group


def known_desktop_groups(session: Session, ids: list[int]) -> list[int]:
    """The ids once each, or 400: a group that doesn't exist is never dropped."""
    wanted = sorted(set(ids))
    known = set(
        session.scalars(select(DesktopGroup.id).where(DesktopGroup.id.in_(wanted)))
    )
    refuse_unknown(wanted, known, "desktop group")
    return wanted
