import pytest
from fastapi import FastAPI
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from daas_auth.models import User


def test_sqlite_refuses_deleting_a_user_that_still_has_a_role(app: FastAPI) -> None:
    # The seeded admin holds a row in user_roles, which has no ON DELETE.
    with Session(app.state.engine) as session, pytest.raises(IntegrityError):
        session.execute(delete(User))
        session.flush()
