"""
The JSON shapes the API answers with, as PHP sends them.
A ...Public model is what a client is shown, not a route without a token.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from daas_auth.models import User


class PublicModel(BaseModel):
    # read the fields off an ORM object: AdminResponseDto.model_validate(user)
    model_config = ConfigDict(from_attributes=True)


class UserPublic(PublicModel):
    id: int
    name: str
    email: str
    role: Literal["user"] = "user"
    groups: list[int]
    enabled: bool

    @classmethod
    def of(cls, user: User, groups: list[int]) -> "UserPublic":
        # groups is not an attribute of User, so it is passed in
        return cls(
            id=user.id,
            name=user.name,
            email=user.email,
            groups=groups,
            enabled=user.enabled,
        )


class AdminPublic(PublicModel):
    id: int
    name: str
    email: str
    # User has no role attribute, so the default applies
    role: Literal["admin"] = "admin"


class UserGroupPublic(PublicModel):
    id: int
    description: str
