"""
The JSON shapes the API answers with, as PHP sends them.
A ...Public model is what a client is shown, not a route without a token.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from daas_auth.domain.accounts import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from daas_auth.models import Desktop, User


class PublicModel(BaseModel):
    # read the fields off an ORM object: AdminPublic.model_validate(user)
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


class DesktopPublic(PublicModel):
    id: int
    description: str
    groups: list[int]  # the desktop groups it is in
    name: str | None
    quart_object_id: str | None

    @classmethod
    def of(cls, desktop: Desktop, groups: list[int]) -> "DesktopPublic":
        # groups is not an attribute of Desktop, so it is passed in
        return cls(
            id=desktop.id,
            description=desktop.description,
            groups=groups,
            name=desktop.name,
            quart_object_id=desktop.quart_object_id,
        )


class DesktopGroupPublic(PublicModel):
    id: int
    description: str
    # PHP's name in the JSON; built as DesktopGroupPublic(..., desktopIds=[...])
    desktop_ids: list[int] = Field(alias="desktopIds")


class Message(BaseModel):
    # PHP's answer where it sends no object, as {"message": ...}
    message: str


Name = Annotated[str, Field(min_length=1, max_length=255)]
# Spaces at the ends are cut off; a description of only spaces is 400, as in PHP.
Description = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
]
QuartObjectId = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
]
Password = Annotated[
    str, Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
]


class RequestModel(BaseModel):
    # A field the route doesn't know is 400, never silently dropped.
    model_config = ConfigDict(extra="forbid")


class UserCreate(RequestModel):
    name: Name
    email: EmailStr
    password: Password
    groups: list[int] = Field(default_factory=list)


class UserUpdate(RequestModel):
    # Every field may be left out; the frontend sends name and email.
    name: Name | None = None
    email: EmailStr | None = None
    password: Password | None = None
    groups: list[int] | None = None


class AdminCreate(RequestModel):
    name: Name
    email: EmailStr
    password: Password


class RegistrationCode(RequestModel):
    email: EmailStr
    registration_code: Annotated[str, Field(min_length=8)]  # PHP's length


class UserGroupCreate(RequestModel):
    description: Description


class UserGroupUpdate(RequestModel):
    # PATCH: only what is sent changes. The dashboard sends the description only.
    description: Description | None = None
    # PHP's name. Replaces the members when sent.
    user_ids: list[int] | None = Field(default=None, alias="userIds")


class DesktopCreate(RequestModel):
    description: Description
    # Desktop-group ids. The dashboard sends objects ([{description}]): 400.
    groups: list[int] = Field(default_factory=list)
    name: Name | None = None
    quart_object_id: QuartObjectId | None = None


class DesktopUpdate(RequestModel):
    # PATCH: only what is sent changes. groups replaces the desktop groups.
    description: Description | None = None
    groups: list[int] | None = None
    name: Name | None = None
    quart_object_id: QuartObjectId | None = None


class DesktopGroupCreate(RequestModel):
    description: Description
    # PHP declared it and dropped it; here the desktops are stored.
    desktop_ids: list[int] = Field(default_factory=list, alias="desktopIds")
