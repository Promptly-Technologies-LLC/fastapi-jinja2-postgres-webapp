from logging import getLogger, DEBUG
from enum import Enum
from uuid import uuid4
from datetime import datetime, UTC, timedelta
from typing import Optional, List, Union
from fastapi import HTTPException
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, Enum as SQLAlchemyEnum, LargeBinary
from sqlalchemy.orm import Mapped

logger = getLogger("uvicorn.error")
logger.setLevel(DEBUG)


# --- Helper functions ---


def utc_time():
    return datetime.now(UTC)


# --- Custom exceptions ---


class DataIntegrityError(HTTPException):
    def __init__(
            self,
            resource: str = "Database resource"
    ):
        super().__init__(
            status_code=500,
            detail=(
                f"{resource} is in a broken state; please contact a system administrator"
            )
        )


# --- Database models ---


default_roles = ["Owner", "Administrator", "Member"]


class ValidPermissions(Enum):
    DELETE_ORGANIZATION = "Delete Organization"
    EDIT_ORGANIZATION = "Edit Organization"
    INVITE_USER = "Invite User"
    REMOVE_USER = "Remove User"
    EDIT_USER_ROLE = "Edit User Role"
    CREATE_ROLE = "Create Role"
    DELETE_ROLE = "Delete Role"
    EDIT_ROLE = "Edit Role"


class UserRoleLink(SQLModel, table=True):
    """
    Associates users with roles. This creates a many-to-many relationship
    between users and roles.
    """
    user_id: Optional[int] = Field(foreign_key="user.id", primary_key=True)
    role_id: Optional[int] = Field(foreign_key="role.id", primary_key=True)


class RolePermissionLink(SQLModel, table=True):
    role_id: Optional[int] = Field(foreign_key="role.id", primary_key=True)
    permission_id: Optional[int] = Field(
        foreign_key="permission.id", primary_key=True)


class Permission(SQLModel, table=True):
    """
    Represents a permission that can be assigned to a role. Should not be
    modified unless the application logic and ValidPermissions enum change.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    name: ValidPermissions = Field(
        sa_column=Column(SQLAlchemyEnum(ValidPermissions, create_type=False)))
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    roles: Mapped[List["Role"]] = Relationship(
        back_populates="permissions",
        link_model=RolePermissionLink
    )


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    roles: Mapped[List["Role"]] = Relationship(
        back_populates="organization",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )

    @property
    def users(self) -> List["User"]:
        """
        Returns all users in the organization via their roles.
        """
        users = []
        # Track user IDs to ensure uniqueness
        user_ids = set()
        for role in self.roles:
            for user in role.users:
                if user.id not in user_ids:
                    users.append(user)
                    user_ids.add(user.id)
        return users


class Role(SQLModel, table=True):
    """
    Represents a role within an organization.

    Attributes:
        id: Primary key.
        name: The name of the role.
        organization_id: Foreign key to the associated organization.
        created_at: Timestamp when the role was created.
        updated_at: Timestamp when the role was last updated.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    organization_id: int = Field(
        foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    organization: Mapped[Organization] = Relationship(back_populates="roles")
    users: Mapped[List["User"]] = Relationship(
        back_populates="roles",
        link_model=UserRoleLink
    )
    permissions: Mapped[List["Permission"]] = Relationship(
        back_populates="roles",
        link_model=RolePermissionLink
    )


class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(foreign_key="user.id")
    token: str = Field(default_factory=lambda: str(
        uuid4()), index=True, unique=True)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=1))
    used: bool = Field(default=False)

    user: Mapped[Optional["User"]] = Relationship(
        back_populates="password_reset_tokens")

    def is_expired(self) -> bool:
        """
        Check if the token has expired
        """
        return datetime.now(UTC) > self.expires_at.replace(tzinfo=UTC)


class UserPassword(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(foreign_key="user.id", unique=True)
    hashed_password: str

    user: Mapped[Optional["User"]] = Relationship(
        back_populates="password",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "single_parent": True
        }
    )


# TODO: Prevent deleting a user who is sole owner of an organization
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(index=True, unique=True)
    avatar_url: Optional[str] = None
    avatar_data: Optional[bytes] = Field(
        default=None, sa_column=Column(LargeBinary))
    avatar_content_type: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    roles: Mapped[List[Role]] = Relationship(
        back_populates="users",
        link_model=UserRoleLink
    )
    password_reset_tokens: Mapped[List["PasswordResetToken"]] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )
    password: Mapped[Optional[UserPassword]] = Relationship(
        back_populates="user"
    )

    @property
    def organizations(self) -> List[Organization]:
        """
        Returns all organizations the user belongs to via their roles.
        """
        organizations = []
        organization_ids = set()
        for role in self.roles:
            if role.organization_id not in organization_ids:
                organizations.append(role.organization)
                organization_ids.add(role.organization_id)
        return organizations

    def has_permission(self, permission: ValidPermissions, organization: Union[Organization, int]) -> bool:
        """
        Check if the user has a specific permission for a given organization.
        """
        organization_id: Optional[int] = None
        if isinstance(organization, Organization):
            organization_id = organization.id
        else:
            organization_id = organization

        if not organization_id:
            raise DataIntegrityError(resource="Organization ID")

        for role in self.roles:
            if role.organization_id == organization_id:
                return permission in [perm.name for perm in role.permissions]
        return False
