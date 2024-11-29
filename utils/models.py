from enum import Enum
from uuid import uuid4
from datetime import datetime, UTC, timedelta
from typing import Optional, List
from sqlmodel import SQLModel, Field, Relationship
from sqlalchemy import Column, Enum as SQLAlchemyEnum


def utc_time():
    return datetime.now(UTC)


default_roles = ["Owner", "Administrator", "Member"]


# TODO: User with permission to create/edit roles can only assign permissions
# they themselves have.
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
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    role_id: int = Field(foreign_key="role.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)


class RolePermissionLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    role_id: int = Field(foreign_key="role.id")
    permission_id: int = Field(foreign_key="permission.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)


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

    roles: List["Role"] = Relationship(
        back_populates="permissions",
        link_model=RolePermissionLink
    )


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    roles: List["Role"] = Relationship(
        back_populates="organization",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "passive_deletes": True
        }
    )

    @property
    def users(self) -> List["User"]:
        """
        Returns all users in the organization via their roles.
        """
        return [role.users for role in self.roles]


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
    organization_id: int = Field(foreign_key="organization.id")
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    organization: Organization = Relationship(back_populates="roles")
    users: List["User"] = Relationship(
        back_populates="roles",
        link_model=UserRoleLink
    )
    permissions: List["Permission"] = Relationship(
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

    user: Optional["User"] = Relationship(
        back_populates="password_reset_tokens")


# TODO: Prevent deleting a user who is sole owner of an organization
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    email: str = Field(index=True, unique=True)
    hashed_password: str
    avatar_url: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_time)
    updated_at: datetime = Field(default_factory=utc_time)

    roles: List[Role] = Relationship(
        back_populates="users",
        link_model=UserRoleLink
    )
    password_reset_tokens: List["PasswordResetToken"] = Relationship(
        back_populates="user",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan",
            "passive_deletes": True
        }
    )

    @property
    def organizations(self) -> List[Organization]:
        """
        Returns all organizations the user belongs to via their roles.
        """
        return [role.organization for role in self.roles]
