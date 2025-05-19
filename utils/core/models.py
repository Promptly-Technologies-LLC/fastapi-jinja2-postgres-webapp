from logging import getLogger, DEBUG
from uuid import uuid4
from datetime import datetime, UTC, timedelta
from typing import Optional, List, Union
from pydantic import EmailStr
from sqlmodel import SQLModel, Field, Relationship, Session, select
from sqlalchemy import Column, Enum as SQLAlchemyEnum, LargeBinary, UniqueConstraint
from sqlalchemy.orm import Mapped
from utils.core.enums import ValidPermissions
from exceptions.http_exceptions import DataIntegrityError

logger = getLogger("uvicorn.error")
logger.setLevel(DEBUG)


# --- Helper functions ---


def utc_now():
    return datetime.now(UTC)


# --- Private database models ---


# TODO: Handle password hashing and checking on the data model?
class Account(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: EmailStr = Field(index=True, unique=True)
    hashed_password: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    user: Mapped[Optional["User"]] = Relationship(
        back_populates="account",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )
    password_reset_tokens: Mapped[List["PasswordResetToken"]] = Relationship(
        back_populates="account",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )
    email_update_tokens: Mapped[List["EmailUpdateToken"]] = Relationship(
        back_populates="account",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )

class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    account_id: Optional[int] = Field(foreign_key="account.id")
    token: str = Field(default_factory=lambda: str(
        uuid4()), index=True, unique=True)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=1))
    used: bool = Field(default=False)

    account: Mapped[Optional[Account]] = Relationship(
        back_populates="password_reset_tokens")

    def is_expired(self) -> bool:
        """
        Check if the token has expired
        """
        return datetime.now(UTC) > self.expires_at.replace(tzinfo=UTC)


class EmailUpdateToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    account_id: Optional[int] = Field(foreign_key="account.id")
    token: str = Field(default_factory=lambda: str(
        uuid4()), index=True, unique=True)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=1))
    used: bool = Field(default=False)

    account: Mapped[Optional[Account]] = Relationship(
        back_populates="email_update_tokens")

    def is_expired(self) -> bool:
        """
        Check if the token has expired
        """
        return datetime.now(UTC) > self.expires_at.replace(tzinfo=UTC)


# --- Public database models ---


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


class UserBase(SQLModel):
    name: Optional[str] = None
    avatar_data: Optional[bytes] = Field(
        default=None, sa_column=Column(LargeBinary)
    )
    avatar_content_type: Optional[str] = Field(
        default=None
    )


# TODO: Prevent deleting a user who is sole owner of an organization
# TODO: Automate change of updated_at when user is updated
class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    account_id: Optional[int] = Field(foreign_key="account.id", unique=True)
    account: Mapped[Optional[Account]] = Relationship(
        back_populates="user"
    )
    roles: Mapped[List["Role"]] = Relationship(
        back_populates="users",
        link_model=UserRoleLink
    )
    accepted_invitations: Mapped[List["Invitation"]] = Relationship(
        back_populates="accepted_by"
    )

    @property
    def organizations(self) -> List["Organization"]:
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

    def has_permission(self, permission: ValidPermissions, organization: Union["Organization", int]) -> bool:
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


class Organization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    roles: Mapped[List["Role"]] = Relationship(
        back_populates="organization",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )
    invitations: Mapped[List["Invitation"]] = Relationship(
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
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    organization: Mapped[Organization] = Relationship(back_populates="roles")
    users: Mapped[List[User]] = Relationship(
        back_populates="roles",
        link_model=UserRoleLink
    )
    permissions: Mapped[List["Permission"]] = Relationship(
        back_populates="roles",
        link_model=RolePermissionLink
    )
    invitations: Mapped[List["Invitation"]] = Relationship(
        back_populates="role",
        sa_relationship_kwargs={
            "cascade": "all, delete-orphan"
        }
    )
    
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_role_organization_name"),
    )

class Permission(SQLModel, table=True):
    """
    Represents a permission that can be assigned to a role. Should not be
    modified unless the application logic and ValidPermissions enum change.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    name: ValidPermissions = Field(
        sa_column=Column(SQLAlchemyEnum(ValidPermissions, create_type=False)))
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    roles: Mapped[List[Role]] = Relationship(
        back_populates="permissions",
        link_model=RolePermissionLink
    )


# --- New Invitation Model ---

class Invitation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    role_id: int = Field(foreign_key="role.id")
    invitee_email: EmailStr = Field(index=True)

    token: str = Field(default_factory=lambda: str(uuid4()), index=True, unique=True)
    expires_at: datetime = Field(default_factory=lambda: utc_now() + timedelta(days=7))
    created_at: datetime = Field(default_factory=utc_now)
    used: bool = Field(default=False, index=True)
    accepted_at: Optional[datetime] = Field(default=None)
    accepted_by_user_id: Optional[int] = Field(default=None, foreign_key="user.id")

    organization: "Organization" = Relationship(back_populates="invitations")
    role: "Role" = Relationship(back_populates="invitations")
    accepted_by: Optional["User"] = Relationship(
        back_populates="accepted_invitations"
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "invitee_email", "used", name="uq_invitation_org_email_used"),
    )

    def is_expired(self) -> bool:
        """Checks if the invitation has passed its expiry date."""
        aware_expires_at = self.expires_at.replace(tzinfo=UTC) if self.expires_at.tzinfo is None else self.expires_at
        return utc_now() > aware_expires_at

    def is_active(self) -> bool:
        """Checks if the invitation is currently valid (not used and not expired)."""
        return not self.used and not self.is_expired()

    @classmethod
    def get_active_for_org(cls, session: Session, organization_id: int) -> list["Invitation"]:
        statement = select(cls).where(cls.organization_id == organization_id, cls.used == False)
        results = session.exec(statement).all()
        return [inv for inv in results if not inv.is_expired()]