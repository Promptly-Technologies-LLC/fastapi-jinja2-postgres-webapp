import os
import logging
from typing import Union, Sequence
from dotenv import load_dotenv
from sqlalchemy.engine import URL
from sqlmodel import create_engine, Session, SQLModel, select
from utils.core.models import Role, Permission, RolePermissionLink
from utils.core.enums import ValidPermissions

# Load environment variables from a .env file
load_dotenv()

# Set up a logger for error reporting
logger = logging.getLogger("uvicorn.error")


# --- Constants ---


default_roles = ["Owner", "Administrator", "Member"]


# --- Database connection functions ---


def get_connection_url() -> URL:
    """
    Constructs a SQLModel URL object for connecting to the PostgreSQL database.

    The connection details are sourced from environment variables, which should include:
    - DB_USER: Database username
    - DB_PASSWORD: Database password
    - DB_HOST: Database host address
    - DB_PORT: Database port (default is 5432)
    - DB_NAME: Database name

    Returns:
        URL: A SQLModel URL object containing the connection details.
    """
    database_url: URL = URL.create(
        drivername="postgresql",
        username=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT") or "5432"),
        database=os.getenv("DB_NAME"),
    )

    return database_url


# Create the database engine using the connection URL
engine = create_engine(get_connection_url())


def assign_permissions_to_role(
        session: Session,
        role: Role,
        permissions: Union[list[Permission], Sequence[Permission]],
        check_first: bool = False
) -> None:
    """
    Assigns permissions to a role in the database.

    Args:
        session (Session): The database session to use for operations.
        role (Role): The role to assign permissions to.
        permissions (list[Permission]): The list of permissions to assign.
        check_first (bool): If True, checks if the role already has the permission before assigning it.
    """

    for permission in permissions:
        # Check if the role already has the permission
        if check_first:
            db_role_permission_link: RolePermissionLink | None = session.exec(
                select(RolePermissionLink).where(
                    RolePermissionLink.role_id == role.id,
                    RolePermissionLink.permission_id == permission.id
                )
            ).first()
        else:
            db_role_permission_link = None

        # Skip granting DELETE_ORGANIZATION permission to the Administrator role
        if not db_role_permission_link:
            role_permission_link = RolePermissionLink(
                role_id=role.id,
                permission_id=permission.id
            )
            session.add(role_permission_link)


def create_default_roles(session: Session, organization_id: int, check_first: bool = True) -> list:
    """
    Creates default roles for a specified organization in the database if they do not already exist,
    and assigns permissions to the Owner and Administrator roles.

    Args:
        session (Session): The database session to use for operations.
        organization_id (int): The ID of the organization for which to create roles.
        check_first (bool): If True, checks if the role already exists before creating it.

    Returns:
        list: A list of roles that were created or already existed in the database.
    """

    roles_in_db = []
    for role_name in default_roles:
        db_role = session.exec(
            select(Role).where(
                Role.name == role_name,
                Role.organization_id == organization_id
            )
        ).first()
        if not db_role:
            db_role = Role(name=role_name, organization_id=organization_id)
            session.add(db_role)
        roles_in_db.append(db_role)

    # TODO: Construct this role-permission mapping once at app startup and use as constant
    # Fetch all permissions once
    owner_permissions = session.exec(select(Permission)).all()
    admin_permissions = [
        permission for permission in owner_permissions
        if permission.name != ValidPermissions.DELETE_ORGANIZATION
    ]

    # Get Owner and Administrator roles by name
    owner_role = next(role for role in roles_in_db if role.name == "Owner")
    admin_role = next(
        role for role in roles_in_db if role.name == "Administrator")

    # Assign all permissions to Owner
    assign_permissions_to_role(
        session, owner_role, owner_permissions, check_first=check_first)

    # Assign filtered permissions to Administrator
    assign_permissions_to_role(
        session, admin_role, admin_permissions, check_first=check_first)

    session.commit()
    return roles_in_db


def create_permissions(session: Session) -> None:
    """
    Creates default permissions in the database if they do not already exist.

    Args:
        session (Session): The database session to use for operations.
    """
    for permission in ValidPermissions:
        db_permission = session.exec(select(Permission).where(
            Permission.name == permission)).first()
        if not db_permission:
            db_permission = Permission(name=permission)
            session.add(db_permission)


def set_up_db(drop: bool = False) -> None:
    """
    Sets up the database by creating tables and populating them with default permissions.

    Args:
        drop (bool): If True, drops all existing tables before creating new ones.
    """
    engine = create_engine(get_connection_url())
    if drop:
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    # Create default permissions
    with Session(engine) as session:
        create_permissions(session)
        session.commit()
    engine.dispose()


def tear_down_db() -> None:
    """
    Tears down the database by dropping all tables.
    """
    engine = create_engine(get_connection_url())
    SQLModel.metadata.drop_all(engine)
    engine.dispose()
