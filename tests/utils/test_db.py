
from sqlmodel import Session, select, inspect
from sqlalchemy import Engine
from utils.core.db import (
    get_connection_url,
    assign_permissions_to_role,
    create_default_roles,
    create_permissions,
    tear_down_db,
    set_up_db,
)
from utils.core.models import Role, Permission, Organization, RolePermissionLink, ValidPermissions
from tests.conftest import SetupError

def test_get_connection_url():
    """Test that get_connection_url returns a valid URL object"""
    url = get_connection_url()
    assert url.drivername == "postgresql"
    assert url.database is not None


def test_create_permissions(session: Session):
    """Test that create_permissions creates all ValidPermissions"""
    # Clear existing permissions
    existing_permissions = session.exec(select(Permission)).all()
    for permission in existing_permissions:
        session.delete(permission)
    session.commit()

    create_permissions(session)
    session.commit()

    # Check all permissions were created
    db_permissions = session.exec(select(Permission)).all()
    assert len(db_permissions) == len(ValidPermissions)
    assert {p.name for p in db_permissions} == {p for p in ValidPermissions}


def test_create_default_roles(session: Session, test_organization: Organization):
    """Test that create_default_roles creates expected roles with correct permissions"""
    # Create permissions first
    create_permissions(session)
    session.commit()

    # Create roles for test organization
    if test_organization.id is not None:
        roles = create_default_roles(session, test_organization.id)
        session.commit()
    else:
        raise SetupError(
            "Test setup failed; test_organization.id is None")

    # Verify roles were created
    assert len(roles) == 3  # Owner, Administrator, Member

    # Check Owner role permissions
    owner_role = next(r for r in roles if r.name == "Owner")
    owner_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == owner_role.id)
    ).all()
    assert len(owner_permissions) == len(ValidPermissions)

    # Check Administrator role permissions
    admin_role = next(r for r in roles if r.name == "Administrator")
    admin_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == admin_role.id)
    ).all()
    # Admin should have all permissions except DELETE_ORGANIZATION
    assert len(admin_permissions) == len(ValidPermissions) - 1
    assert ValidPermissions.DELETE_ORGANIZATION not in {
        p.name for p in admin_permissions}


def test_assign_permissions_to_role(session: Session, test_organization: Organization):
    """Test that assign_permissions_to_role correctly assigns permissions"""
    # Create a test role with the organization from fixture
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)

    # Create test permissions
    perm1 = Permission(name=ValidPermissions.CREATE_ROLE)
    perm2 = Permission(name=ValidPermissions.DELETE_ROLE)
    session.add(perm1)
    session.add(perm2)
    session.commit()

    # Assign permissions
    permissions = [perm1, perm2]
    assign_permissions_to_role(session, role, permissions)
    session.commit()

    # Verify assignments
    db_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == role.id)
    ).all()

    assert len(db_permissions) == 2
    assert {p.name for p in db_permissions} == {
        ValidPermissions.CREATE_ROLE, ValidPermissions.DELETE_ROLE}


def test_assign_permissions_to_role_duplicate_check(session: Session, test_organization: Organization):
    """Test that assign_permissions_to_role doesn't create duplicates"""
    # Create a test role with the organization from fixture
    role = Role(name="Test Role", organization_id=test_organization.id)
    perm = Permission(name=ValidPermissions.CREATE_ROLE)
    session.add(role)
    session.add(perm)
    session.commit()

    # Assign same permission twice
    assign_permissions_to_role(session, role, [perm], check_first=True)
    assign_permissions_to_role(session, role, [perm], check_first=True)
    session.commit()

    # Verify only one assignment exists
    link_count = session.exec(
        select(RolePermissionLink)
        .where(
            RolePermissionLink.role_id == role.id,
            RolePermissionLink.permission_id == perm.id
        )
    ).all()
    assert len(link_count) == 1


def test_set_up_db_creates_tables(engine: Engine, session: Session):
    """Test that set_up_db creates all expected tables without warnings"""
    # First tear down any existing tables
    tear_down_db()

    # Run set_up_db with drop=False since we just cleaned up
    set_up_db(drop=False)

    # Use SQLAlchemy inspect to check tables
    inspector = inspect(engine)
    table_names = inspector.get_table_names()

    # Check for core tables
    expected_tables = {
        "user",
        "organization",
        "role",
        "permission",
        "rolepermissionlink",
        "passwordresettoken"
    }
    assert expected_tables.issubset(set(table_names))

    # Verify permissions were created
    permissions = session.exec(select(Permission)).all()
    assert len(permissions) == len(ValidPermissions)


def test_set_up_db_drop_flag(engine: Engine, session: Session):
    """Test that set_up_db's drop flag properly recreates tables"""
    # Set up db with drop=True
    set_up_db(drop=True)

    # Verify valid permissions exist
    permissions = session.exec(select(Permission)).all()
    assert len(permissions) == len(ValidPermissions)

    # Create an organization
    org = Organization(name="Test Organization")
    session.add(org)
    session.commit()

    # Set up db with drop=False
    set_up_db(drop=False)

    # Verify organization exists
    assert session.exec(select(Organization).where(
        Organization.name == "Test Organization")).first() is not None
