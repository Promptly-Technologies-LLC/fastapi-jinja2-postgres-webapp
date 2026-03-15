import pytest
from sqlmodel import Session, select, inspect
from sqlalchemy import Engine
from utils.core.db import (
    get_connection_url,
    assign_permissions_to_role,
    create_default_roles,
    create_permissions,
    seed_account_emails,
    tear_down_db,
    set_up_db,
)
from utils.core.models import Account, AccountEmail, Role, Permission, Organization, RolePermissionLink
from utils.core.auth import get_password_hash
from utils.core.enums import ValidPermissions
from utils.app.enums import AppPermissions
from tests.conftest import SetupError


# --- Connection URL Tests ---


def test_get_connection_url(env_vars):
    """Test that get_connection_url returns a valid URL object"""
    url = get_connection_url()
    assert url.drivername == "postgresql"
    assert url.database is not None


def test_get_connection_url_direct_mode(monkeypatch):
    """Test that direct mode uses standard DB vars."""
    # Clear any existing vars
    for var in ["USE_POOL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
                "DB_POOL_PORT", "DB_POOL_NAME", "DB_APPUSER", "DB_APPUSER_PASSWORD"]:
        monkeypatch.delenv(var, raising=False)

    # Set direct mode vars
    monkeypatch.setenv("DB_HOST", "localhost")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_NAME", "testdb")
    monkeypatch.setenv("DB_USER", "testuser")
    monkeypatch.setenv("DB_PASSWORD", "testpass")

    url = get_connection_url()
    assert url.host == "localhost"
    assert url.port == 5432
    assert url.database == "testdb"
    assert url.username == "testuser"
    assert url.query.get("sslmode") == "prefer"


def test_get_connection_url_pooled_mode(monkeypatch):
    """Test that pooled mode uses pool-specific vars."""
    # Clear any existing vars
    for var in ["USE_POOL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
                "DB_POOL_PORT", "DB_POOL_NAME", "DB_APPUSER", "DB_APPUSER_PASSWORD"]:
        monkeypatch.delenv(var, raising=False)

    # Set pooled mode vars
    monkeypatch.setenv("USE_POOL", "1")
    monkeypatch.setenv("DB_HOST", "pooler.example.com")
    monkeypatch.setenv("DB_POOL_PORT", "6543")
    monkeypatch.setenv("DB_POOL_NAME", "pooldb")
    monkeypatch.setenv("DB_APPUSER", "appuser")
    monkeypatch.setenv("DB_APPUSER_PASSWORD", "apppass")
    monkeypatch.setenv("DB_SSLMODE", "require")

    url = get_connection_url()
    assert url.host == "pooler.example.com"
    assert url.port == 6543
    assert url.database == "pooldb"
    assert url.username == "appuser"
    assert url.query.get("sslmode") == "require"


def test_get_connection_url_missing_direct_vars(monkeypatch):
    """Test that missing direct mode vars raises ValueError."""
    # Clear all DB vars
    for var in ["USE_POOL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
                "DB_POOL_PORT", "DB_POOL_NAME", "DB_APPUSER", "DB_APPUSER_PASSWORD"]:
        monkeypatch.delenv(var, raising=False)

    with pytest.raises(ValueError, match="Missing environment variables"):
        get_connection_url()


def test_get_connection_url_missing_pool_vars(monkeypatch):
    """Test that missing pooled mode vars raises ValueError."""
    # Clear all DB vars
    for var in ["USE_POOL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD",
                "DB_POOL_PORT", "DB_POOL_NAME", "DB_APPUSER", "DB_APPUSER_PASSWORD"]:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("USE_POOL", "1")
    monkeypatch.setenv("DB_HOST", "localhost")
    # Missing: DB_POOL_PORT, DB_POOL_NAME, DB_APPUSER, DB_APPUSER_PASSWORD

    with pytest.raises(ValueError, match="Missing environment variables.*DB_POOL_PORT"):
        get_connection_url()


# --- Permission and Role Tests ---


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
    all_perms = list(ValidPermissions) + list(AppPermissions)
    assert len(db_permissions) == len(all_perms)
    assert {p.name for p in db_permissions} == {str(p) for p in all_perms}


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
    all_perms = list(ValidPermissions) + list(AppPermissions)
    assert len(owner_permissions) == len(all_perms)

    # Check Administrator role permissions
    admin_role = next(r for r in roles if r.name == "Administrator")
    admin_permissions = session.exec(
        select(Permission)
        .join(RolePermissionLink)
        .where(RolePermissionLink.role_id == admin_role.id)
    ).all()
    # Admin should have all permissions except DELETE_ORGANIZATION
    assert len(admin_permissions) == len(all_perms) - 1
    assert str(ValidPermissions.DELETE_ORGANIZATION) not in {
        p.name for p in admin_permissions}


def test_assign_permissions_to_role(session: Session, test_organization: Organization):
    """Test that assign_permissions_to_role correctly assigns permissions"""
    # Create a test role with the organization from fixture
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)
    session.commit()

    # Get existing permissions
    perm1 = session.exec(
        select(Permission).where(Permission.name == str(ValidPermissions.CREATE_ROLE))
    ).first()
    perm2 = session.exec(
        select(Permission).where(Permission.name == str(ValidPermissions.DELETE_ROLE))
    ).first()
    assert perm1 is not None and perm2 is not None

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
        str(ValidPermissions.CREATE_ROLE), str(ValidPermissions.DELETE_ROLE)}


def test_assign_permissions_to_role_duplicate_check(session: Session, test_organization: Organization):
    """Test that assign_permissions_to_role doesn't create duplicates"""
    # Create a test role with the organization from fixture
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)
    session.commit()

    perm = session.exec(
        select(Permission).where(Permission.name == str(ValidPermissions.CREATE_ROLE))
    ).first()
    assert perm is not None

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
    public_table_names = inspector.get_table_names(schema="public")

    # Check for public tables
    expected_public_tables = {
        "user",
        "organization",
        "role",
        "permission",
        "rolepermissionlink",
    }
    assert expected_public_tables.issubset(set(public_table_names))

    # Check that private tables are NOT in the public schema
    assert "account" not in public_table_names
    assert "passwordresettoken" not in public_table_names
    assert "emailverificationtoken" not in public_table_names

    # Check that private tables ARE in the private schema
    private_table_names = inspector.get_table_names(schema="private")
    expected_private_tables = {"account", "passwordresettoken", "emailverificationtoken"}
    assert expected_private_tables.issubset(set(private_table_names))

    # Verify permissions were created
    permissions = session.exec(select(Permission)).all()
    assert len(permissions) == len(ValidPermissions) + len(AppPermissions)


def test_private_schema_exists_after_setup(engine: Engine):
    """Test that set_up_db creates the 'private' PostgreSQL schema."""
    inspector = inspect(engine)
    schemas = inspector.get_schema_names()
    assert "private" in schemas


def test_private_tables_in_private_schema(engine: Engine):
    """Account, PasswordResetToken, and EmailVerificationToken must be in the private schema."""
    inspector = inspect(engine)
    private_tables = set(inspector.get_table_names(schema="private"))
    assert {"account", "passwordresettoken", "emailverificationtoken"}.issubset(private_tables)


def test_public_tables_in_public_schema(engine: Engine):
    """Core business-logic tables must be in the public schema."""
    inspector = inspect(engine)
    public_tables = set(inspector.get_table_names(schema="public"))
    assert {"user", "organization", "role", "permission"}.issubset(public_tables)
    # Private tables must not leak into public
    assert "account" not in public_tables
    assert "passwordresettoken" not in public_tables
    assert "emailverificationtoken" not in public_tables


def test_set_up_db_drop_flag(engine: Engine, session: Session):
    """Test that set_up_db's drop flag properly recreates tables"""
    # Set up db with drop=True
    set_up_db(drop=True)

    # Verify valid permissions exist
    permissions = session.exec(select(Permission)).all()
    assert len(permissions) == len(ValidPermissions) + len(AppPermissions)

    # Create an organization
    org = Organization(name="Test Organization")
    session.add(org)
    session.commit()

    # Set up db with drop=False
    set_up_db(drop=False)

    # Verify organization exists
    assert session.exec(select(Organization).where(
        Organization.name == "Test Organization")).first() is not None


# --- Seed AccountEmail Tests ---


def test_seed_creates_account_email_for_existing_accounts(session: Session):
    """Test that seed_account_emails creates AccountEmail rows for existing accounts."""
    # Create accounts without AccountEmail rows
    account1 = Account(email="seed1@example.com", hashed_password=get_password_hash("Test123!@#"))
    account2 = Account(email="seed2@example.com", hashed_password=get_password_hash("Test123!@#"))
    session.add(account1)
    session.add(account2)
    session.commit()

    # Verify no AccountEmail rows exist
    assert len(session.exec(select(AccountEmail)).all()) == 0

    # Run seed
    seed_account_emails(session)

    # Verify AccountEmail rows were created
    emails = session.exec(select(AccountEmail)).all()
    assert len(emails) == 2
    for ae in emails:
        assert ae.is_primary is True
        assert ae.verified is True
        assert ae.verified_at is not None


def test_seed_is_idempotent(session: Session):
    """Test that running seed_account_emails twice doesn't create duplicates."""
    account = Account(email="idempotent@example.com", hashed_password=get_password_hash("Test123!@#"))
    session.add(account)
    session.commit()

    seed_account_emails(session)
    seed_account_emails(session)

    emails = session.exec(select(AccountEmail)).all()
    assert len(emails) == 1
