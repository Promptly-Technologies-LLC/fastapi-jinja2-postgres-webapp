import pytest
import os
from typing import Generator
from sqlmodel import create_engine, Session, select
from fastapi.testclient import TestClient
from dotenv import load_dotenv
from utils.core.db import get_connection_url, tear_down_db, set_up_db, create_default_roles, ensure_database_exists
from utils.core.models import User, Organization, Role, Account, Invitation
from utils.core.auth import get_password_hash, create_access_token, create_refresh_token
from main import app
from datetime import datetime, UTC, timedelta

# Define a custom exception for test setup errors
class SetupError(Exception):
    """Exception raised for errors in the test setup process."""
    def __init__(self, message="An error occurred during test setup"):
        self.message = message
        super().__init__(self.message)


@pytest.fixture
def env_vars(monkeypatch):
    load_dotenv()

    # monkeypatch remaining env vars
    with monkeypatch.context() as m:
        # Get valid db user, password, host, and port from env
        m.setenv("DB_HOST", os.getenv("DB_HOST", "127.0.0.1"))
        m.setenv("DB_PORT", os.getenv("DB_PORT", "5432"))
        m.setenv("DB_USER", os.getenv("DB_USER", "postgres"))
        m.setenv("DB_PASSWORD", os.getenv("DB_PASSWORD", "postgres"))
        m.setenv("SECRET_KEY", "testsecretkey")
        m.setenv("HOST_NAME", "Test Organization")
        m.setenv("DB_NAME", "webapp-test-db")
        m.setenv("RESEND_API_KEY", "test")
        m.setenv("EMAIL_FROM", "test@example.com")
        m.setenv("BASE_URL", "http://localhost:8000")
        yield


@pytest.fixture
def engine(env_vars):
    """
    Create a new SQLModel engine for the test database.
    Use PostgreSQL for testing to match production environment.
    """
    # Use PostgreSQL for testing to match production environment
    ensure_database_exists(get_connection_url())
    engine = create_engine(get_connection_url())
    set_up_db(drop=True)

    yield engine

    # Clean up after tests
    tear_down_db()


@pytest.fixture
def session(engine) -> Generator[Session, None, None]:
    """
    Provide a session for database operations in tests.
    """
    with Session(engine) as session:
        yield session


@pytest.fixture
def test_account(session: Session) -> Account:
    """
    Creates a test account in the database.
    """
    account = Account(
        email="test@example.com",
        hashed_password=get_password_hash("Test123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    return account


@pytest.fixture
def test_user(session: Session, test_account: Account) -> User:
    """
    Creates a test user in the database linked to the test account.
    """
    user = User(
        name="Test User",
        account_id=test_account.id
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    
    # Also refresh the account to ensure the relationship is loaded
    session.refresh(test_account)
    return user


@pytest.fixture
def unauth_client(session: Session) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance without authentication.
    """
    client = TestClient(app)
    yield client


@pytest.fixture
def auth_client(session: Session, test_account: Account, test_user: User) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance with valid authentication tokens.
    """
    client = TestClient(app)

    # Create and set valid tokens
    access_token = create_access_token({"sub": test_account.email})
    refresh_token = create_refresh_token({"sub": test_account.email})

    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)

    yield client


@pytest.fixture
def test_organization(session: Session) -> Organization:
    """Create a test organization with default roles and permissions"""
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.flush()

    if organization.id:
        # Use the utility function to create default roles and assign permissions
        # This function handles the commit internally
        create_default_roles(session, organization.id, check_first=False)
    else:
        pytest.fail("Failed to get organization ID after flush")

    return organization


@pytest.fixture
def org_owner(session: Session, test_organization: Organization) -> User:
    """Create a user who is the owner of the test organization"""
    # Create account
    account = Account(
        email="owner@example.com",
        hashed_password=get_password_hash("Owner123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    
    # Create user
    user = User(
        name="Org Owner",
        account_id=account.id
    )
    session.add(user)
    # Find the Owner role for the test organization
    owner_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Owner")
    ).first()

    if owner_role is None:
        pytest.fail("Owner role not found for test organization")

    # Assign user to owner role
    user.roles.append(owner_role)
    
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def org_admin_user(session: Session, test_organization: Organization) -> User:
    """Create a user with Administrator role in the test organization"""
    # Create account
    account = Account(
        email="admin@example.com",
        hashed_password=get_password_hash("Admin123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    
    # Create user
    user = User(
        name="Admin User",
        account_id=account.id
    )
    session.add(user)
    
    # Find the Admin role for the test organization (already created with permissions)
    admin_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Administrator")
    ).first()

    if admin_role is None:
        pytest.fail("Administrator role not found for test organization")

    # Assign role to user
    user.roles.append(admin_role)
    
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def org_member_user(session: Session, test_organization: Organization) -> User:
    """Create a user with basic Member role in the test organization"""
    # Create account
    account = Account(
        email="member@example.com",
        hashed_password=get_password_hash("Member123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    
    # Create user
    user = User(
        name="Member User",
        account_id=account.id
    )
    session.add(user)
    
    # Find the Member role for the test organization (already created)
    member_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Member")
    ).first()

    if member_role is None:
        pytest.fail("Member role not found for test organization")

    # Assign role to user
    user.roles.append(member_role)
    
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def non_member_user(session: Session) -> User:
    """Create a user who is not a member of the test organization"""
    # Create account
    account = Account(
        email="nonmember@example.com",
        hashed_password=get_password_hash("NonMember123!@#")
    )
    session.add(account)
    session.commit()
    
    # Create user
    user = User(
        name="Non-Member User",
        account_id=account.id
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def auth_client_owner(session: Session, org_owner: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as the organization owner"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if org_owner.account:
        access_token = create_access_token({"sub": org_owner.account.email})
        refresh_token = create_refresh_token({"sub": org_owner.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def auth_client_admin(session: Session, org_admin_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as an organization administrator"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if org_admin_user.account:
        access_token = create_access_token({"sub": org_admin_user.account.email})
        refresh_token = create_refresh_token({"sub": org_admin_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def auth_client_member(session: Session, org_member_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as the organization member"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if org_member_user.account:
        access_token = create_access_token({"sub": org_member_user.account.email})
        refresh_token = create_refresh_token({"sub": org_member_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def auth_client_non_member(session: Session, non_member_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as a non-member"""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if non_member_user.account:
        access_token = create_access_token({"sub": non_member_user.account.email})
        refresh_token = create_refresh_token({"sub": non_member_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client


@pytest.fixture
def second_test_organization(session: Session) -> Organization:
    """Create a second test organization for multi-organization tests"""
    organization = Organization(name="Second Test Organization")
    session.add(organization)
    session.commit()
    return organization


# --- Invitation Fixtures ---

@pytest.fixture
def member_role(session: Session, test_organization: Organization) -> Role:
    """Returns the 'Member' role for the test_organization."""
    member_role = session.exec(
        select(Role)
        .where(Role.organization_id == test_organization.id)
        .where(Role.name == "Member")
    ).first()

    if member_role is None:
        pytest.fail(f"Member role not found for organization {test_organization.id}")
    return member_role


@pytest.fixture
def test_invitation(session: Session, test_organization: Organization, member_role: Role) -> Invitation:
    """Creates a valid, active Invitation for invitee@example.com."""
    # Assert IDs are not None to satisfy type checker
    assert test_organization.id is not None
    assert member_role.id is not None
    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="invitee@example.com",
        token="valid-test-token",
        expires_at=datetime.now(UTC) + timedelta(days=7)
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation


@pytest.fixture
def expired_invitation(session: Session, test_organization: Organization, member_role: Role) -> Invitation:
    """Creates an Invitation with an expiration date in the past."""
    # Assert IDs are not None to satisfy type checker
    assert test_organization.id is not None
    assert member_role.id is not None
    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="expired-invitee@example.com",
        token="expired-test-token",
        expires_at=datetime.now(UTC) - timedelta(days=1)
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation


@pytest.fixture
def used_invitation(session: Session, test_organization: Organization, member_role: Role, non_member_user: User) -> Invitation:
    """Creates an Invitation that has already been used."""
    # Assert IDs are not None to satisfy type checker
    assert test_organization.id is not None
    assert member_role.id is not None
    assert non_member_user.id is not None
    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="used-invitee@example.com",
        token="used-test-token",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        used=True,
        accepted_at=datetime.now(UTC),
        accepted_by_user_id=non_member_user.id
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation


@pytest.fixture
def existing_invitee_account(session: Session) -> Account:
    """Creates an Account for invitee@example.com."""
    account = Account(
        email="invitee@example.com",
        hashed_password=get_password_hash("Invitee123!@#")
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    return account


@pytest.fixture
def existing_invitee_user(session: Session, existing_invitee_account: Account) -> User:
    """Creates a User linked to existing_invitee_account."""
    user = User(
        name="Invitee User",
        account_id=existing_invitee_account.id
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    # Refresh account to load user relationship
    session.refresh(existing_invitee_account)
    return user


@pytest.fixture
def auth_client_invitee(session: Session, existing_invitee_user: User) -> Generator[TestClient, None, None]:
    """Provides a TestClient authenticated as the existing_invitee_user."""
    client = TestClient(app)
    
    # Initialize tokens
    access_token = ""
    refresh_token = ""
    
    # Create and set valid tokens
    if existing_invitee_user.account:
        access_token = create_access_token({"sub": existing_invitee_user.account.email})
        refresh_token = create_refresh_token({"sub": existing_invitee_user.account.email})
        
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    
    yield client

# --- Email Mocking Fixtures ---

@pytest.fixture
def mock_email_response():
    """
    Returns a mock Email response object
    """
    # Use dictionary unpacking to handle the 'from' keyword
    email_data = {
        "id": "mock_resend_id",
        "from": "test@example.com",
        "to": ["recipient@example.com"],
        "created_at": "2023-01-01T00:00:00Z",
        "subject": "Mock Subject",
        "html": "<p>Mock HTML</p>",
        "text": "Mock Text",
        "bcc": [],
        "cc": [],
        "reply_to": [],
        "last_event": "delivered"
    }
    # Ensure resend is imported
    import resend
    return resend.Email(**email_data)


@pytest.fixture
def mock_resend_send(mock_email_response):
    """
    Patches resend.Emails.send to return a mock response
    """
    # Ensure patch and resend are imported
    from unittest.mock import patch
    import resend
    with patch('resend.Emails.send', return_value=mock_email_response) as mock:
        yield mock