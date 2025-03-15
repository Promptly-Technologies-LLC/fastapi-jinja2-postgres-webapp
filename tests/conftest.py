import pytest
from typing import Generator
from sqlmodel import create_engine, Session, select
from sqlalchemy import Engine
from fastapi.testclient import TestClient
import os
from dotenv import load_dotenv
from utils.db import get_session, get_connection_url, tear_down_db, set_up_db
from utils.models import User, PasswordResetToken, EmailUpdateToken, Organization, Role, Account
from utils.auth import get_password_hash, create_access_token, create_refresh_token
from utils.dependencies import get_authenticated_user, get_user_with_relations
from main import app

# Load environment variables
load_dotenv(override=True)

# Define a custom exception for test setup errors
class SetupError(Exception):
    """Exception raised for errors in the test setup process."""
    def __init__(self, message="An error occurred during test setup"):
        self.message = message
        super().__init__(self.message)


@pytest.fixture(scope="session")
def engine() -> Engine:
    """
    Create a new SQLModel engine for the test database.
    Use PostgreSQL for testing to match production environment.
    """
    # Use PostgreSQL for testing to match production environment
    engine = create_engine(get_connection_url())
    return engine


@pytest.fixture(scope="session", autouse=True)
def set_up_database(engine) -> Generator[None, None, None]:
    """
    Set up the test database before running the test suite.
    Drop all tables and recreate them to ensure a clean state.
    """
    # Drop and recreate all tables using the helpers from db.py
    tear_down_db()
    set_up_db(drop=False)
    
    yield
    
    # Clean up after tests
    tear_down_db()


@pytest.fixture
def session(engine) -> Generator[Session, None, None]:
    """
    Provide a session for database operations in tests.
    """
    with Session(engine) as session:
        yield session


@pytest.fixture(autouse=True)
def clean_db(session: Session) -> None:
    """
    Cleans up the database tables before each test.
    """
    # Don't delete permissions as they are required for tests
    for model in (PasswordResetToken, EmailUpdateToken, User, Role, Organization, Account):
        for record in session.exec(select(model)).all():
            session.delete(record)

    session.commit()


@pytest.fixture()
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


@pytest.fixture()
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


@pytest.fixture()
def unauth_client(session: Session) -> Generator[TestClient, None, None]:
    """
    Provides a TestClient instance without authentication.
    """
    client = TestClient(app)
    yield client


@pytest.fixture()
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
    """Create a test organization for use in tests"""
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.commit()
    return organization
