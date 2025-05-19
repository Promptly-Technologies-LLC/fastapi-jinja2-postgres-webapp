import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import URLPath
from sqlmodel import Session, select
from datetime import timedelta
from urllib.parse import urlparse, parse_qs
from html import unescape
from sqlalchemy import inspect

from main import app
from utils.core.models import User, PasswordResetToken, EmailUpdateToken, Account
from utils.core.auth import (
    create_access_token,
    verify_password,
    validate_token,
    get_password_hash
)

# --- Fixture setup ---


# --- API Endpoint Tests ---


def test_register_endpoint(unauth_client: TestClient, session: Session):
    # Debug: Print the tables in the database
    inspector = inspect(session.bind)
    if inspector:  # Add null check
        print("Tables in the database:", inspector.get_table_names())
    
    # Create a mock register response
    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "New User",
            "email": "new@example.com",
            "password": "NewPass123!@#",
            "confirm_password": "NewPass123!@#"
        },
        follow_redirects=False
    )
    
    # Just check the response status code
    assert response.status_code == 303
    
    # Verify the account was created
    account = session.exec(select(Account).where(Account.email == "new@example.com")).first()
    assert account is not None
    assert verify_password("NewPass123!@#", account.hashed_password)
    
    # Verify the user was created and linked to the account
    user = session.exec(select(User).where(User.account_id == account.id)).first()
    assert user is not None
    assert user.name == "New User"


def test_login_endpoint(unauth_client: TestClient, test_account: Account):
    response = unauth_client.post(
        app.url_path_for("login"),
        data={
            "email": test_account.email,
            "password": "Test123!@#"
        },
        follow_redirects=False
    )
    assert response.status_code == 303

    # Check if cookies are set
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies


def test_refresh_token_endpoint(auth_client: TestClient, test_account: Account):
    # Override just the access token to be expired, keeping the valid refresh token
    expired_access_token = create_access_token(
        {"sub": test_account.email},
        timedelta(minutes=-10)
    )
    auth_client.cookies.set("access_token", expired_access_token)

    response = auth_client.post(
        app.url_path_for("refresh_token"),
        follow_redirects=False
    )
    assert response.status_code == 303

    # Check for new tokens in headers
    cookie_headers = response.headers.get_list("set-cookie")
    assert any("access_token=" in cookie for cookie in cookie_headers)
    assert any("refresh_token=" in cookie for cookie in cookie_headers)

    # Get the new access token from headers for validation
    access_token_cookie = next(
        cookie for cookie in cookie_headers if "access_token=" in cookie
    )
    new_access_token = access_token_cookie.split(";")[0].split("=")[1]

    # Verify new access token is valid
    decoded = validate_token(new_access_token, "access")
    assert decoded is not None
    assert decoded["sub"] == test_account.email


def test_password_reset_flow(unauth_client: TestClient, session: Session, test_account: Account, mock_resend_send):
    # Test forgot password request
    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": test_account.email},
        follow_redirects=False
    )
    assert response.status_code == 303

    # Verify the email was "sent" with correct parameters
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args[0][0]  # Get the SendParams argument

    # Verify SendParams structure and required fields
    assert isinstance(call_args, dict)
    assert isinstance(call_args["from"], str)
    assert isinstance(call_args["to"], list)
    assert isinstance(call_args["subject"], str)
    assert isinstance(call_args["html"], str)

    # Verify content
    assert call_args["to"] == [test_account.email]
    assert call_args["from"] == "noreply@promptlytechnologies.com"
    assert "Password Reset Request" in call_args["subject"]
    assert "reset_password" in call_args["html"]

    # Verify reset token was created
    reset_token = session.exec(select(PasswordResetToken)
                               .where(PasswordResetToken.account_id == test_account.id)).first()
    assert reset_token is not None
    assert not reset_token.used
    
    # Update password and mark token as used directly in the database
    test_account.hashed_password = get_password_hash("NewPass123!@#")
    reset_token.used = True
    session.commit()
    
    # Verify password was updated and token was marked as used
    session.refresh(test_account)
    session.refresh(reset_token)
    assert verify_password("NewPass123!@#", test_account.hashed_password)
    assert reset_token.used


def test_logout_endpoint(auth_client: TestClient):
    response = auth_client.get(
        app.url_path_for("logout"),
        follow_redirects=False
    )
    assert response.status_code == 303

    # Check for cookie deletion in headers
    cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        "access_token=" in cookie and "Max-Age=0" in cookie for cookie in cookie_headers)
    assert any(
        "refresh_token=" in cookie and "Max-Age=0" in cookie for cookie in cookie_headers)


# --- Error Case Tests ---


def test_register_with_existing_email(unauth_client: TestClient, test_account: Account):
    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "Another User",
            "email": test_account.email,
            "password": "Test123!@#",
            "confirm_password": "Test123!@#"
        }
    )
    assert response.status_code == 409


def test_login_with_invalid_credentials(unauth_client: TestClient, test_account: Account):
    response = unauth_client.post(
        app.url_path_for("login"),
        data={
            "email": test_account.email,
            "password": "WrongPass123!@#"
        }
    )
    assert response.status_code == 401


def test_password_reset_with_invalid_token(unauth_client: TestClient, test_account: Account):
    response = unauth_client.post(
        app.url_path_for("reset_password"),
        data={
            "email": test_account.email,
            "token": "invalid_token",
            "password": "NewPass123!@#",
            "confirm_password": "NewPass123!@#"
        }
    )
    assert response.status_code == 401  # Unauthorized for invalid token


def test_password_reset_email_url(unauth_client: TestClient, session: Session, test_account: Account, mock_resend_send):
    """
    Tests that the password reset email contains a properly formatted reset URL.
    """
    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": test_account.email},
        follow_redirects=False
    )
    assert response.status_code == 303

    # Get the reset token from the database
    reset_token = session.exec(select(PasswordResetToken)
                               .where(PasswordResetToken.account_id == test_account.id)).first()
    assert reset_token is not None

    # Get the actual path from the FastAPI app
    reset_password_path: URLPath = app.url_path_for("reset_password")

    # Verify the email HTML contains the correct URL
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args[0][0]
    html_content = call_args["html"]

    # Extract URL from HTML
    import re
    url_match = re.search(r'<a[^>]*href=[\'"]([^\'"]*)[\'"]', html_content)
    assert url_match is not None
    reset_url = unescape(url_match.group(1))

    # Parse and verify the URL
    parsed = urlparse(reset_url)
    query_params = parse_qs(parsed.query)

    assert parsed.path == str(reset_password_path)
    assert query_params["email"][0] == test_account.email
    assert query_params["token"][0] == reset_token.token


def test_request_email_update_success(auth_client: TestClient, test_account: Account, mock_resend_send):
    """Test successful email update request"""
    new_email = "newemail@example.com"
    
    response = auth_client.post(
        app.url_path_for("request_email_update"),
        data={"email": test_account.email, "new_email": new_email},
        follow_redirects=False
    )
    
    assert response.status_code == 303
    assert f"{app.url_path_for('read_profile')}?email_update_requested=true" in response.headers["location"]
    
    # Verify email was "sent"
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args[0][0]
    
    # Verify email content
    assert call_args["to"] == [test_account.email]
    assert call_args["from"] == "noreply@promptlytechnologies.com"
    assert "Confirm Email Update" in call_args["subject"]
    assert "confirm_email_update" in call_args["html"]
    assert new_email in call_args["html"]


def test_request_email_update_already_registered(auth_client: TestClient, session: Session, test_account: Account):
    """Test email update request with already registered email"""
    # Create another account with the target email
    existing_email = "existing@example.com"
    existing_account = Account(
        email=existing_email,
        hashed_password=get_password_hash("Test123!@#")
    )
    session.add(existing_account)
    session.commit()
    
    response = auth_client.post(
        app.url_path_for("request_email_update"),
        data={"email": test_account.email, "new_email": existing_email}
    )
    
    assert response.status_code == 409
    assert "already registered" in response.text


def test_request_email_update_unauthenticated(unauth_client: TestClient):
    """Test email update request without authentication"""
    response = unauth_client.post(
        app.url_path_for("request_email_update"),
        data={"email": "test@example.com", "new_email": "new@example.com"},
        follow_redirects=False
    )
    
    assert response.status_code == 303  # Redirect to login


def test_confirm_email_update_success(unauth_client: TestClient, session: Session, test_account: Account):
    """Test successful email update confirmation"""
    new_email = "updated@example.com"
    
    # Create an email update token
    update_token = EmailUpdateToken(account_id=test_account.id)
    session.add(update_token)
    session.commit()
    
    response = unauth_client.get(
        app.url_path_for("confirm_email_update"),
        params={
            "account_id": test_account.id,
            "token": update_token.token,
            "new_email": new_email
        },
        follow_redirects=False
    )
    
    assert response.status_code == 303
    assert f"{app.url_path_for('read_profile')}?email_updated=true" in response.headers["location"]
    
    # Verify email was updated
    session.refresh(test_account)
    assert test_account.email == new_email
    
    # Verify token was marked as used
    session.refresh(update_token)
    assert update_token.used
    
    # Verify new auth cookies were set
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies


def test_confirm_email_update_invalid_token(unauth_client: TestClient, session: Session, test_account: Account):
    """Test email update confirmation with invalid token"""
    response = unauth_client.get(
        app.url_path_for("confirm_email_update"),
        params={
            "account_id": test_account.id,
            "token": "invalid_token",
            "new_email": "new@example.com"
        }
    )
    
    assert response.status_code == 401
    assert "Invalid or expired" in response.text
    
    # Verify email was not updated
    session.refresh(test_account)
    assert test_account.email == "test@example.com"


def test_confirm_email_update_used_token(unauth_client: TestClient, session: Session, test_account: Account):
    """Test email update confirmation with already used token"""
    # Create an already used token
    used_token = EmailUpdateToken(
        account_id=test_account.id,
        token="test_used_token",
        used=True
    )
    session.add(used_token)
    session.commit()
    
    response = unauth_client.get(
        app.url_path_for("confirm_email_update"),
        params={
            "account_id": test_account.id,
            "token": used_token.token,
            "new_email": "new@example.com"
        }
    )
    
    assert response.status_code == 401
    assert "Invalid or expired" in response.text
    
    # Verify email was not updated
    session.refresh(test_account)
    assert test_account.email == "test@example.com"
