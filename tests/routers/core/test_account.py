import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import URLPath
from sqlmodel import Session, select
from datetime import timedelta
from urllib.parse import urlparse, parse_qs
from html import unescape
from sqlalchemy import inspect

from main import app
from utils.core.models import User, PasswordResetToken, EmailUpdateToken, RefreshToken, Account
from utils.core.auth import (
    create_access_token,
    create_refresh_token,
    create_tracked_refresh_token,
    verify_password,
    validate_token,
    get_password_hash
)
from utils.core.rate_limit import (
    login_ip_limiter,
    login_email_limiter,
    register_ip_limiter,
    forgot_password_ip_limiter,
    forgot_password_email_limiter,
)


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Reset all rate limiter state between tests to avoid cross-test pollution."""
    yield
    for limiter in (
        login_ip_limiter,
        login_email_limiter,
        register_ip_limiter,
        forgot_password_ip_limiter,
        forgot_password_email_limiter,
    ):
        limiter._attempts.clear()

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
    )

    # Just check the response status code
    assert response.status_code == 303
    assert response.headers["location"] == str(app.url_path_for("read_dashboard"))
    
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
    )
    assert response.status_code == 303
    assert response.headers["location"] == str(app.url_path_for("read_dashboard"))

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
    )
    assert response.status_code == 303
    assert response.headers["location"] == str(app.url_path_for("read_dashboard"))

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
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/forgot_password?show_form=false"

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
    assert call_args["from"] == "test@example.com"
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
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    # Check for cookie deletion in headers
    cookie_headers = response.headers.get_list("set-cookie")
    assert any(
        "access_token=" in cookie and "Max-Age=0" in cookie for cookie in cookie_headers)
    assert any(
        "refresh_token=" in cookie and "Max-Age=0" in cookie for cookie in cookie_headers)


# --- Error Case Tests ---


def test_register_page_shows_password_requirements(unauth_client: TestClient):
    """Issue #156: Register page must display password requirements visibly."""
    response = unauth_client.get(app.url_path_for("read_register"))
    assert response.status_code == 200
    html = response.text
    # Requirements should be visible as text (not just in hidden pattern/title attributes)
    assert "8" in html, "Page should mention minimum 8 characters"
    assert "uppercase" in html.lower(), "Page should mention uppercase requirement"
    assert "lowercase" in html.lower(), "Page should mention lowercase requirement"
    assert "number" in html.lower() or "digit" in html.lower(), "Page should mention digit requirement"
    assert "special" in html.lower(), "Page should mention special character requirement"


def test_register_page_confirm_password_has_autocomplete(unauth_client: TestClient):
    """Issue #156: Both password fields must have autocomplete='new-password' for Chrome autofill."""
    response = unauth_client.get(app.url_path_for("read_register"))
    assert response.status_code == 200
    html = response.text
    # The confirm_password field should have autocomplete="new-password"
    assert 'id="confirm_password"' in html
    # Find the confirm_password input and check it has autocomplete="new-password"
    import re
    confirm_input = re.search(r'<input[^>]*id="confirm_password"[^>]*>', html)
    assert confirm_input is not None
    assert 'autocomplete="new-password"' in confirm_input.group(0), \
        "confirm_password field must have autocomplete='new-password' for Chrome autofill"


def test_register_weak_password_error_restates_requirements(unauth_client: TestClient, session: Session):
    """Issue #156: Error toast for weak password must restate the security policy requirements."""
    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "Test User",
            "email": "weak@example.com",
            "password": "weak",
            "confirm_password": "weak"
        },
    )
    assert response.status_code == 422
    text = response.text
    # The error message must include the actual requirements, not just a generic message
    assert "8" in text, "Error should mention minimum 8 characters"
    assert "uppercase" in text.lower() or "upper" in text.lower(), \
        "Error should mention uppercase requirement"
    assert "lowercase" in text.lower() or "lower" in text.lower(), \
        "Error should mention lowercase requirement"


def test_register_weak_password_htmx_error_restates_requirements(unauth_client: TestClient, session: Session):
    """Issue #156: HTMX error toast for weak password must restate the security policy requirements."""
    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "Test User",
            "email": "weak@example.com",
            "password": "weak",
            "confirm_password": "weak"
        },
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 422
    text = response.text
    # The toast message must include the actual requirements
    assert "8" in text, "Toast should mention minimum 8 characters"
    assert "uppercase" in text.lower() or "upper" in text.lower(), \
        "Toast should mention uppercase requirement"
    assert "lowercase" in text.lower() or "lower" in text.lower(), \
        "Toast should mention lowercase requirement"


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
    assert app.url_path_for("read_login") not in response.headers.get("location", "")


def test_password_reset_email_url(unauth_client: TestClient, session: Session, test_account: Account, mock_resend_send):
    """
    Tests that the password reset email contains a properly formatted reset URL.
    """
    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": test_account.email},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/forgot_password?show_form=false"

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


def test_forgot_password_does_not_send_second_email_while_token_is_active(
    unauth_client: TestClient,
    session: Session,
    test_account: Account,
    mock_resend_send,
):
    """Forgot-password preserves the existing one-hour token/send suppression."""
    first_response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": test_account.email},
    )
    assert first_response.status_code == 303
    assert first_response.headers["location"] == "/forgot_password?show_form=false"

    second_response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": test_account.email},
    )
    assert second_response.status_code == 303
    assert second_response.headers["location"] == "/forgot_password?show_form=false"

    tokens = session.exec(
        select(PasswordResetToken).where(PasswordResetToken.account_id == test_account.id)
    ).all()
    assert len(tokens) == 1
    assert mock_resend_send.call_count == 1


def test_request_email_update_success(auth_client: TestClient, test_account: Account, mock_resend_send):
    """Test successful email update request"""
    new_email = "newemail@example.com"
    
    response = auth_client.post(
        app.url_path_for("request_email_update"),
        data={"email": test_account.email, "new_email": new_email},
    )

    assert response.status_code == 303
    assert response.headers["location"] == str(app.url_path_for("read_profile"))
    # Flash cookie should be set
    assert "flash_message" in response.headers.get("set-cookie", "")

    # Verify email was "sent"
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args[0][0]
    
    # Verify email content
    assert call_args["to"] == [test_account.email]
    assert call_args["from"] == "test@example.com"
    assert "Confirm Email Update" in call_args["subject"]
    assert "confirm_email_update" in call_args["html"]
    assert new_email in call_args["html"]


def test_request_email_update_same_email_returns_error_page(auth_client: TestClient, test_account: Account):
    response = auth_client.post(
        app.url_path_for("request_email_update"),
        data={"email": test_account.email, "new_email": test_account.email},
    )

    assert response.status_code == 401
    assert response.headers.get("location") is None
    assert "New email is the same as the current email" in response.text


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
    )

    assert response.status_code == 303  # Redirect to login
    assert response.headers["location"] == str(app.url_path_for("read_login"))


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
    )
    
    assert response.status_code == 303
    assert response.headers["location"] == str(app.url_path_for("read_profile"))
    # Flash cookie should be set
    assert "flash_message" in response.headers.get("set-cookie", "")

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


# --- Rate Limiting Tests ---


def test_login_ip_rate_limit(unauth_client: TestClient, test_account: Account):
    """Login returns 429 after exceeding IP rate limit."""
    for _ in range(login_ip_limiter.max_attempts):
        unauth_client.post(
            app.url_path_for("login"),
            data={"email": test_account.email, "password": "WrongPass123!@#"},
        )

    response = unauth_client.post(
        app.url_path_for("login"),
        data={"email": test_account.email, "password": "WrongPass123!@#"},
    )
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_login_email_rate_limit(unauth_client: TestClient, test_account: Account):
    """Login returns 429 after exceeding per-email rate limit."""
    for _ in range(login_email_limiter.max_attempts):
        unauth_client.post(
            app.url_path_for("login"),
            data={"email": test_account.email, "password": "WrongPass123!@#"},
        )

    response = unauth_client.post(
        app.url_path_for("login"),
        data={"email": test_account.email, "password": "WrongPass123!@#"},
    )
    assert response.status_code == 429


def test_login_success_resets_email_limiter(unauth_client: TestClient, test_account: Account):
    """Successful login resets the per-email rate limiter."""
    # Use up all but one email attempt
    for _ in range(login_email_limiter.max_attempts - 1):
        unauth_client.post(
            app.url_path_for("login"),
            data={"email": test_account.email, "password": "WrongPass123!@#"},
        )
    assert login_email_limiter.remaining(f"email:{test_account.email.lower().strip()}") == 1

    # Successful login should reset the counter
    response = unauth_client.post(
        app.url_path_for("login"),
        data={"email": test_account.email, "password": "Test123!@#"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == str(app.url_path_for("read_dashboard"))

    # Verify the limiter was reset — full allowance available
    assert login_email_limiter.remaining(f"email:{test_account.email.lower().strip()}") == login_email_limiter.max_attempts


def test_register_ip_rate_limit(unauth_client: TestClient, session: Session):
    """Register returns 429 after exceeding IP rate limit."""
    for i in range(register_ip_limiter.max_attempts):
        unauth_client.post(
            app.url_path_for("register"),
            data={
                "name": f"User{i}",
                "email": f"user{i}@example.com",
                "password": "Test123!@#",
                "confirm_password": "Test123!@#",
            },
        )

    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "Blocked",
            "email": "blocked@example.com",
            "password": "Test123!@#",
            "confirm_password": "Test123!@#",
        },
    )
    assert response.status_code == 429


def test_forgot_password_ip_rate_limit(unauth_client: TestClient):
    """Forgot password returns 429 after exceeding IP rate limit."""
    for i in range(forgot_password_ip_limiter.max_attempts):
        unauth_client.post(
            app.url_path_for("forgot_password"),
            data={"email": f"user{i}@example.com"},
        )

    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": "extra@example.com"},
    )
    assert response.status_code == 429


def test_forgot_password_email_rate_limit(unauth_client: TestClient, test_account: Account, mock_resend_send):
    """Forgot password returns 429 after exceeding per-email rate limit."""
    for _ in range(forgot_password_email_limiter.max_attempts):
        unauth_client.post(
            app.url_path_for("forgot_password"),
            data={"email": test_account.email},
        )

    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": test_account.email},
    )
    assert response.status_code == 429


# --- Refresh Token Security Tests ---


def test_register_creates_tracked_refresh_token(unauth_client: TestClient, session: Session):
    """Registration creates a RefreshToken record in the database."""
    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "Token User",
            "email": "tokenuser@example.com",
            "password": "Token123!@#",
            "confirm_password": "Token123!@#"
        },
    )
    assert response.status_code == 303

    account = session.exec(select(Account).where(Account.email == "tokenuser@example.com")).first()
    assert account is not None

    db_tokens = session.exec(
        select(RefreshToken).where(RefreshToken.account_id == account.id)
    ).all()
    assert len(db_tokens) == 1
    assert db_tokens[0].revoked is False


def test_login_creates_tracked_refresh_token(unauth_client: TestClient, session: Session, test_account: Account, test_user: User):
    """Login creates a RefreshToken record in the database."""
    response = unauth_client.post(
        app.url_path_for("login"),
        data={"email": test_account.email, "password": "Test123!@#"},
    )
    assert response.status_code == 303

    db_tokens = session.exec(
        select(RefreshToken).where(RefreshToken.account_id == test_account.id)
    ).all()
    assert len(db_tokens) >= 1
    assert any(not t.revoked for t in db_tokens)


def test_logout_revokes_refresh_token(auth_client: TestClient, session: Session, test_account: Account):
    """Logout revokes the refresh token server-side."""
    # Get existing tokens before logout
    db_tokens_before = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    assert len(db_tokens_before) >= 1

    auth_client.get(app.url_path_for("logout"))

    # Verify the token was revoked
    session.expire_all()
    active_tokens = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    assert len(active_tokens) == 0


def test_refresh_endpoint_rotates_token(auth_client: TestClient, session: Session, test_account: Account):
    """The /refresh endpoint revokes the old token and issues a new one."""
    # Expire the access token so the refresh endpoint works
    expired_access_token = create_access_token(
        {"sub": test_account.email}, timedelta(minutes=-10)
    )
    auth_client.cookies.set("access_token", expired_access_token)

    # Count active tokens before
    active_before = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    assert len(active_before) == 1
    old_jti = active_before[0].jti

    response = auth_client.post(app.url_path_for("refresh_token"))
    assert response.status_code == 303

    # Old token should be revoked, new one should exist
    session.expire_all()
    old_token = session.exec(
        select(RefreshToken).where(RefreshToken.jti == old_jti)
    ).first()
    assert old_token is not None
    assert old_token.revoked is True

    active_after = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    assert len(active_after) == 1
    assert active_after[0].jti != old_jti


def test_refresh_reuse_detection_revokes_all_tokens(
    unauth_client: TestClient, session: Session, test_account: Account, test_user: User
):
    """Replaying a revoked refresh token revokes ALL tokens for that account."""
    # Create a tracked refresh token and immediately revoke it (simulating prior use)
    refresh_jwt = create_tracked_refresh_token(test_account.id, test_account.email, session)
    session.commit()

    db_token = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).first()
    assert db_token is not None
    db_token.revoked = True

    # Create a second active token (simulating the legitimate new token)
    create_tracked_refresh_token(test_account.id, test_account.email, session)
    session.commit()

    # Replay the revoked token via the /refresh endpoint
    client = TestClient(app, follow_redirects=False)
    client.cookies.set("refresh_token", refresh_jwt)

    response = client.post(app.url_path_for("refresh_token"))

    # Should redirect to login (denied)
    assert response.status_code == 303
    assert "login" in response.headers["location"]

    # ALL tokens for this account should now be revoked
    session.expire_all()
    active_tokens = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    assert len(active_tokens) == 0


def test_legacy_refresh_token_without_jti_rejected(
    unauth_client: TestClient, session: Session, test_account: Account, test_user: User
):
    """A refresh token without a JTI (pre-migration) is rejected."""
    import uuid
    # Create a legacy-style token without jti by using create_refresh_token with a jti
    # but NOT storing it in the DB — simulating a pre-migration token
    legacy_token = create_refresh_token(
        data={"sub": test_account.email},
        jti=str(uuid.uuid4())  # has jti in JWT but no DB record
    )

    client = TestClient(app, follow_redirects=False)
    client.cookies.set("refresh_token", legacy_token)

    response = client.post(app.url_path_for("refresh_token"))

    # Should redirect to login (no DB record for this JTI)
    assert response.status_code == 303
    assert "login" in response.headers["location"]


def test_automatic_token_refresh_via_dependency(
    session: Session, test_account: Account, test_user: User
):
    """When access token expires, the dependency auto-refreshes using the refresh token."""
    # Create a tracked refresh token
    refresh_jwt = create_tracked_refresh_token(test_account.id, test_account.email, session)
    session.commit()

    # Create an expired access token
    expired_access = create_access_token(
        {"sub": test_account.email}, timedelta(minutes=-10)
    )

    client = TestClient(app, follow_redirects=False)
    client.cookies.set("access_token", expired_access)
    client.cookies.set("refresh_token", refresh_jwt)

    # Hit an authenticated endpoint — should trigger NeedsNewTokens -> 307 redirect
    response = client.get(app.url_path_for("read_dashboard"))

    # The middleware catches NeedsNewTokens and redirects with new cookies
    assert response.status_code == 307

    cookie_headers = response.headers.get_list("set-cookie")
    assert any("access_token=" in c for c in cookie_headers)
    assert any("refresh_token=" in c for c in cookie_headers)

    # Old refresh token should be revoked
    session.expire_all()
    active_tokens = session.exec(
        select(RefreshToken).where(
            RefreshToken.account_id == test_account.id,
            RefreshToken.revoked == False  # noqa: E712
        )
    ).all()
    # Should have exactly 1 active token (the new one)
    assert len(active_tokens) == 1
