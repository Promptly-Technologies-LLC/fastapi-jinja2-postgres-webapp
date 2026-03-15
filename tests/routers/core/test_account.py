import pytest
from fastapi.testclient import TestClient
from starlette.datastructures import URLPath
from sqlmodel import Session, select
from datetime import datetime, timedelta, UTC
from urllib.parse import urlparse, parse_qs
from html import unescape
from sqlalchemy import inspect

from main import app
from utils.core.models import User, AccountEmail, AccountRecoveryToken, EmailVerificationToken, PasswordResetToken, RefreshToken, Account
from tests.conftest import htmx_headers
from utils.core.auth import (
    create_access_token,
    create_recovery_token,
    create_refresh_token,
    create_tracked_refresh_token,
    generate_recovery_url,
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


def test_register_creates_account_email_row(unauth_client: TestClient, session: Session):
    """Test that registration creates an AccountEmail row with is_primary=True and verified=True."""
    response = unauth_client.post(
        app.url_path_for("register"),
        data={
            "name": "Email Test User",
            "email": "emailtest@example.com",
            "password": "NewPass123!@#",
            "confirm_password": "NewPass123!@#"
        },
    )
    assert response.status_code == 303

    account = session.exec(select(Account).where(Account.email == "emailtest@example.com")).first()
    assert account is not None

    account_email = session.exec(
        select(AccountEmail).where(AccountEmail.account_id == account.id)
    ).first()
    assert account_email is not None
    assert account_email.email == "emailtest@example.com"
    assert account_email.is_primary is True
    assert account_email.verified is True
    assert account_email.verified_at is not None


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


def test_password_reset_auto_logs_in_and_shows_flash(
    unauth_client: TestClient, session: Session, test_account: Account
):
    """Password reset flow (standard forgot-password path):

    1. User receives a password reset email and clicks the link.
    2. User submits the reset form with a new password.
    3. Server resets the password, issues auth cookies, and redirects
       to the dashboard with a "Password reset successfully" toast.
    4. User lands on the dashboard already logged in.
    """
    # Create a valid reset token
    reset_token = PasswordResetToken(account_id=test_account.id)
    session.add(reset_token)
    session.commit()
    session.refresh(reset_token)

    response = unauth_client.post(
        app.url_path_for("reset_password"),
        data={
            "email": test_account.email,
            "token": reset_token.token,
            "password": "NewPass123!@#",
            "confirm_password": "NewPass123!@#",
        }
    )

    assert response.status_code == 303

    # Should redirect to dashboard, not login
    dashboard_path = str(app.url_path_for("read_dashboard"))
    assert dashboard_path in response.headers["location"]

    # Should set auth cookies
    cookie_headers = response.headers.get_list("set-cookie")
    assert any("access_token=" in c for c in cookie_headers)
    assert any("refresh_token=" in c for c in cookie_headers)

    # Should set a flash cookie with success message
    assert any("flash_message=" in c for c in cookie_headers)


def test_password_reset_after_recovery_auto_logs_in(
    unauth_client: TestClient, session: Session
):
    """Account recovery → password reset → auto-login flow:

    1. An attacker has compromised the account (changed primary email).
    2. The victim clicks the recovery link from a notification email.
    3. Server restores the victim's email, revokes all sessions, and
       redirects to the password reset page.
    4. Victim submits a new password on the reset form.
    5. Server resets the password, issues new auth cookies, and redirects
       to the dashboard with a success flash toast.
    6. Victim lands on the dashboard already logged in — no manual login
       required despite all prior sessions having been revoked.
    """
    original_email = "recovery-login@example.com"
    attacker_email = "attacker-login@example.com"

    account = Account(
        email=attacker_email,
        hashed_password=get_password_hash("Attacker123!@#"),
    )
    session.add(account)
    session.flush()

    # Create user so auth works
    user = User(name="Recovery User", account_id=account.id)
    session.add(user)

    attacker_account_email = AccountEmail(
        account_id=account.id, email=attacker_email,
        is_primary=True, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(attacker_account_email)

    recovery_token = AccountRecoveryToken(
        account_id=account.id, email=original_email,
    )
    session.add(recovery_token)
    session.commit()
    session.refresh(recovery_token)

    # Step 1: Hit recovery endpoint
    recovery_response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert recovery_response.status_code == 303
    reset_location = recovery_response.headers["location"]
    assert "reset_password" in reset_location
    assert f"email={original_email}" in reset_location

    # Extract reset token from redirect URL
    parsed = urlparse(reset_location)
    query_params = parse_qs(parsed.query)
    reset_token_value = query_params["token"][0]

    # Step 2: Submit password reset
    reset_response = unauth_client.post(
        app.url_path_for("reset_password"),
        data={
            "email": original_email,
            "token": reset_token_value,
            "password": "NewSecure123!@#",
            "confirm_password": "NewSecure123!@#",
        }
    )
    assert reset_response.status_code == 303

    # Should redirect to dashboard, not login
    dashboard_path = str(app.url_path_for("read_dashboard"))
    assert dashboard_path in reset_response.headers["location"]

    # Should have auth cookies
    cookie_headers = reset_response.headers.get_list("set-cookie")
    assert any("access_token=" in c for c in cookie_headers)
    assert any("refresh_token=" in c for c in cookie_headers)

    # Should have flash message
    assert any("flash_message=" in c for c in cookie_headers)


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


# --- Add Email Tests ---


def test_add_email_sends_verification(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that POST /account/emails/add creates a verification token and sends email."""
    response = auth_client.post(
        app.url_path_for("add_email"),
        data={"new_email": "secondary@example.com"},
    )
    assert response.status_code in (200, 303)

    # Verify token was created
    token = session.exec(
        select(EmailVerificationToken).where(
            EmailVerificationToken.account_id == test_account.id,
            EmailVerificationToken.new_email == "secondary@example.com",
        )
    ).first()
    assert token is not None
    assert token.used is False

    # Verify email was sent to the NEW address
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args
    assert "secondary@example.com" in call_args[0][0]["to"]


def test_add_email_already_registered_returns_409(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that adding an email already registered on another account returns 409."""
    # Create another account with an AccountEmail
    other_account = Account(email="other@example.com", hashed_password="hash")
    session.add(other_account)
    session.commit()
    other_email = AccountEmail(
        account_id=other_account.id, email="taken@example.com",
        is_primary=True, verified=True,
    )
    session.add(other_email)
    session.commit()

    response = auth_client.post(
        app.url_path_for("add_email"),
        data={"new_email": "taken@example.com"},
    )
    assert response.status_code == 409


def test_add_email_already_on_own_account_returns_409(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that adding an email already on own account returns 409."""
    response = auth_client.post(
        app.url_path_for("add_email"),
        data={"new_email": test_account_email.email},
    )
    assert response.status_code == 409


def test_add_email_max_limit_returns_400(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that adding a 3rd email returns 400 when account already has 2."""
    # Add a second email to reach the limit
    second_email = AccountEmail(
        account_id=test_account.id, email="second@example.com",
        is_primary=False, verified=True,
    )
    session.add(second_email)
    session.commit()

    response = auth_client.post(
        app.url_path_for("add_email"),
        data={"new_email": "third@example.com"},
    )
    assert response.status_code == 400


def test_add_email_unauthenticated_redirects(unauth_client: TestClient):
    """Test that unauthenticated users are redirected."""
    response = unauth_client.post(
        app.url_path_for("add_email"),
        data={"new_email": "new@example.com"},
    )
    assert response.status_code == 303


def test_add_email_suppresses_duplicate_token(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that a second request for the same email doesn't create a duplicate token."""
    # Create an existing unexpired token
    existing_token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="dupe@example.com",
    )
    session.add(existing_token)
    session.commit()

    response = auth_client.post(
        app.url_path_for("add_email"),
        data={"new_email": "dupe@example.com"},
    )
    assert response.status_code in (200, 303)

    # Should still only have 1 token
    tokens = session.exec(
        select(EmailVerificationToken).where(
            EmailVerificationToken.account_id == test_account.id,
            EmailVerificationToken.new_email == "dupe@example.com",
        )
    ).all()
    assert len(tokens) == 1
    mock_resend_send.assert_not_called()


# --- Verify Email Tests ---


def test_verify_email_creates_account_email(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that clicking a valid verification link creates an AccountEmail row."""
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="verified@example.com",
    )
    session.add(token)
    session.commit()

    response = auth_client.get(
        app.url_path_for("verify_email"),
        params={"token": token.token},
    )
    assert response.status_code == 303

    # Verify AccountEmail was created
    account_email = session.exec(
        select(AccountEmail).where(
            AccountEmail.account_id == test_account.id,
            AccountEmail.email == "verified@example.com",
        )
    ).first()
    assert account_email is not None
    assert account_email.is_primary is False
    assert account_email.verified is True

    # Token should be marked as used
    session.refresh(token)
    assert token.used is True


def test_verify_email_invalid_token_returns_401(
    auth_client: TestClient, test_account_email
):
    """Test that an invalid token returns 401."""
    response = auth_client.get(
        app.url_path_for("verify_email"),
        params={"token": "nonexistent-token"},
    )
    assert response.status_code == 401


def test_verify_email_expired_token_returns_401(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that an expired token returns 401."""
    from datetime import timedelta as td
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="expired@example.com",
        expires_at=datetime.now(UTC) - td(hours=1),
    )
    session.add(token)
    session.commit()

    response = auth_client.get(
        app.url_path_for("verify_email"),
        params={"token": token.token},
    )
    assert response.status_code == 401


def test_verify_email_used_token_returns_401(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that a used token returns 401."""
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="used@example.com",
        used=True,
    )
    session.add(token)
    session.commit()

    response = auth_client.get(
        app.url_path_for("verify_email"),
        params={"token": token.token},
    )
    assert response.status_code == 401


def test_verify_email_sends_notification_to_primary(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that a notification is sent to the primary email after verification."""
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="notify@example.com",
    )
    session.add(token)
    session.commit()

    response = auth_client.get(
        app.url_path_for("verify_email"),
        params={"token": token.token},
    )
    assert response.status_code == 303

    # Notification should have been sent to the primary email
    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args
    assert test_account.email in call_args[0][0]["to"]


def test_verify_email_unauthenticated_redirects_to_login(
    unauth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Email verification flow when session has expired or link opened in another browser:

    1. User adds a secondary email and receives a verification link.
    2. User clicks the link in their email (cross-site navigation, so
       samesite=strict auth cookies are not sent).
    3. Server verifies the email, adds it to the account, and redirects
       to the login page with a success flash toast.
    4. User sees "Email address verified and added to your account." on
       the login page, logs in, and continues normally.
    """
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="unauth-verify@example.com",
    )
    session.add(token)
    session.commit()

    response = unauth_client.get(
        app.url_path_for("verify_email"),
        params={"token": token.token},
    )
    assert response.status_code == 303
    assert "/account/login" in response.headers["location"]

    # Flash cookie should be set
    assert "flash_message" in response.cookies

    # Email should still be verified
    account_email = session.exec(
        select(AccountEmail).where(
            AccountEmail.account_id == test_account.id,
            AccountEmail.email == "unauth-verify@example.com",
        )
    ).first()
    assert account_email is not None
    assert account_email.verified is True


def test_verify_email_race_condition_email_taken(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that if email was taken between request and verify, return 409."""
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="raced@example.com",
    )
    session.add(token)
    session.commit()

    # Simulate race condition: another account takes the email
    other_account = Account(email="other2@example.com", hashed_password="hash")
    session.add(other_account)
    session.commit()
    other_email = AccountEmail(
        account_id=other_account.id, email="raced@example.com",
        is_primary=True, verified=True,
    )
    session.add(other_email)
    session.commit()

    response = auth_client.get(
        app.url_path_for("verify_email"),
        params={"token": token.token},
    )
    assert response.status_code == 409


# --- Promote Email Tests ---


def test_promote_email_swaps_primary(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that promoting a secondary email swaps primary flags."""
    secondary = AccountEmail(
        account_id=test_account.id, email="secondary@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": secondary.id},
    )
    assert response.status_code == 303

    session.refresh(test_account_email)
    session.refresh(secondary)
    assert secondary.is_primary is True
    assert test_account_email.is_primary is False


def test_promote_email_updates_account_email_field(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that Account.email is updated to the new primary."""
    secondary = AccountEmail(
        account_id=test_account.id, email="newprimary@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": secondary.id},
    )
    assert response.status_code == 303

    session.refresh(test_account)
    assert test_account.email == "newprimary@example.com"


def test_promote_email_revokes_refresh_tokens(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that all refresh tokens are revoked and new ones issued."""
    secondary = AccountEmail(
        account_id=test_account.id, email="promoted@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": secondary.id},
    )
    assert response.status_code == 303

    # New cookies should be set
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies


def test_promote_email_sends_notification_to_old_primary(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that a notification is sent to the old primary email."""
    old_primary_email = test_account.email
    secondary = AccountEmail(
        account_id=test_account.id, email="notified@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": secondary.id},
    )
    assert response.status_code == 303

    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args
    assert old_primary_email in call_args[0][0]["to"]


def test_promote_email_unverified_fails_400(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that promoting an unverified email returns 400."""
    unverified = AccountEmail(
        account_id=test_account.id, email="unverified@example.com",
        is_primary=False, verified=False,
    )
    session.add(unverified)
    session.commit()
    session.refresh(unverified)

    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": unverified.id},
    )
    assert response.status_code == 400


def test_promote_email_not_owned_returns_404(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that promoting an email not owned by the account returns 404."""
    other_account = Account(email="other3@example.com", hashed_password="hash")
    session.add(other_account)
    session.commit()
    other_email = AccountEmail(
        account_id=other_account.id, email="notmine@example.com",
        is_primary=True, verified=True,
    )
    session.add(other_email)
    session.commit()
    session.refresh(other_email)

    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": other_email.id},
    )
    assert response.status_code == 404


def test_promote_email_already_primary_is_noop(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that promoting the current primary is a no-op redirect."""
    response = auth_client.post(
        app.url_path_for("promote_email"),
        data={"email_id": test_account_email.id},
    )
    # Should redirect without error
    assert response.status_code == 303


# --- Remove Email Tests ---


def test_remove_secondary_email_succeeds(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that removing a secondary email deletes the AccountEmail row."""
    secondary = AccountEmail(
        account_id=test_account.id, email="removeme@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)
    secondary_id = secondary.id

    response = auth_client.post(
        app.url_path_for("remove_email"),
        data={"email_id": secondary.id},
    )
    assert response.status_code == 303

    # Verify the email was deleted
    remaining = session.exec(
        select(AccountEmail).where(AccountEmail.id == secondary_id)
    ).first()
    assert remaining is None


def test_remove_primary_email_fails_400(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that removing the primary email returns 400."""
    response = auth_client.post(
        app.url_path_for("remove_email"),
        data={"email_id": test_account_email.id},
    )
    assert response.status_code == 400


def test_remove_email_not_owned_returns_404(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that removing an email not owned by the account returns 404."""
    other_account = Account(email="other4@example.com", hashed_password="hash")
    session.add(other_account)
    session.commit()
    other_email = AccountEmail(
        account_id=other_account.id, email="notmine2@example.com",
        is_primary=True, verified=True,
    )
    session.add(other_email)
    session.commit()
    session.refresh(other_email)

    response = auth_client.post(
        app.url_path_for("remove_email"),
        data={"email_id": other_email.id},
    )
    assert response.status_code == 404


def test_remove_email_sends_notification(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that a notification is sent to the removed email address."""
    secondary = AccountEmail(
        account_id=test_account.id, email="goodbye@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    response = auth_client.post(
        app.url_path_for("remove_email"),
        data={"email_id": secondary.id},
    )
    assert response.status_code == 303

    mock_resend_send.assert_called_once()
    call_args = mock_resend_send.call_args
    assert "goodbye@example.com" in call_args[0][0]["to"]


def test_remove_email_unauthenticated_redirects(unauth_client: TestClient):
    """Test that unauthenticated users are redirected."""
    response = unauth_client.post(
        app.url_path_for("remove_email"),
        data={"email_id": 1},
    )
    assert response.status_code == 303


# --- Profile UI Tests ---


def test_profile_shows_all_emails(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that profile page shows all email addresses."""
    secondary = AccountEmail(
        account_id=test_account.id, email="profile-secondary@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()

    response = auth_client.get(app.url_path_for("read_profile"))
    assert response.status_code == 200
    assert test_account.email in response.text
    assert "profile-secondary@example.com" in response.text


def test_profile_shows_primary_badge(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that profile page shows primary badge."""
    response = auth_client.get(app.url_path_for("read_profile"))
    assert response.status_code == 200
    assert "Primary" in response.text


def test_profile_shows_add_form_when_under_limit(
    auth_client: TestClient, test_account_email, session: Session
):
    """Test that add email form is shown when under the limit."""
    response = auth_client.get(app.url_path_for("read_profile"))
    assert response.status_code == 200
    assert "/account/emails/add" in response.text


def test_profile_hides_add_form_at_limit(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session
):
    """Test that add email form is hidden when at the limit."""
    secondary = AccountEmail(
        account_id=test_account.id, email="limit@example.com",
        is_primary=False, verified=True,
    )
    session.add(secondary)
    session.commit()

    response = auth_client.get(app.url_path_for("read_profile"))
    assert response.status_code == 200
    # The add form should not be present
    assert "Add Email" not in response.text


# --- Account Recovery Token Helper Tests ---


def test_generate_recovery_url(monkeypatch):
    """Test that generate_recovery_url returns the correct URL."""
    monkeypatch.setenv("BASE_URL", "https://example.com")
    url = generate_recovery_url("abc123")
    assert url == "https://example.com/account/recover?token=abc123"


def test_create_recovery_token(
    test_account: Account, session: Session
):
    """Test that create_recovery_token creates a DB row and returns the token string."""
    token_str = create_recovery_token(test_account.id, "victim@example.com", session)
    session.commit()

    assert token_str is not None
    # Verify DB row
    db_token = session.exec(
        select(AccountRecoveryToken).where(AccountRecoveryToken.token == token_str)
    ).first()
    assert db_token is not None
    assert db_token.account_id == test_account.id
    assert db_token.email == "victim@example.com"
    assert db_token.used is False
    assert db_token.expires_at.replace(tzinfo=UTC) > datetime.now(UTC) + timedelta(days=6)


def test_create_recovery_token_deduplicates(
    test_account: Account, session: Session
):
    """Test that create_recovery_token returns existing token if unexpired one exists."""
    token1 = create_recovery_token(test_account.id, "victim@example.com", session)
    session.commit()
    token2 = create_recovery_token(test_account.id, "victim@example.com", session)
    session.commit()

    assert token1 == token2
    # Only one token in DB
    count = len(session.exec(
        select(AccountRecoveryToken).where(
            AccountRecoveryToken.account_id == test_account.id,
            AccountRecoveryToken.email == "victim@example.com",
        )
    ).all())
    assert count == 1


# --- Notification function tests (recovery URL) ---


def test_send_primary_email_changed_notification_includes_recovery_url(
    mock_resend_send, monkeypatch
):
    """Test that primary email changed notification includes recovery URL in HTML."""
    from utils.core.auth import send_primary_email_changed_notification
    monkeypatch.setenv("EMAIL_FROM", "noreply@test.com")
    monkeypatch.setenv("RESEND_API_KEY", "test_key")

    send_primary_email_changed_notification(
        "old@example.com", "new@example.com",
        recovery_url="https://example.com/account/recover?token=abc123"
    )

    mock_resend_send.assert_called_once()
    html = mock_resend_send.call_args[0][0]["html"]
    assert "https://example.com/account/recover?token=abc123" in html
    assert "Recover Your Account" in html


def test_promote_email_creates_recovery_token(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that promoting an email creates an AccountRecoveryToken for the old primary."""
    old_primary_email = test_account.email
    secondary = AccountEmail(
        account_id=test_account.id, email="attacker@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    auth_client.post(app.url_path_for("promote_email"), data={"email_id": secondary.id})

    recovery_token = session.exec(
        select(AccountRecoveryToken).where(
            AccountRecoveryToken.account_id == test_account.id,
            AccountRecoveryToken.email == old_primary_email,
        )
    ).first()
    assert recovery_token is not None
    assert recovery_token.used is False


def test_promote_email_notification_contains_recovery_url(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that the promote notification email contains a recovery URL."""
    secondary = AccountEmail(
        account_id=test_account.id, email="attacker2@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    auth_client.post(app.url_path_for("promote_email"), data={"email_id": secondary.id})

    mock_resend_send.assert_called_once()
    html = mock_resend_send.call_args[0][0]["html"]
    assert "/account/recover?token=" in html


def test_remove_email_creates_recovery_token(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that removing an email creates an AccountRecoveryToken for the removed email."""
    secondary = AccountEmail(
        account_id=test_account.id, email="removed@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    auth_client.post(app.url_path_for("remove_email"), data={"email_id": secondary.id})

    recovery_token = session.exec(
        select(AccountRecoveryToken).where(
            AccountRecoveryToken.account_id == test_account.id,
            AccountRecoveryToken.email == "removed@example.com",
        )
    ).first()
    assert recovery_token is not None
    assert recovery_token.used is False


def test_remove_email_notification_contains_recovery_url(
    auth_client: TestClient, test_account: Account, test_account_email, session: Session, mock_resend_send
):
    """Test that the remove notification email contains a recovery URL."""
    secondary = AccountEmail(
        account_id=test_account.id, email="removed2@example.com",
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(secondary)
    session.commit()
    session.refresh(secondary)

    auth_client.post(app.url_path_for("remove_email"), data={"email_id": secondary.id})

    mock_resend_send.assert_called_once()
    html = mock_resend_send.call_args[0][0]["html"]
    assert "/account/recover?token=" in html


def test_send_email_removed_notification_includes_recovery_url(
    mock_resend_send, monkeypatch
):
    """Test that email removed notification includes recovery URL in HTML."""
    from utils.core.auth import send_email_removed_notification
    monkeypatch.setenv("EMAIL_FROM", "noreply@test.com")
    monkeypatch.setenv("RESEND_API_KEY", "test_key")

    send_email_removed_notification(
        "removed@example.com",
        recovery_url="https://example.com/account/recover?token=xyz789"
    )

    mock_resend_send.assert_called_once()
    html = mock_resend_send.call_args[0][0]["html"]
    assert "https://example.com/account/recover?token=xyz789" in html
    assert "Recover Your Account" in html


# --- Account Recovery Route Tests ---


def _setup_compromised_account(session: Session) -> tuple:
    """Helper: create an account that has been taken over by an attacker.
    Returns (account, recovery_token, original_email).
    """
    original_email = "victim@example.com"
    attacker_email = "attacker@example.com"

    account = Account(
        email=attacker_email,
        hashed_password=get_password_hash("Attacker123!@#"),
    )
    session.add(account)
    session.flush()

    # Attacker's email is now primary
    attacker_account_email = AccountEmail(
        account_id=account.id, email=attacker_email,
        is_primary=True, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(attacker_account_email)

    # Create recovery token for the victim's original email
    recovery_token = AccountRecoveryToken(
        account_id=account.id,
        email=original_email,
    )
    session.add(recovery_token)
    session.commit()
    session.refresh(recovery_token)

    return account, recovery_token, original_email


def test_recover_account_restores_email_as_primary(
    unauth_client: TestClient, session: Session
):
    """Test that recovery restores the victim's email as primary."""
    account, recovery_token, original_email = _setup_compromised_account(session)

    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert response.status_code == 303

    session.refresh(account)
    assert account.email == original_email

    primary = session.exec(
        select(AccountEmail).where(
            AccountEmail.account_id == account.id,
            AccountEmail.is_primary == True,  # noqa: E712
        )
    ).first()
    assert primary is not None
    assert primary.email == original_email


def test_recover_account_removes_attacker_emails(
    unauth_client: TestClient, session: Session
):
    """Test that recovery removes all existing AccountEmail rows (attacker's emails)."""
    account, recovery_token, original_email = _setup_compromised_account(session)

    unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )

    all_emails = session.exec(
        select(AccountEmail).where(AccountEmail.account_id == account.id)
    ).all()
    assert len(all_emails) == 1
    assert all_emails[0].email == original_email


def test_recover_account_revokes_all_sessions(
    unauth_client: TestClient, session: Session
):
    """Test that recovery revokes all refresh tokens."""
    account, recovery_token, _ = _setup_compromised_account(session)

    # Create a refresh token for the account
    rt = RefreshToken(account_id=account.id, expires_at=datetime.now(UTC) + timedelta(days=30))
    session.add(rt)
    session.commit()

    unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )

    session.refresh(rt)
    assert rt.revoked is True


def test_recover_account_generates_password_reset_token(
    unauth_client: TestClient, session: Session
):
    """Test that recovery creates a PasswordResetToken."""
    account, recovery_token, _ = _setup_compromised_account(session)

    unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )

    reset_token = session.exec(
        select(PasswordResetToken).where(
            PasswordResetToken.account_id == account.id,
            PasswordResetToken.used == False,  # noqa: E712
        )
    ).first()
    assert reset_token is not None


def test_recover_account_redirects_to_reset_password(
    unauth_client: TestClient, session: Session
):
    """Test that recovery redirects to the reset password page."""
    account, recovery_token, original_email = _setup_compromised_account(session)

    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert "/account/reset_password" in location
    assert f"email={original_email}" in location


def test_recover_account_marks_token_used(
    unauth_client: TestClient, session: Session
):
    """Test that the recovery token is marked as used after recovery."""
    account, recovery_token, _ = _setup_compromised_account(session)

    unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )

    session.refresh(recovery_token)
    assert recovery_token.used is True


def test_recover_account_expired_token_fails(
    unauth_client: TestClient, session: Session
):
    """Test that an expired recovery token fails."""
    account, recovery_token, _ = _setup_compromised_account(session)
    recovery_token.expires_at = datetime.now(UTC) - timedelta(hours=1)
    session.commit()

    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert response.status_code == 401


def test_recover_account_used_token_fails(
    unauth_client: TestClient, session: Session
):
    """Test that a used recovery token fails."""
    account, recovery_token, _ = _setup_compromised_account(session)
    recovery_token.used = True
    session.commit()

    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert response.status_code == 401


def test_recover_account_invalid_token_fails(
    unauth_client: TestClient, session: Session
):
    """Test that a nonexistent recovery token fails."""
    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": "nonexistent-token"},
    )
    assert response.status_code == 401


def test_recover_account_readds_removed_email(
    unauth_client: TestClient, session: Session
):
    """Test recovery works when the email was fully removed (no AccountEmail row)."""
    original_email = "victim2@example.com"
    account = Account(
        email="attacker2@example.com",
        hashed_password=get_password_hash("Attacker123!@#"),
    )
    session.add(account)
    session.flush()

    # No AccountEmail rows at all (simulating complete takeover)
    recovery_token = AccountRecoveryToken(
        account_id=account.id,
        email=original_email,
    )
    session.add(recovery_token)
    session.commit()
    session.refresh(recovery_token)

    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert response.status_code == 303

    session.refresh(account)
    assert account.email == original_email


def test_recover_account_when_victim_email_still_exists_as_account_email(
    unauth_client: TestClient, session: Session
):
    """Account recovery when the victim's email is still on the account:

    1. Attacker promoted their email to primary; victim's email was demoted
       to secondary (still exists as an AccountEmail row).
    2. Victim clicks the recovery link from the notification email.
    3. Server deletes ALL AccountEmail rows (including the victim's
       secondary), then re-creates the victim's email as the sole primary.
    4. Server revokes all sessions and redirects to password reset.

    This scenario requires flushing the deletes before the insert to avoid
    a unique constraint violation (SQLAlchemy processes INSERTs before
    DELETEs within a single autoflush).
    """
    original_email = "victim-swap@example.com"
    attacker_email = "attacker-swap@example.com"

    account = Account(
        email=attacker_email,
        hashed_password=get_password_hash("Attacker123!@#"),
    )
    session.add(account)
    session.flush()

    # After a primary swap: attacker email is primary, victim email is still present as secondary
    attacker_account_email = AccountEmail(
        account_id=account.id, email=attacker_email,
        is_primary=True, verified=True, verified_at=datetime.now(UTC),
    )
    victim_account_email = AccountEmail(
        account_id=account.id, email=original_email,
        is_primary=False, verified=True, verified_at=datetime.now(UTC),
    )
    session.add(attacker_account_email)
    session.add(victim_account_email)

    recovery_token = AccountRecoveryToken(
        account_id=account.id,
        email=original_email,
    )
    session.add(recovery_token)
    session.commit()
    session.refresh(recovery_token)

    response = unauth_client.get(
        app.url_path_for("recover_account"),
        params={"token": recovery_token.token},
    )
    assert response.status_code == 303

    # Verify the victim's email is now the only AccountEmail and is primary
    session.refresh(account)
    assert account.email == original_email

    all_emails = session.exec(
        select(AccountEmail).where(AccountEmail.account_id == account.id)
    ).all()
    assert len(all_emails) == 1
    assert all_emails[0].email == original_email
    assert all_emails[0].is_primary is True

    restored = session.exec(
        select(AccountEmail).where(
            AccountEmail.account_id == account.id,
            AccountEmail.email == original_email,
        )
    ).first()
    assert restored is not None
    assert restored.is_primary is True
    assert restored.verified is True
