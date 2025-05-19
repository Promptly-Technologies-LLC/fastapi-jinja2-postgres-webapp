import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from sqlalchemy.orm import joinedload
from urllib.parse import urlparse, parse_qs

from main import app
from utils.core.models import User, Account, Invitation

# --- Test Scenarios ---

# 1. Success: New User Registration Flow
def test_accept_invitation_new_user_get_redirects_to_register(
    unauth_client: TestClient,
    test_invitation: Invitation
):
    """GET /accept with valid token for non-existent account redirects to register."""
    response = unauth_client.get(
        app.url_path_for("accept_invitation"),
        params={"token": test_invitation.token},
        follow_redirects=False
    )
    assert response.status_code == 303
    redirect_location = response.headers["location"]
    parsed_url = urlparse(redirect_location)
    query_params = parse_qs(parsed_url.query)

    assert parsed_url.path == app.url_path_for("read_register")
    assert query_params.get("invitation_token") == [test_invitation.token]
    assert query_params.get("email") == [test_invitation.invitee_email]

def test_accept_invitation_new_user_post_registers_and_accepts(
    unauth_client: TestClient,
    session: Session,
    test_invitation: Invitation,
    test_organization: Invitation # Fetch org for redirect check
):
    """POST /register with valid token creates user, accepts invite, redirects to org."""
    register_data = {
        "name": "New Invitee",
        "email": test_invitation.invitee_email, # Must match invitation
        "password": "NewInvitee123!@#",
        "confirm_password": "NewInvitee123!@#",
        "invitation_token": test_invitation.token
    }
    response = unauth_client.post(
        app.url_path_for("register"),
        data=register_data,
        follow_redirects=False
    )

    assert response.status_code == 303
    # Check redirect URL matches the organization page
    expected_redirect_url = app.url_path_for("read_organization", org_id=test_organization.id)
    assert response.headers["location"] == expected_redirect_url

    # Check cookies are set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # Verify database state
    # 1. Account created
    account = session.exec(select(Account).where(Account.email == test_invitation.invitee_email)).first()
    assert account is not None

    # 2. User created and linked
    user: User = session.exec(
        select(User).where(User.account_id == account.id).options(joinedload(User.roles))
    ).unique().one()
    assert user is not None
    assert user.name == "New Invitee"

    # 3. User added to the correct Role
    assert any(role.id == test_invitation.role_id for role in user.roles)

    # 4. Invitation marked as used
    session.refresh(test_invitation)
    assert test_invitation.used is True
    assert test_invitation.accepted_by_user_id == user.id
    assert test_invitation.accepted_at is not None

# 2. Success: Existing User Login Flow
def test_accept_invitation_existing_user_logged_out_get_redirects_to_login(
    unauth_client: TestClient,
    test_invitation: Invitation,
    existing_invitee_account: Account # Ensure account exists
):
    """GET /accept with valid token for existing account redirects to login."""
    response = unauth_client.get(
        app.url_path_for("accept_invitation"),
        params={"token": test_invitation.token},
        follow_redirects=False
    )
    assert response.status_code == 303
    redirect_location = response.headers["location"]
    parsed_url = urlparse(redirect_location)
    query_params = parse_qs(parsed_url.query)

    assert parsed_url.path == app.url_path_for("read_login")
    assert query_params.get("invitation_token") == [test_invitation.token]

def test_accept_invitation_existing_user_post_logs_in_and_accepts(
    unauth_client: TestClient,
    session: Session,
    test_invitation: Invitation,
    existing_invitee_account: Account,
    existing_invitee_user: User, # To verify role assignment
    test_organization: Invitation # Fetch org for redirect check
):
    """POST /login with valid token logs in user, accepts invite, redirects to org."""
    login_data = {
        "email": existing_invitee_account.email,
        "password": "Invitee123!@#", # Password from fixture
        "invitation_token": test_invitation.token
    }
    response = unauth_client.post(
        app.url_path_for("login"),
        data=login_data,
        follow_redirects=False
    )

    assert response.status_code == 303
    # Check redirect URL matches the organization page
    expected_redirect_url = app.url_path_for("read_organization", org_id=test_organization.id)
    assert response.headers["location"] == expected_redirect_url

    # Check cookies are set
    assert "access_token" in response.cookies
    assert "refresh_token" in response.cookies

    # Verify database state
    # 1. User added to the correct Role (load roles eagerly)
    session.refresh(existing_invitee_user, attribute_names=['roles'])
    assert any(role.id == test_invitation.role_id for role in existing_invitee_user.roles)

    # 2. Invitation marked as used
    session.refresh(test_invitation)
    assert test_invitation.used is True
    assert test_invitation.accepted_by_user_id == existing_invitee_user.id
    assert test_invitation.accepted_at is not None

# 3. Success: Logged-in Correct User Flow
def test_accept_invitation_logged_in_correct_user_get_accepts_and_redirects(
    auth_client_invitee: TestClient,
    session: Session,
    test_invitation: Invitation,
    existing_invitee_user: User,
    test_organization: Invitation # Fetch org for redirect check
):
    """GET /accept with valid token when logged in as correct user accepts directly."""
    response = auth_client_invitee.get(
        app.url_path_for("accept_invitation"),
        params={"token": test_invitation.token},
        follow_redirects=False
    )

    assert response.status_code == 303
    # Check redirect URL matches the organization page
    expected_redirect_url = app.url_path_for("read_organization", org_id=test_organization.id)
    assert response.headers["location"] == expected_redirect_url

    # Verify database state
    # 1. User added to the correct Role (load roles eagerly)
    session.refresh(existing_invitee_user, attribute_names=['roles'])
    assert any(role.id == test_invitation.role_id for role in existing_invitee_user.roles)

    # 2. Invitation marked as used
    session.refresh(test_invitation)
    assert test_invitation.used is True
    assert test_invitation.accepted_by_user_id == existing_invitee_user.id
    assert test_invitation.accepted_at is not None

# 4. Failure: Invalid/Expired/Used Token
@pytest.mark.parametrize("token_type", [
    "invalid",
    "expired",
    "used",
])
def test_accept_invitation_get_invalid_token_fails(
    unauth_client: TestClient,
    token_type: str,
    request # Required by getfixturevalue
):
    """GET /accept with invalid, expired, or used token fails with 404."""
    token_value = "invalid-token-string"
    if token_type == "expired":
        expired_invite: Invitation = request.getfixturevalue("expired_invitation")
        token_value = expired_invite.token
    elif token_type == "used":
        used_invite: Invitation = request.getfixturevalue("used_invitation")
        token_value = used_invite.token

    response = unauth_client.get(
        app.url_path_for("accept_invitation"),
        params={"token": token_value},
        follow_redirects=False
    )
    assert response.status_code == 404 # InvalidInvitationTokenError maps to 404

@pytest.mark.parametrize("token_type", [
    "invalid",
    "expired",
    "used",
])
def test_accept_invitation_register_post_invalid_token_fails(
    unauth_client: TestClient,
    token_type: str,
    request # Required by getfixturevalue
):
    """POST /register with invalid token fails with 404."""
    token_value = "invalid-token-string"
    invitee_email = "some_email@example.com"
    if token_type == "expired":
        expired_invite: Invitation = request.getfixturevalue("expired_invitation")
        token_value = expired_invite.token
        invitee_email = expired_invite.invitee_email
    elif token_type == "used":
        used_invite: Invitation = request.getfixturevalue("used_invitation")
        token_value = used_invite.token
        invitee_email = used_invite.invitee_email

    register_data = {
        "name": "Invalid Token User",
        "email": invitee_email,
        "password": "Password123!@#",
        "confirm_password": "Password123!@#",
        "invitation_token": token_value
    }
    response = unauth_client.post(
        app.url_path_for("register"),
        data=register_data,
        follow_redirects=False
    )
    assert response.status_code == 404 # InvalidInvitationTokenError

@pytest.mark.parametrize("token_type", [
    "invalid",
    "expired",
    "used",
])
def test_accept_invitation_login_post_invalid_token_fails(
    unauth_client: TestClient,
    token_type: str,
    existing_invitee_account, # Need an account to attempt login
    request # Required by getfixturevalue
):
    """POST /login with invalid token fails with 404."""
    token_value = "invalid-token-string"
    if token_type == "expired":
        expired_invite: Invitation = request.getfixturevalue("expired_invitation")
        token_value = expired_invite.token
    elif token_type == "used":
        used_invite: Invitation = request.getfixturevalue("used_invitation")
        token_value = used_invite.token

    login_data = {
        "email": existing_invitee_account.email,
        "password": "Invitee123!@#",
        "invitation_token": token_value
    }
    response = unauth_client.post(
        app.url_path_for("login"),
        data=login_data,
        follow_redirects=False
    )
    assert response.status_code == 404 # InvalidInvitationTokenError

# 5. Failure: Email Mismatch (Registration)
def test_accept_invitation_register_email_mismatch_fails(
    unauth_client: TestClient,
    test_invitation: Invitation
):
    """POST /register with valid token but different email fails with 403."""
    register_data = {
        "name": "Mismatch User",
        "email": "wrong.email@example.com", # Different from invitation
        "password": "Password123!@#",
        "confirm_password": "Password123!@#",
        "invitation_token": test_invitation.token
    }
    response = unauth_client.post(
        app.url_path_for("register"),
        data=register_data,
        follow_redirects=False
    )
    assert response.status_code == 403 # InvitationEmailMismatchError

# 6. Failure: Email Mismatch (Login)
def test_accept_invitation_login_email_mismatch_fails(
    unauth_client: TestClient,
    test_invitation: Invitation,
    test_account: Account # Account with email different from invitee
):
    """POST /login with valid token but credentials for different user fails with 403."""
    login_data = {
        "email": test_account.email, # Different email
        "password": "Test123!@#",   # Password for test_account
        "invitation_token": test_invitation.token # Token for invitee@example.com
    }
    response = unauth_client.post(
        app.url_path_for("login"),
        data=login_data,
        follow_redirects=False
    )
    assert response.status_code == 403 # InvitationEmailMismatchError

# 7. Failure: Logged-in Wrong User
def test_accept_invitation_logged_in_wrong_user_get_redirects_to_login(
    auth_client_non_member: TestClient, # Client logged in as user != invitee
    test_invitation: Invitation,
    existing_invitee_account: Account, # Ensure the invitee's account exists
    session: Session
):
    """GET /accept with valid token when logged in as wrong user redirects to login."""
    response = auth_client_non_member.get(
        app.url_path_for("accept_invitation"),
        params={"token": test_invitation.token},
        follow_redirects=False
    )
    assert response.status_code == 303
    redirect_location = response.headers["location"]
    parsed_url = urlparse(redirect_location)
    query_params = parse_qs(parsed_url.query)

    # Should redirect back to login, preserving the token
    assert parsed_url.path == app.url_path_for("read_login")
    assert query_params.get("invitation_token") == [test_invitation.token]

    # Verify database state hasn't changed
    session.refresh(test_invitation)
    assert test_invitation.used is False
    assert test_invitation.accepted_by_user_id is None
