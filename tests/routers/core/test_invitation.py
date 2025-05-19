import pytest
from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock, patch
from sqlmodel import Session, select
from tests.conftest import SetupError
from utils.core.models import Role, Permission, ValidPermissions, User, Invitation, Organization, Account
from main import app
from utils.core.invitations import generate_invitation_link
from exceptions.exceptions import EmailSendFailedError

@pytest.fixture
def invite_user_permission(session: Session) -> Permission:
    """Get the INVITE_USER permission."""
    permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.INVITE_USER)
    ).first()
    if permission is None:
        # Attempt to create it if missing. Permissions are global.
        permission = Permission(name=ValidPermissions.INVITE_USER)
        session.add(permission)
        session.commit()
        session.refresh(permission)

        # Link permission to existing Owner/Admin roles if they exist in any org
        # This assumes standard roles exist, adjust if setup is different
        orgs = session.exec(select(Organization)).all()
        for org in orgs:
            assert org.id is not None
            owner_role = session.exec(select(Role).where(Role.name == "Owner", Role.organization_id == org.id)).first()
            if owner_role and permission not in owner_role.permissions:
                owner_role.permissions.append(permission)
                session.add(owner_role)

            admin_role = session.exec(select(Role).where(Role.name == "Admin", Role.organization_id == org.id)).first()
            if admin_role and permission not in admin_role.permissions:
                admin_role.permissions.append(permission)
                session.add(admin_role)
        session.commit() # Commit role permission changes

    if permission is None: # Re-check in case creation failed silently (shouldn't happen)
        raise SetupError("INVITE_USER permission could not be found or created.")
    return permission

@pytest.fixture
def inviter_user(session: Session, test_user: User, test_organization: Organization, invite_user_permission: Permission) -> User:
    """Create a user with INVITE_USER permission."""
    assert test_organization.id is not None # Ensure org ID is not None
    # Find or create an "Inviter Role" specific for this test setup
    inviter_role = session.exec(
        select(Role).where(
            Role.name == "Inviter Role",
            Role.organization_id == test_organization.id
        )
    ).first()

    if not inviter_role:
        inviter_role = Role(
            name="Inviter Role",
            organization_id=test_organization.id
        )
        session.add(inviter_role)
        # Add permission link before committing the role
        inviter_role.permissions.append(invite_user_permission)
        session.commit() # Commit role and permission link
        session.refresh(inviter_role) # Refresh to load relationship if needed

    # Check if user already has the role to avoid duplicate entries
    if inviter_role not in test_user.roles:
        test_user.roles.append(inviter_role)
        session.add(test_user) # Add user again to update relationship
        session.commit()
        session.refresh(test_user)

    # Verify the permission is effectively granted through the role
    # Refresh roles and permissions to ensure they are loaded correctly
    session.refresh(test_user)
    for r in test_user.roles:
        session.refresh(r)
        # Ensure permissions are loaded for the check
        if hasattr(r, 'permissions'):
             # Check if permissions relation is loaded, might need eager loading strategy
             # or explicit refresh like session.refresh(r, attribute_names=['permissions'])
             pass # Assume loaded for now
    assert any(p.name == ValidPermissions.INVITE_USER for role in test_user.roles if role.organization_id == test_organization.id for p in role.permissions)
    return test_user


@pytest.fixture
def existing_invitation(session: Session, test_organization: Organization, inviter_user: User) -> Invitation:
    """Create a sample invitation for testing."""
    assert test_organization.id is not None
    # Ensure the Member role exists
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        member_role = Role(name="Member", organization_id=test_organization.id)
        session.add(member_role)
        session.commit()
        session.refresh(member_role)
    assert member_role.id is not None

    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="invited@example.com",
        token="test-token-12345",
        expires_at=datetime.now(UTC) + timedelta(days=7)
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation

@pytest.fixture
def expired_invitation(session: Session, test_organization: Organization, inviter_user: User) -> Invitation:
    """Create an expired invitation for testing."""
    assert test_organization.id is not None
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        pytest.fail("Member role not found for expired_invitation fixture")
    assert member_role.id is not None

    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="expired@example.com",
        token="expired-token-12345",
        expires_at=datetime.now(UTC) - timedelta(days=1)  # Expired yesterday
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation

@pytest.fixture
def used_invitation(session: Session, test_organization: Organization, inviter_user: User, test_user: User) -> Invitation:
    """Create a used invitation for testing."""
    assert test_organization.id is not None
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        pytest.fail("Member role not found for used_invitation fixture")
    assert member_role.id is not None

    # Create a user account for the accepted_by user if it doesn't exist
    accepted_by_account = session.exec(select(Account).where(Account.email == "accepted_by@example.com")).first()
    if not accepted_by_account:
        accepted_by_account = Account(email="accepted_by@example.com", hashed_password="password")
        session.add(accepted_by_account)
        session.commit()
        session.refresh(accepted_by_account)
    assert accepted_by_account.id is not None

    accepted_by_user = session.exec(select(User).where(User.account_id == accepted_by_account.id)).first()
    if not accepted_by_user:
        accepted_by_user = User(name="Accepted User", account_id=accepted_by_account.id)
        session.add(accepted_by_user)
        session.commit()
        session.refresh(accepted_by_user)
    assert accepted_by_user.id is not None


    invitation = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="used@example.com",
        token="used-token-12345",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        used=True,
        accepted_at=datetime.now(UTC),
        accepted_by_user_id=accepted_by_user.id # Use a different user than test_user to avoid conflicts
    )
    session.add(invitation)
    session.commit()
    session.refresh(invitation)
    return invitation

# --- Model Tests ---
def test_invitation_is_expired(session: Session, existing_invitation: Invitation, expired_invitation: Invitation):
    """Test the is_expired method correctly identifies expired invitations."""
    assert not existing_invitation.is_expired()
    assert expired_invitation.is_expired()

def test_invitation_is_active(session: Session, existing_invitation: Invitation, expired_invitation: Invitation, used_invitation: Invitation):
    """Test the is_active method correctly identifies active invitations."""
    assert existing_invitation.is_active()
    assert not expired_invitation.is_active()
    assert not used_invitation.is_active()

def test_get_active_for_org(session: Session, test_organization: Organization, inviter_user: User, existing_invitation: Invitation, expired_invitation: Invitation, used_invitation: Invitation):
    """Test the get_active_for_org class method returns only active invitations."""
    assert test_organization.id is not None
    # Ensure the Member role exists
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        pytest.fail("Member role not found in test_get_active_for_org")
    assert member_role.id is not None

    # Create another active invitation in the same org
    second_active = Invitation(
        organization_id=test_organization.id,
        role_id=member_role.id,
        invitee_email="another@example.com",
        token="another-token-12345",
        expires_at=datetime.now(UTC) + timedelta(days=7)
    )
    session.add(second_active)

    # Create an active invitation in a different org
    other_org = Organization(name="Other Org")
    session.add(other_org)
    session.commit() # Commit to get other_org.id
    assert other_org.id is not None # Ensure other_org ID is not None

    # Ensure the Member role exists in the other org too, or create one
    other_member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == other_org.id)).first()
    if not other_member_role:
        other_member_role = Role(name="Member", organization_id=other_org.id)
        session.add(other_member_role)
        session.commit()
        session.refresh(other_member_role)
    assert other_member_role.id is not None

    # We need an inviter user associated with the other org, or use an existing one if appropriate.
    # For simplicity, let's reuse inviter_user, assuming they could potentially invite to multiple orgs
    # depending on the application logic. A more robust test might create a separate inviter for other_org.
    assert inviter_user.id is not None
    other_org_invitation = Invitation(
        organization_id=other_org.id,
        role_id=other_member_role.id,
        invitee_email="other-org@example.com",
        token="other-org-token-12345",
        expires_at=datetime.now(UTC) + timedelta(days=7)
    )
    session.add(other_org_invitation)
    session.commit()

    # Test the method
    active_invitations = Invitation.get_active_for_org(session, test_organization.id)

    # Should include existing_invitation and second_active, but not expired, used, or other org
    assert len(active_invitations) == 2
    assert existing_invitation in active_invitations
    assert second_active in active_invitations
    assert expired_invitation not in active_invitations
    assert used_invitation not in active_invitations
    assert other_org_invitation not in active_invitations

# --- Utility Tests ---
def test_generate_invitation_link():
    """Test the generate_invitation_link function creates correct URLs."""
    token = "test-token-abc123"
    # Assuming generate_invitation_link doesn't need settings for this test
    # If it does, you might need to mock settings or pass a base URL
    link = generate_invitation_link(token)
    # Check format without hard-coding BASE_URL as it may vary in tests
    assert link.endswith(f"/invitations/accept?token={token}")
    # A basic check that it looks like a URL path fragment
    assert "/invitations/accept" in link
    assert "?token=" in link


# --- Create Invitation Endpoint Tests ---
# Note: Assumes mock_resend_send fixture is available (moved to conftest.py as suggested)
def test_create_invitation_success(auth_client, inviter_user: User, test_organization: Organization, session: Session, mock_resend_send: MagicMock):
    """Test successful invitation creation, including email sending."""
    invitee_email = "new_invite@example.com"
    assert test_organization.id is not None
    # Ensure the Member role exists and get its ID
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        pytest.fail("Member role not found in test_create_invitation_success")
    assert member_role.id is not None
    member_role_id = member_role.id

    response = auth_client.post(
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": invitee_email,
            "role_id": str(member_role_id), # Form data is usually string
            "organization_id": str(test_organization.id) # Form data is usually string
        },
        follow_redirects=False # Important for checking redirect
    )

    assert response.status_code == 303, f"Expected 303 redirect, got {response.status_code}. Response: {response.text}" # See Other redirect
    assert f"/organizations/{test_organization.id}" in response.headers["location"]

    # Verify invitation was created in DB
    created = session.exec(
        select(Invitation).where(
            Invitation.invitee_email == invitee_email,
            Invitation.organization_id == test_organization.id
        )
    ).first()

    assert created is not None
    assert created.role_id == member_role_id
    assert not created.used
    assert created.token is not None

    # Verify email sending task was triggered (via background tasks)
    # This requires the background tasks system to run the task synchronously for testing,
    # or mocking/spying on background_tasks.add_task.
    # Assuming mock_resend_send is called directly by the task runner in tests:
    mock_resend_send.assert_called_once()

    # Check basic call arguments (more specific checks might require inspecting rendered template)
    call_args, call_kwargs = mock_resend_send.call_args
    # Extract send params from either kwargs or the first positional argument
    send_params = call_kwargs or call_args[0]
    assert send_params["to"] == [invitee_email]
    assert test_organization.name in send_params["subject"]  # Check org name is in subject
    # Check token is in email body (assuming HTML content)
    assert created.token in send_params.get("html", "") or created.token in send_params.get("text", "")

def test_create_invitation_unauthorized(auth_client_member, test_user: User, test_organization: Organization, session: Session):
    """Test invitation creation without INVITE_USER permission (using auth_client_member)."""
    assert test_organization.id is not None
    # Ensure the Member role exists and get its ID
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        pytest.fail("Member role not found in test_create_invitation_unauthorized")
    assert member_role.id is not None

    response = auth_client_member.post( # Use client logged in as a regular member
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": "unauthorized@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id)
        },
        follow_redirects=False
    )

    assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}. Response: {response.text}" # Forbidden


def test_create_invitation_for_existing_member(auth_client, inviter_user: User, test_organization: Organization, session: Session):
    """Test that inviting an existing member fails."""
    assert test_organization.id is not None
    # Create a user that's already a member
    existing_email = "existing_member@example.com"
    existing_account = session.exec(select(Account).where(Account.email == existing_email)).first()
    if not existing_account:
        existing_account = Account(email=existing_email, hashed_password="password_hash")
        session.add(existing_account)
        session.commit()
        session.refresh(existing_account)
    assert existing_account.id is not None

    existing_user = session.exec(select(User).where(User.account_id == existing_account.id)).first()
    if not existing_user:
        existing_user = User(name="Existing Member", account_id=existing_account.id)
        session.add(existing_user)
        # Note: Role is added below before commit

    # Find the Member role
    member_role = session.exec(
        select(Role).where(
            Role.organization_id == test_organization.id,
            Role.name == "Member"
        )
    ).first()

    if not member_role:
        pytest.fail("Member role not found in test_create_invitation_for_existing_member")
    assert member_role.id is not None

    # Add user to organization if not already a member
    needs_commit = False
    if existing_user is None: # Should not happen given above logic, but check anyway
         pytest.fail("existing_user is None unexpectedly")
    if existing_user.id is None: # User was created but not committed
        needs_commit = True

    if member_role not in existing_user.roles:
        existing_user.roles.append(member_role)
        session.add(existing_user) # Add again to update roles relationship
        needs_commit = True

    if needs_commit:
        session.commit()
        session.refresh(existing_user)

    # Try to invite the existing member
    response = auth_client.post( # Use the client that has permission
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": existing_email,
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id)
        },
        follow_redirects=False
    )

    # Expecting a 409 Conflict based on the plan
    assert response.status_code == 409, f"Expected 409 Conflict, got {response.status_code}. Response: {response.text}" # Conflict - UserIsAlreadyMemberError

def test_create_invitation_duplicate_active(auth_client, inviter_user: User, existing_invitation: Invitation):
    """Test that creating a duplicate active invitation fails."""
    assert existing_invitation.organization_id is not None
    assert existing_invitation.role_id is not None
    response = auth_client.post(
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": existing_invitation.invitee_email,  # Same email
            "role_id": str(existing_invitation.role_id),
            "organization_id": str(existing_invitation.organization_id)
        },
        follow_redirects=False
    )

    assert response.status_code == 409, f"Expected 409 Conflict, got {response.status_code}. Response: {response.text}" # Conflict - ActiveInvitationExistsError

def test_create_invitation_role_not_found(auth_client, inviter_user: User, test_organization: Organization):
    """Test that specifying a role_id that doesn't exist fails with 404."""
    assert test_organization.id is not None
    non_existent_role_id = 99999
    response = auth_client.post(
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": "testrole_notfound@example.com",
            "role_id": str(non_existent_role_id),
            "organization_id": str(test_organization.id)
        },
        follow_redirects=False
    )

    # Depending on implementation, this might be 404 (Role Not Found) or 400 (Invalid Role for Org)
    # The plan suggests 404, let's stick to that.
    assert response.status_code == 404, f"Expected 404 Not Found, got {response.status_code}. Response: {response.text}"

def test_create_invitation_role_wrong_organization(auth_client, inviter_user: User, test_organization: Organization, session: Session):
    """Test that specifying a role_id belonging to another org fails with 400."""
    assert test_organization.id is not None
    # Create another organization and a role within it
    other_org = Organization(name="Other Test Org For Roles")
    session.add(other_org)
    session.commit() # Commit to get ID
    assert other_org.id is not None
    other_role = Role(name="Other Org Role", organization_id=other_org.id)
    session.add(other_role)
    session.commit() # Commit to get ID
    assert other_role.id is not None

    response = auth_client.post(
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": "testrole_wrongorg@example.com",
            "role_id": str(other_role.id),  # Role from the wrong org
            "organization_id": str(test_organization.id) # Target the main test org
        },
        follow_redirects=False
    )

    # Plan suggests 400 Bad Request
    assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}. Response: {response.text}"

def test_create_invitation_unauthenticated(unauth_client, test_organization: Organization, session: Session):
    """Test invitation attempt without authentication."""
    assert test_organization.id is not None
    # Ensure the Member role exists and get its ID
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
         member_role = Role(name="Member", organization_id=test_organization.id)
         session.add(member_role)
         session.commit()
         session.refresh(member_role)
    assert member_role.id is not None

    response = unauth_client.post(
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": "unauth@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id)
        },
        follow_redirects=False # Check for redirect explicitly
    )

    assert response.status_code == 303, f"Expected 303 redirect to login, got {response.status_code}" # Redirect to login
    # Optionally check that the redirect location is the login page
    # assert "/login" in response.headers.get("location", "")

def test_create_invitation_email_send_failure(auth_client, inviter_user: User, test_organization: Organization, session: Session, mock_resend_send: MagicMock):
    """Test that invitation creation fails and rolls back if email sending fails."""
    invitee_email = "fail_invite@example.com"
    assert test_organization.id is not None
    member_role = session.exec(select(Role).where(Role.name == "Member", Role.organization_id == test_organization.id)).first()
    if not member_role:
        pytest.fail("Member role not found in test_create_invitation_email_send_failure")
    assert member_role.id is not None
    member_role_id = member_role.id

    # Mock resend.Emails.send to raise an exception, simulating failure
    # This will cause send_invitation_email to raise EmailSendFailedError
    mock_resend_send.side_effect = Exception("Simulated email send failure")

    response = auth_client.post(
        app.url_path_for("create_invitation"),
        data={
            "invitee_email": invitee_email,
            "role_id": str(member_role_id),
            "organization_id": str(test_organization.id)
        },
        follow_redirects=False
    )

    assert response.status_code == 500, f"Expected 500 Internal Server Error, got {response.status_code}. Response: {response.text}"
    assert "Failed to send invitation email" in response.text # Check for error detail

    # Verify invitation was NOT created in DB (due to rollback)
    failed_invitation = session.exec(
        select(Invitation).where(
            Invitation.invitee_email == invitee_email,
            Invitation.organization_id == test_organization.id
        )
    ).first()

    assert failed_invitation is None, "Invitation should not have been created due to email failure and rollback."

# --- Organization Page Tests ---
def test_organization_page_shows_active_invitations(auth_client_owner, test_organization: Organization, session: Session, existing_invitation: Invitation, expired_invitation: Invitation, used_invitation: Invitation):
    """Test that the organization page shows active invitations."""
    assert test_organization.id is not None
    response = auth_client_owner.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 200
    response_text = response.text

    # Active invitation email should be in response (Depends on Invitation model)
    assert existing_invitation.invitee_email in response_text # Ignored Error: Invitation model not defined yet

    # Expired and used invitation emails should not be in response (Depends on Invitation model)
    assert expired_invitation.invitee_email not in response_text # Ignored Error: Invitation model not defined yet
    assert used_invitation.invitee_email not in response_text # Ignored Error: Invitation model not defined yet

def test_organization_page_invite_form_visibility(auth_client_owner, auth_client_admin, auth_client_member, test_organization: Organization):
    """Test that the invitation form is only shown to users with INVITE_USER permission."""
    assert test_organization.id is not None
    # Owner should see invitation form (has INVITE_USER permission via Owner role -> permission fixture)
    owner_response = auth_client_owner.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )
    assert owner_response.status_code == 200
    assert '<form' in owner_response.text
    # Check specifically for the invitation form action
    print(owner_response.text)
    assert f'action="http://testserver{app.url_path_for("create_invitation")}"' in owner_response.text.replace('&amp;', '&')

    # Admin should also see invitation form (has INVITE_USER permission via Admin role -> permission fixture)
    admin_response = auth_client_admin.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )
    assert admin_response.status_code == 200
    assert '<form' in admin_response.text
    assert f'action="http://testserver{app.url_path_for("create_invitation")}"' in admin_response.text.replace('&amp;', '&')

    # Regular member should not see invitation form (lacks INVITE_USER permission)
    member_response = auth_client_member.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )
    assert member_response.status_code == 200

    # Regular members should still see the list of pending invitations if there are any,
    # but not the form to create new ones
    # Check that the invitation form action is NOT present
    assert f'action="http://testserver{app.url_path_for("create_invitation")}"' not in member_response.text.replace('&amp;', '&')
    # Optionally, if there's a specific section title, check it exists or doesn't
    # Example check if invitations are shown (if any exist)
    if 'Pending Invitations' in member_response.text:
        assert 'action="/invitations"' not in member_response.text
