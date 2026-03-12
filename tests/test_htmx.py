"""
Tests for HTMX-specific endpoint behavior.

Convention: HTMX requests send the HX-Request: true header.
- Success responses return 200 HTML partials (no <!DOCTYPE html>).
- Error responses return 422/400/401 toast partials.
- Navigation responses return 200 with HX-Redirect header.
- Non-HTMX paths remain unchanged (303 RedirectResponse or full-page error).
"""
import pytest
from starlette.requests import Request
from tests.conftest import htmx_headers
from utils.htmx import is_htmx_request
from utils.core.rate_limit import (
    login_ip_limiter,
    login_email_limiter,
    register_ip_limiter,
    forgot_password_ip_limiter,
    forgot_password_email_limiter,
)


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Reset all rate limiter state between tests."""
    yield
    for limiter in (
        login_ip_limiter,
        login_email_limiter,
        register_ip_limiter,
        forgot_password_ip_limiter,
        forgot_password_email_limiter,
    ):
        limiter._attempts.clear()


# ---------------------------------------------------------------------------
# 1.3 — is_htmx_request helper
# ---------------------------------------------------------------------------

def test_is_htmx_request_true():
    scope = {
        "type": "http",
        "headers": [(b"hx-request", b"true")],
        "method": "GET",
        "path": "/",
        "query_string": b"",
    }
    request = Request(scope)
    assert is_htmx_request(request) is True


def test_is_htmx_request_false():
    scope = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/",
        "query_string": b"",
    }
    request = Request(scope)
    assert is_htmx_request(request) is False


# ---------------------------------------------------------------------------
# 1.4 — Exception handler branches
# ---------------------------------------------------------------------------

def test_validation_error_returns_toast_for_htmx(unauth_client):
    """RequestValidationError from an HTMX request returns a 422 toast partial."""
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
        headers=htmx_headers(),
    )
    assert response.status_code == 422
    assert "<!DOCTYPE html>" not in response.text
    assert "toast" in response.text


def test_validation_error_returns_full_page_for_non_htmx(unauth_client):
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
    )
    assert response.status_code == 422
    assert "<!DOCTYPE html>" in response.text


# ---------------------------------------------------------------------------
# 4.2 — Password mismatch on register/reset
# ---------------------------------------------------------------------------

def test_password_mismatch_htmx_returns_toast(unauth_client):
    response = unauth_client.post(
        "/account/register",
        data={
            "name": "T",
            "email": "t@t.com",
            "password": "Abcdef1!",
            "confirm_password": "wrong",
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 422
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text


# ---------------------------------------------------------------------------
# 4.3 — Login failure toast
# ---------------------------------------------------------------------------

def test_bad_login_htmx_returns_toast(unauth_client):
    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
        headers=htmx_headers(),
    )
    assert response.status_code == 401
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text


# ---------------------------------------------------------------------------
# 2.3 — Role CRUD endpoints
# ---------------------------------------------------------------------------

def test_create_role_htmx_returns_partial(auth_client_owner, test_organization):
    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "Viewer",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "Viewer" in response.text
    assert 'data-bs-target="#editRoleModal' in response.text


def test_create_role_non_htmx_redirects(auth_client_owner, test_organization):
    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "Viewer2",
            "organization_id": str(test_organization.id),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_delete_role_htmx_returns_partial(auth_client_owner, test_organization, session):
    """After deleting a custom role with HTMX, returns updated roles table partial."""
    from utils.core.models import Role
    # Create a custom role to delete
    custom_role = Role(name="ToDelete", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/delete",
        data={
            "id": str(custom_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "ToDelete" not in response.text


def test_create_role_htmx_returns_modal_markup_for_new_role(auth_client_owner, test_organization):
    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "Auditor",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )

    assert response.status_code == 200
    assert 'id="editRoleModal' in response.text
    assert "Edit Role: Auditor" in response.text


# ---------------------------------------------------------------------------
# 2.4 — Invitation endpoint
# ---------------------------------------------------------------------------

def test_create_invitation_htmx_returns_invitations_partial(
    auth_client_owner, test_organization, member_role, mock_resend_send
):
    assert test_organization.id is not None
    assert member_role.id is not None
    response = auth_client_owner.post(
        "/invitations/",
        data={
            "invitee_email": "newperson@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    assert "newperson@example.com" in response.text


# ---------------------------------------------------------------------------
# 3.2 — Update profile endpoint
# ---------------------------------------------------------------------------

def test_update_profile_htmx_returns_profile_display(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Updated Name"},
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "Updated Name" in response.text
    assert "<!DOCTYPE html>" not in response.text


def test_update_profile_htmx_returns_display_and_form_in_sync(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Synced Name"},
        headers=htmx_headers(),
    )

    assert response.status_code == 200
    assert "Synced Name" in response.text
    assert 'value="Synced Name"' in response.text


def test_update_profile_non_htmx_redirects(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Updated Name"},
        follow_redirects=False,
    )
    assert response.status_code == 303


# ---------------------------------------------------------------------------
# 4.1 — Business logic errors via HTTPException handler
# ---------------------------------------------------------------------------

def test_duplicate_org_name_htmx_returns_toast(auth_client, test_organization):
    assert test_organization.id is not None
    response = auth_client.post(
        "/organizations/create",
        data={"name": test_organization.name},
        headers=htmx_headers(),
    )
    assert response.status_code in (400, 422)
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text


def test_update_user_role_htmx_returns_member_modal_markup(
    auth_client_owner, org_member_user, test_organization, member_role
):
    assert org_member_user.id is not None
    assert test_organization.id is not None
    assert member_role.id is not None

    response = auth_client_owner.post(
        "/user/role/update",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
            "roles": [str(member_role.id)],
        },
        headers=htmx_headers(),
    )

    assert response.status_code == 200
    assert f'id="editUserRoleModal{org_member_user.id}"' in response.text


def test_remove_last_non_owner_member_htmx_preserves_empty_state(
    auth_client_owner, org_member_user, test_organization
):
    assert org_member_user.id is not None
    assert test_organization.id is not None

    response = auth_client_owner.post(
        "/user/organization/remove",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )

    assert response.status_code == 200
    assert "No members found" in response.text


# ---------------------------------------------------------------------------
# 2.3 — update_role HTMX refreshes both table and modal container
# ---------------------------------------------------------------------------

def test_update_role_htmx_refreshes_modal_container(auth_client_owner, test_organization, session):
    """
    update_role HTMX response includes the updated role name in the table
    and refreshes the role-modals-container OOB so the edit modal title
    reflects the renamed role.
    """
    from utils.core.models import Role

    # Create a custom role to rename
    custom_role = Role(name="OldName", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    assert test_organization.id is not None
    response = auth_client_owner.post(
        "/roles/update",
        data={
            "id": str(custom_role.id),
            "name": "NewName",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )

    assert response.status_code == 200
    assert "<!DOCTYPE html>" not in response.text
    # Updated name appears in the table rows
    assert "NewName" in response.text
    # Old name is gone from the table
    assert "OldName" not in response.text
    # OOB-refreshed modal container includes updated edit modal title
    assert "Edit Role: NewName" in response.text
    assert 'id="role-modals-container"' in response.text


# ---------------------------------------------------------------------------
# 5.1 — Rate limit 429 toast responses
# ---------------------------------------------------------------------------

def test_login_rate_limit_htmx_returns_toast(unauth_client):
    """Rate-limited HTMX login returns a 429 toast partial with Retry-After."""
    for _ in range(login_ip_limiter.max_attempts):
        unauth_client.post(
            "/account/login",
            data={"email": "nobody@example.com", "password": "wrongpass"},
            headers=htmx_headers(),
        )

    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
        headers=htmx_headers(),
    )
    assert response.status_code == 429
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    assert "Retry-After" in response.headers


def test_forgot_password_rate_limit_htmx_returns_toast(unauth_client):
    """Rate-limited HTMX forgot-password returns a 429 toast partial."""
    for _ in range(forgot_password_ip_limiter.max_attempts):
        unauth_client.post(
            "/account/forgot_password",
            data={"email": "user@example.com"},
            headers=htmx_headers(),
            follow_redirects=False,
        )

    response = unauth_client.post(
        "/account/forgot_password",
        data={"email": "user@example.com"},
        headers=htmx_headers(),
    )
    assert response.status_code == 429
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
