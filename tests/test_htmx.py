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
from fastapi.templating import Jinja2Templates
from tests.conftest import htmx_headers
from utils.htmx import is_htmx_request, toast_response, append_toast
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

def _assert_htmx_error_is_oob_only(response):
    """Assert an HTMX error response contains only OOB-swapped content.

    If the response contained non-OOB HTML, HTMX would replace the main
    swap target with that content, clobbering whatever widget triggered
    the request (e.g. a roles table).
    """
    from html.parser import HTMLParser

    class TopLevelChecker(HTMLParser):
        def __init__(self):
            super().__init__()
            self.depth = 0
            self.top_level_tags = []
            self.top_level_has_oob = []

        def handle_starttag(self, tag, attrs):
            if self.depth == 0:
                attrs_dict = dict(attrs)
                self.top_level_tags.append(tag)
                self.top_level_has_oob.append("hx-swap-oob" in attrs_dict)
            self.depth += 1

        def handle_endtag(self, tag):
            self.depth -= 1

    checker = TopLevelChecker()
    checker.feed(response.text.strip())
    assert checker.top_level_tags, "HTMX error response body is empty"
    for i, (tag, has_oob) in enumerate(
        zip(checker.top_level_tags, checker.top_level_has_oob)
    ):
        assert has_oob, (
            f"Top-level element #{i} (<{tag}>) lacks hx-swap-oob — "
            "it would replace the HTMX swap target on error responses"
        )


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
    _assert_htmx_error_is_oob_only(response)


def test_credentials_error_htmx_is_oob_only(unauth_client):
    """CredentialsError HTMX response must be OOB-only to avoid clobbering targets."""
    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
        headers=htmx_headers(),
    )
    assert response.status_code == 401
    _assert_htmx_error_is_oob_only(response)


def test_http_exception_htmx_is_oob_only(auth_client, test_organization):
    """HTTPException HTMX response (e.g. duplicate org name) must be OOB-only."""
    response = auth_client.post(
        "/organizations/create",
        data={"name": test_organization.name},
        headers=htmx_headers(),
    )
    assert response.status_code in (400, 422)
    _assert_htmx_error_is_oob_only(response)


def test_validation_error_returns_full_page_for_non_htmx(unauth_client):
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
    )
    assert response.status_code == 422
    assert "<!DOCTYPE html>" in response.text


# ---------------------------------------------------------------------------
# 1.5 — Non-HTMX error pages: human-readable, consistent navigation
# ---------------------------------------------------------------------------

def test_password_validation_error_non_htmx_shows_readable_message(unauth_client):
    """PasswordValidationError must render human-readable text, not raw dicts."""
    from html import unescape
    response = unauth_client.post(
        "/account/register",
        data={
            "name": "T",
            "email": "t@t.com",
            "password": "Abcdef1!",
            "confirm_password": "wrong",
        },
    )
    assert response.status_code == 422
    # Unescape so HTML entities don't hide raw dict syntax
    text = unescape(response.text)
    # Must contain the actual message, not the raw dict
    assert "password" in text.lower()
    assert "{'field'" not in text, "Raw dict rendered in error page"
    assert "{'message'" not in text, "Raw dict rendered in error page"


def test_non_htmx_error_pages_have_go_back_and_home_links(unauth_client):
    """All non-HTMX error pages should have both Go Back and Return to Home."""
    # Validation error (422)
    response = unauth_client.post(
        "/account/login",
        data={"email": "", "password": ""},
    )
    assert response.status_code == 422
    assert "Go Back" in response.text
    assert "Return to Home" in response.text

    # Credentials error (401)
    response = unauth_client.post(
        "/account/login",
        data={"email": "nobody@example.com", "password": "wrongpass"},
    )
    assert response.status_code == 401
    assert "Go Back" in response.text
    assert "Return to Home" in response.text


# ---------------------------------------------------------------------------
# 1.6 — Auth forms include hx-post for HTMX submission
# ---------------------------------------------------------------------------

def test_login_form_has_hx_post(unauth_client):
    """Login form must include hx-post so submissions go through HTMX."""
    response = unauth_client.get("/account/login")
    assert response.status_code == 200
    assert 'hx-post' in response.text


def test_register_form_has_hx_post(unauth_client):
    """Register form must include hx-post so submissions go through HTMX."""
    response = unauth_client.get("/account/register")
    assert response.status_code == 200
    assert 'hx-post' in response.text


def test_forgot_password_form_has_hx_post(unauth_client):
    """Forgot password form must include hx-post so submissions go through HTMX."""
    response = unauth_client.get("/account/forgot_password")
    assert response.status_code == 200
    assert 'hx-post' in response.text


def test_reset_password_form_has_hx_post(unauth_client, session, test_account):
    """Reset password form must include hx-post so submissions go through HTMX."""
    from utils.core.models import PasswordResetToken
    token = PasswordResetToken(account_id=test_account.id)
    session.add(token)
    session.commit()
    response = unauth_client.get(
        "/account/reset_password",
        params={"email": test_account.email, "token": token.token},
    )
    assert response.status_code == 200
    assert 'hx-post' in response.text


# ---------------------------------------------------------------------------
# 1.7 — Auth form HTMX success returns HX-Redirect (not 303)
# ---------------------------------------------------------------------------

def test_login_htmx_success_returns_hx_redirect(unauth_client, test_account):
    """HTMX login success must return HX-Redirect header, not a 303."""
    response = unauth_client.post(
        "/account/login",
        data={"email": test_account.email, "password": "Test123!@#"},
        headers=htmx_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "HX-Redirect" in response.headers


def test_register_htmx_success_returns_hx_redirect(unauth_client):
    """HTMX register success must return HX-Redirect header, not a 303."""
    response = unauth_client.post(
        "/account/register",
        data={
            "name": "HTMX User",
            "email": "htmxuser@example.com",
            "password": "Test123!@#",
            "confirm_password": "Test123!@#",
        },
        headers=htmx_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "HX-Redirect" in response.headers


def test_forgot_password_htmx_success_returns_hx_redirect(
    unauth_client, test_account, mock_resend_send
):
    """HTMX forgot-password success must return HX-Redirect, not a 303."""
    response = unauth_client.post(
        "/account/forgot_password",
        data={"email": test_account.email},
        headers=htmx_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "HX-Redirect" in response.headers


def test_reset_password_htmx_success_returns_hx_redirect(
    unauth_client, session, test_account
):
    """HTMX reset-password success must return HX-Redirect, not a 303."""
    from utils.core.models import PasswordResetToken
    token = PasswordResetToken(account_id=test_account.id)
    session.add(token)
    session.commit()
    response = unauth_client.post(
        "/account/reset_password",
        data={
            "email": test_account.email,
            "token": token.token,
            "password": "NewPass123!@#",
            "confirm_password": "NewPass123!@#",
        },
        headers=htmx_headers(),
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "HX-Redirect" in response.headers


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
    _assert_htmx_error_is_oob_only(response)


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
    _assert_htmx_error_is_oob_only(response)


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
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/organizations/{test_organization.id}"


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
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/user/profile"


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
    _assert_htmx_error_is_oob_only(response)


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
    _assert_htmx_error_is_oob_only(response)


def test_forgot_password_rate_limit_htmx_returns_toast(unauth_client):
    """Rate-limited HTMX forgot-password returns a 429 toast partial."""
    for _ in range(forgot_password_ip_limiter.max_attempts):
        unauth_client.post(
            "/account/forgot_password",
            data={"email": "user@example.com"},
            headers=htmx_headers(),
        )

    response = unauth_client.post(
        "/account/forgot_password",
        data={"email": "user@example.com"},
        headers=htmx_headers(),
    )
    assert response.status_code == 429
    assert "toast" in response.text
    assert "<!DOCTYPE html>" not in response.text
    _assert_htmx_error_is_oob_only(response)


# ---------------------------------------------------------------------------
# 6.1 — toast_response helper
# ---------------------------------------------------------------------------

def test_toast_response_helper():
    """toast_response returns a TemplateResponse with toast HTML."""
    templates = Jinja2Templates(directory="templates")
    scope = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/",
        "query_string": b"",
    }
    request = Request(scope)
    resp = toast_response(request, templates, "Hello", level="success", status_code=200)
    body = resp.body.decode()
    assert "toast" in body
    assert "Hello" in body
    assert resp.status_code == 200


def test_toast_response_with_headers():
    """toast_response forwards extra headers."""
    templates = Jinja2Templates(directory="templates")
    scope = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/",
        "query_string": b"",
    }
    request = Request(scope)
    resp = toast_response(
        request, templates, "Rate limited", level="danger",
        status_code=429, headers={"Retry-After": "60"},
    )
    assert resp.headers["Retry-After"] == "60"


def test_append_toast_helper():
    """append_toast appends toast HTML to an existing TemplateResponse."""
    templates = Jinja2Templates(directory="templates")
    scope = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/",
        "query_string": b"",
    }
    request = Request(scope)
    original = templates.TemplateResponse(
        request,
        "base/partials/toast.html",
        {"message": "original", "level": "info"},
    )
    result = append_toast(original, request, templates, "appended", level="success")
    body = result.body.decode()
    assert "original" in body
    assert "appended" in body


# ---------------------------------------------------------------------------
# 6.2 — Success toasts in HTMX mutation responses
# ---------------------------------------------------------------------------

def test_update_profile_htmx_includes_success_toast(auth_client):
    response = auth_client.post(
        "/user/update",
        data={"name": "Toast Name"},
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "Profile updated successfully" in response.text
    assert "toast" in response.text


def test_update_profile_htmx_triggers_profile_updated_event(auth_client):
    """The response must include an HX-Trigger header so the client can
    toggle display of the basic-info / edit-profile cards.  Using
    hx-on::after-request on the form is unreliable because the OOB swap
    for #profile-form replaces the form element before afterRequest fires
    (HTMX 2.0 fires afterRequest AFTER the swap)."""
    response = auth_client.post(
        "/user/update",
        data={"name": "Trigger Name"},
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    trigger = response.headers.get("HX-Trigger")
    assert trigger is not None, "Missing HX-Trigger response header"
    assert "profileUpdated" in trigger


def test_create_role_htmx_includes_success_toast(auth_client_owner, test_organization):
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "ToastRole",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "Role created successfully" in response.text


def test_delete_role_htmx_includes_success_toast(auth_client_owner, test_organization, session):
    from utils.core.models import Role
    custom_role = Role(name="ToDeleteToast", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    response = auth_client_owner.post(
        "/roles/delete",
        data={
            "id": str(custom_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "Role deleted successfully" in response.text


def test_update_role_htmx_includes_success_toast(auth_client_owner, test_organization, session):
    from utils.core.models import Role
    custom_role = Role(name="RenameMe", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    response = auth_client_owner.post(
        "/roles/update",
        data={
            "id": str(custom_role.id),
            "name": "Renamed",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "Role updated successfully" in response.text


def test_update_role_htmx_triggers_modal_cleanup(auth_client_owner, test_organization, session):
    """The response must include an HX-Trigger header so the client can
    dismiss the Bootstrap modal and its backdrop.  The OOB swap for
    #role-modals-container replaces the modal element before afterRequest
    fires, leaving the backdrop stuck on screen."""
    from utils.core.models import Role
    custom_role = Role(name="TriggerRole", organization_id=test_organization.id)
    session.add(custom_role)
    session.commit()
    session.refresh(custom_role)

    response = auth_client_owner.post(
        "/roles/update",
        data={
            "id": str(custom_role.id),
            "name": "TriggerRenamed",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    trigger = response.headers.get("HX-Trigger")
    assert trigger is not None, "Missing HX-Trigger response header"
    assert "modalDismiss" in trigger


def test_create_role_htmx_triggers_modal_cleanup(auth_client_owner, test_organization):
    """create_role must send HX-Trigger: modalDismiss to close the
    create-role Bootstrap modal after the swap."""
    response = auth_client_owner.post(
        "/roles/create",
        data={
            "name": "ModalCleanupRole",
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    trigger = response.headers.get("HX-Trigger")
    assert trigger is not None, "Missing HX-Trigger response header"
    assert "modalDismiss" in trigger


def test_create_invitation_htmx_triggers_modal_cleanup(
    auth_client_owner, test_organization, member_role, mock_resend_send
):
    """create_invitation must send HX-Trigger: modalDismiss to close
    the invite-member Bootstrap modal after the swap."""
    response = auth_client_owner.post(
        "/invitations/",
        data={
            "invitee_email": "modaldismiss@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    trigger = response.headers.get("HX-Trigger")
    assert trigger is not None, "Missing HX-Trigger response header"
    assert "modalDismiss" in trigger


def test_update_user_role_htmx_triggers_modal_cleanup(
    auth_client_owner, org_member_user, test_organization, member_role
):
    """update_user_role must send HX-Trigger: modalDismiss to close
    the edit-user-role Bootstrap modal after the swap."""
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
    trigger = response.headers.get("HX-Trigger")
    assert trigger is not None, "Missing HX-Trigger response header"
    assert "modalDismiss" in trigger


def test_create_invitation_htmx_includes_success_toast(
    auth_client_owner, test_organization, member_role, mock_resend_send
):
    response = auth_client_owner.post(
        "/invitations/",
        data={
            "invitee_email": "toastinvite@example.com",
            "role_id": str(member_role.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "Invitation sent successfully" in response.text


def test_update_user_role_htmx_includes_success_toast(
    auth_client_owner, org_member_user, test_organization, member_role
):
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
    assert "User role updated successfully" in response.text


def test_remove_user_htmx_includes_success_toast(
    auth_client_owner, org_member_user, test_organization
):
    response = auth_client_owner.post(
        "/user/organization/remove",
        data={
            "user_id": str(org_member_user.id),
            "organization_id": str(test_organization.id),
        },
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "User removed from organization" in response.text


# ---------------------------------------------------------------------------
# 7 — Architectural guard: ban hx-on::after-request in templates
# ---------------------------------------------------------------------------

def test_no_templates_use_hx_on_after_request():
    """In HTMX 2.0 afterRequest fires AFTER the swap, so any handler
    on an element that is replaced by an OOB swap will silently fail.
    Use HX-Trigger response headers instead."""
    import pathlib
    import re

    # Match the attribute in HTML tags, not in JS comments or prose.
    attr_pattern = re.compile(r'hx-on::after-request=|hx-on:htmx:after-request=')

    templates_dir = pathlib.Path(__file__).resolve().parent.parent / "templates"
    violations = []
    for path in templates_dir.rglob("*.html"):
        text = path.read_text()
        if attr_pattern.search(text):
            violations.append(str(path.relative_to(templates_dir)))

    assert violations == [], (
        f"Templates must not use hx-on::after-request (unreliable in HTMX 2.0). "
        f"Use HX-Trigger response headers instead. Violations: {violations}"
    )
