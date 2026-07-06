"""Static redirect lint and runtime POST redirect chain smoke tests (Phase 4)."""

import pytest

from main import app
from tests.frontend.helpers import assert_redirect_renders_full_page
from tests.frontend.redirect_analysis import (
    extract_redirect_sites,
    validate_redirect_sites,
)
from pathlib import Path


def _url(name: str, **path_params) -> str:
    return str(app.url_path_for(name, **path_params))


@pytest.mark.usefixtures("env_vars")
def test_redirect_static_analysis():
    """Every RedirectResponse target must reference a valid endpoint or route."""
    sites = extract_redirect_sites(Path("."))
    assert sites, "Expected at least one RedirectResponse in application source"
    errors = validate_redirect_sites(app, sites)
    assert not errors, "\n".join(errors)


@pytest.mark.usefixtures("env_vars")
class TestPostRedirectChainsRender:
    def test_register_redirect_renders(self, unauth_client):
        response = unauth_client.post(
            _url("register"),
            data={
                "name": "Redirect Test User",
                "email": "redirect-register@example.com",
                "password": "NewPass123!@#",
                "confirm_password": "NewPass123!@#",
            },
        )
        assert_redirect_renders_full_page(unauth_client, response)

    def test_login_redirect_renders(self, unauth_client, test_account):
        response = unauth_client.post(
            _url("login"),
            data={
                "email": test_account.email,
                "password": "Test123!@#",
            },
        )
        assert_redirect_renders_full_page(unauth_client, response)

    def test_logout_redirect_renders(self, auth_client_owner):
        response = auth_client_owner.get(_url("logout"))
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_forgot_password_redirect_renders(self, unauth_client, test_account):
        response = unauth_client.post(
            _url("forgot_password"),
            data={"email": test_account.email},
            headers={"referer": _url("read_forgot_password")},
        )
        assert_redirect_renders_full_page(unauth_client, response)

    def test_reset_password_redirect_renders(
        self, unauth_client, password_reset_credentials
    ):
        email, token = password_reset_credentials
        response = unauth_client.post(
            _url("reset_password"),
            data={
                "email": email,
                "token": token,
                "password": "NewPass123!@#",
                "confirm_password": "NewPass123!@#",
            },
        )
        assert_redirect_renders_full_page(unauth_client, response)

    def test_recover_account_redirect_renders(
        self, unauth_client, account_recovery_token
    ):
        response = unauth_client.post(
            _url("recover_account"),
            data={"token": account_recovery_token},
        )
        assert_redirect_renders_full_page(unauth_client, response)

    def test_refresh_token_redirect_renders(self, auth_client_owner):
        response = auth_client_owner.post(_url("refresh_token"))
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_create_organization_redirect_renders(self, auth_client):
        response = auth_client.post(
            _url("create_organization"),
            data={"name": "Redirect Org"},
        )
        assert_redirect_renders_full_page(auth_client, response)

    def test_update_organization_redirect_renders(
        self, auth_client_owner, test_organization
    ):
        assert test_organization.id is not None
        response = auth_client_owner.post(
            _url("update_organization", org_id=test_organization.id),
            data={"name": "Updated Redirect Org"},
        )
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_delete_organization_redirect_renders(
        self, auth_client_owner, test_organization
    ):
        assert test_organization.id is not None
        response = auth_client_owner.post(
            _url("delete_organization", org_id=test_organization.id),
        )
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_invite_member_redirect_renders(
        self,
        auth_client_owner,
        test_organization,
        non_member_user,
    ):
        assert test_organization.id is not None
        assert non_member_user.account is not None
        response = auth_client_owner.post(
            _url("invite_member", org_id=test_organization.id),
            data={"email": non_member_user.account.email},
        )
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_create_role_non_htmx_redirect_renders(
        self, auth_client_owner, test_organization
    ):
        assert test_organization.id is not None
        response = auth_client_owner.post(
            _url("create_role"),
            data={
                "name": "Redirect Role",
                "organization_id": str(test_organization.id),
            },
        )
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_delete_invitation_redirect_renders(
        self,
        auth_client_owner,
        test_organization,
        test_invitation,
    ):
        assert test_organization.id is not None
        assert test_invitation.id is not None
        response = auth_client_owner.post(
            _url("delete_invitation"),
            data={
                "invitation_id": str(test_invitation.id),
                "organization_id": str(test_organization.id),
            },
        )
        assert_redirect_renders_full_page(auth_client_owner, response)

    def test_resend_invitation_redirect_renders(
        self,
        auth_client_owner,
        test_organization,
        test_invitation,
        mock_resend_send,
    ):
        assert test_organization.id is not None
        assert test_invitation.id is not None
        response = auth_client_owner.post(
            _url("resend_invitation"),
            data={
                "invitation_id": str(test_invitation.id),
                "organization_id": str(test_organization.id),
            },
        )
        assert_redirect_renders_full_page(auth_client_owner, response)
