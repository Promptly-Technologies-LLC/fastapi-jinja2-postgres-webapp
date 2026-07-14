"""Jinja-check static context proof + runtime full-page GET smoke."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import pytest

from main import app
from tests.frontend.helpers import assert_full_page_rendered


def _url(name: str, **path_params) -> str:
    return str(app.url_path_for(name, **path_params))


STATIC_PAGES = ("about", "privacy-policy", "terms-of-service")


@dataclass(frozen=True)
class GetPageCase:
    id: str
    client_fixture: str
    path_factory: Callable[[], str | None]
    marker: str | None = None
    jinja_route: str | None = None
    expected_status: int = 200


GET_PAGE_CASES = [
    GetPageCase(
        "home", "unauth_client", lambda: _url("read_home"), jinja_route="read_home"
    ),
    GetPageCase(
        "login", "unauth_client", lambda: _url("read_login"), jinja_route="read_login"
    ),
    GetPageCase(
        "register",
        "unauth_client",
        lambda: _url("read_register"),
        jinja_route="read_register",
    ),
    GetPageCase(
        "forgot_password",
        "unauth_client",
        lambda: _url("read_forgot_password"),
        jinja_route="read_forgot_password",
    ),
    GetPageCase(
        "dashboard_owner",
        "auth_client_owner",
        lambda: _url("read_dashboard"),
        marker="Organization-specific assets will display here:",
        jinja_route="read_dashboard",
    ),
    GetPageCase(
        "dashboard_no_orgs",
        "auth_client",
        lambda: _url("read_dashboard"),
        marker="not a member of any organizations",
    ),
    GetPageCase(
        "profile_owner",
        "auth_client_owner",
        lambda: _url("read_profile"),
        marker="Profile",
        jinja_route="read_profile",
    ),
    GetPageCase(
        "organization_owner",
        "auth_client_owner",
        lambda: None,
        marker="Create Role",
        jinja_route="read_organization",
    ),
    GetPageCase(
        "organization_member",
        "auth_client_member",
        lambda: None,
        marker="Members",
        jinja_route="read_organization",
    ),
    *[
        GetPageCase(
            f"static_{page}",
            "unauth_client",
            lambda page=page: _url("read_static_page", page_name=page),
        )
        for page in STATIC_PAGES
    ],
]


@pytest.mark.usefixtures("env_vars")
class TestJinjaCheckAndGetSmokeIntegration:
    @pytest.fixture(autouse=True)
    def _setup_org_owner(
        self,
        request,
        test_organization,
        org_owner,
    ):
        # No setup body: autouse only so test_organization and org_owner run before
        # org-scoped client fixtures (auth_client_owner, auth_client_member).
        del request, test_organization, org_owner

    def test_static_context_analysis_passes(self, missing_context_variables):
        assert not missing_context_variables, missing_context_variables

    def test_all_jinja_checked_read_routes_are_in_runtime_matrix(self, route_contexts):
        checked_reads = {
            ctx.function_name
            for ctx in route_contexts
            if ctx.function_name
            and ctx.function_name.startswith("read_")
            and ctx.template_name.endswith(".html")
            and not ctx.template_name.startswith("organization/partials/")
            and not ctx.template_name.startswith("users/partials/")
            and ctx.template_name != "base/partials/navbar_avatar_oob.html"
        }
        runtime_reads = {
            case.jinja_route for case in GET_PAGE_CASES if case.jinja_route is not None
        }
        runtime_reads.add("read_reset_password")
        runtime_reads.add("recover_account_confirm")
        runtime_reads.add("read_billing")

        uncovered = checked_reads - runtime_reads
        assert not uncovered, (
            "Add runtime GET smoke for jinja-checked routes: "
            + ", ".join(sorted(uncovered))
        )

    @pytest.mark.parametrize("case", GET_PAGE_CASES, ids=lambda case: case.id)
    def test_get_page_renders(
        self,
        case: GetPageCase,
        request: pytest.FixtureRequest,
        test_organization,
        missing_context_variables,
    ):
        assert not missing_context_variables
        client = request.getfixturevalue(case.client_fixture)
        path = case.path_factory()
        if path is None:
            assert test_organization.id is not None
            path = _url("read_organization", org_id=test_organization.id)
        response = client.get(path)
        assert_full_page_rendered(response, expected_status=case.expected_status)
        if case.marker:
            assert case.marker in response.text

    def test_organization_nested_includes_need_runtime_smoke(
        self,
        auth_client_owner,
        test_organization,
        route_contexts,
        missing_context_variables,
    ):
        """Static analysis checks organization.html keys; runtime proves nested RBAC partials render."""
        org_contexts = [
            ctx
            for ctx in route_contexts
            if ctx.template_name == "organization/organization.html"
        ]
        assert len(org_contexts) == 1
        assert not missing_context_variables

        assert test_organization.id is not None
        response = auth_client_owner.get(
            _url("read_organization", org_id=test_organization.id)
        )
        assert_full_page_rendered(response)
        assert 'id="roles-card-content"' in response.text
        assert 'id="members-card-content"' in response.text
        assert "Create Role" in response.text
        assert "Invite Member" in response.text

    def test_reset_password_page_renders(
        self, unauth_client, password_reset_credentials, missing_context_variables
    ):
        assert not missing_context_variables
        email, token = password_reset_credentials
        response = unauth_client.get(
            _url("read_reset_password"),
            params={"email": email, "token": token},
        )
        assert_full_page_rendered(response)
        assert 'id="password"' in response.text

    def test_recover_page_renders(
        self, unauth_client, account_recovery_token, missing_context_variables
    ):
        assert not missing_context_variables
        response = unauth_client.get(
            _url("recover_account_confirm"),
            params={"token": account_recovery_token},
        )
        assert_full_page_rendered(response)
        assert "recover" in response.text.lower()

    def test_billing_page_renders(
        self,
        auth_client_owner,
        test_organization,
        missing_context_variables,
    ):
        assert not missing_context_variables
        assert test_organization.id is not None
        response = auth_client_owner.get(
            _url("read_billing", org_id=test_organization.id)
        )
        assert_full_page_rendered(response)
        assert "Organization billing" in response.text
        assert "Pro plan" in response.text

    def test_register_with_invitation_token_renders(
        self, unauth_client, test_invitation, missing_context_variables
    ):
        assert not missing_context_variables
        response = unauth_client.get(
            _url("read_register"),
            params={"invitation_token": test_invitation.token},
        )
        assert_full_page_rendered(response)
        assert test_invitation.token in response.text


@pytest.mark.usefixtures("env_vars")
class TestGetPagesRequireAuth:
    @pytest.mark.parametrize(
        ("client_fixture", "path_factory"),
        [
            ("unauth_client", lambda: _url("read_dashboard")),
            ("unauth_client", lambda: _url("read_profile")),
            ("unauth_client", lambda: None),
        ],
        ids=["dashboard", "profile", "organization"],
    )
    def test_unauthenticated_redirects_to_login(
        self,
        client_fixture,
        path_factory,
        request: pytest.FixtureRequest,
        test_organization,
    ):
        client = request.getfixturevalue(client_fixture)
        path = path_factory()
        if path is None:
            assert test_organization.id is not None
            path = _url("read_organization", org_id=test_organization.id)
        response = client.get(path)
        assert response.status_code in {303, 307}
        assert "login" in response.headers.get("location", "")

    def test_authenticated_home_redirects_to_dashboard(self, auth_client_owner):
        response = auth_client_owner.get(_url("read_home"))
        assert response.status_code == 302
        assert "dashboard" in response.headers.get("location", "")
