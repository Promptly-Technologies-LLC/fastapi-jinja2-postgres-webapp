"""Cross-cutting frontend edge cases (cookies, auth guards, errors)."""

from __future__ import annotations

import pytest

from main import app
from tests.frontend.helpers import assert_full_page_rendered


def _url(name: str, **path_params) -> str:
    return str(app.url_path_for(name, **path_params))


@pytest.mark.usefixtures("env_vars")
def test_dashboard_respects_selected_organization_cookie(
    auth_client_owner,
    test_organization,
    second_test_organization,
    session,
    org_owner,
):
    from tests.conftest import add_owner_to_organization
    from utils.app.models import OrganizationResource

    add_owner_to_organization(session, org_owner, second_test_organization)
    assert test_organization.id is not None
    assert second_test_organization.id is not None

    session.add(
        OrganizationResource(
            organization_id=test_organization.id,
            title="First Org Resource",
            description="Resource for first org",
        )
    )
    session.add(
        OrganizationResource(
            organization_id=second_test_organization.id,
            title="Second Org Resource",
            description="Resource for second org",
        )
    )
    session.commit()

    auth_client_owner.cookies.set(
        "selected_organization_id", str(second_test_organization.id)
    )
    response = auth_client_owner.get(_url("read_dashboard"))
    assert_full_page_rendered(response)
    assert "Second Org Resource" in response.text
    assert "First Org Resource" not in response.text


@pytest.mark.usefixtures("env_vars")
def test_unknown_route_renders_branded_404(unauth_client):
    response = unauth_client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    assert "404" in response.text
    assert "Return to Home" in response.text
