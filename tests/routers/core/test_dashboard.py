from main import app
from sqlmodel import Session
from utils.core.models import Organization, User
from utils.app.models import OrganizationResource
from tests.conftest import htmx_headers


def test_dashboard_authenticated(auth_client_owner):
    """Test that authenticated users can access the dashboard."""
    response = auth_client_owner.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Organization-specific assets will display here:" in response.text


def test_dashboard_unauthenticated(unauth_client):
    """Test that unauthenticated users are redirected to login."""
    response = unauth_client.get(app.url_path_for("read_dashboard"))
    assert response.status_code == 303
    assert "login" in response.headers["location"]


def test_dashboard_shows_org_dropdown(auth_client_owner, test_organization):
    """Test that dashboard shows organization dropdown for users with orgs."""
    response = auth_client_owner.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert test_organization.name in response.text
    assert "orgSelect" in response.text


def test_dashboard_no_orgs(auth_client):
    """Test dashboard when user has no organizations."""
    response = auth_client.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "not a member of any organizations" in response.text
    # No dropdown should be shown
    assert "orgSelect" not in response.text


def test_select_organization_sets_cookie(auth_client_owner, test_organization):
    """Test that selecting an organization sets the cookie."""
    response = auth_client_owner.post(
        app.url_path_for("select_organization", org_id=test_organization.id),
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "HX-Redirect" in response.headers
    # Check the cookie was set
    assert "selected_organization_id" in response.headers.get("set-cookie", "")


def test_select_organization_non_member(auth_client, test_organization):
    """Test that non-members cannot select an organization they don't belong to."""
    response = auth_client.post(
        app.url_path_for("select_organization", org_id=test_organization.id),
        headers=htmx_headers(),
    )
    assert response.status_code == 200
    assert "HX-Redirect" in response.headers
    # Should NOT set a cookie since user is not a member
    assert "selected_organization_id" not in response.headers.get("set-cookie", "")


def test_dashboard_respects_org_cookie(
    auth_client_owner,
    session: Session,
    test_organization: Organization,
    org_owner: User,
):
    """Test that dashboard loads resources for the cookie-selected organization."""
    # Create a resource for the test organization
    assert test_organization.id is not None
    resource = OrganizationResource(
        organization_id=test_organization.id,
        title="Test Resource",
        description="A test resource for the organization",
    )
    session.add(resource)
    session.commit()

    # Set the cookie and load dashboard
    auth_client_owner.cookies.set(
        "selected_organization_id", str(test_organization.id)
    )
    response = auth_client_owner.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Test Resource" in response.text
    assert "A test resource for the organization" in response.text


def test_dashboard_no_resources(auth_client_owner, test_organization):
    """Test dashboard with no resources for the selected organization."""
    auth_client_owner.cookies.set(
        "selected_organization_id", str(test_organization.id)
    )
    response = auth_client_owner.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "No resources found" in response.text


def test_dashboard_member_no_read_permission(
    auth_client_member,
    session: Session,
    test_organization: Organization,
):
    """Test that members without READ_ORGANIZATION_RESOURCES see permission message."""
    assert test_organization.id is not None
    resource = OrganizationResource(
        organization_id=test_organization.id,
        title="Hidden Resource",
    )
    session.add(resource)
    session.commit()

    auth_client_member.cookies.set(
        "selected_organization_id", str(test_organization.id)
    )
    response = auth_client_member.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "do not have permission" in response.text
    assert "Hidden Resource" not in response.text


def test_dashboard_invalid_org_cookie(auth_client_owner, test_organization):
    """Test that an invalid org cookie falls back to first organization."""
    auth_client_owner.cookies.set("selected_organization_id", "not-a-number")
    response = auth_client_owner.get(
        app.url_path_for("read_dashboard"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    # Should still render with first org selected
    assert test_organization.name in response.text
