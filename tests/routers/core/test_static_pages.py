import pytest
from fastapi.testclient import TestClient
from routers.core.static_pages import VALID_PAGES

# Get valid page names from the router module
valid_page_names = list(VALID_PAGES.keys())


@pytest.mark.parametrize("page_name", valid_page_names)
def test_read_static_page_unauthenticated(
    unauth_client: TestClient,
    page_name: str
):
    """Test that valid static pages return 200 OK for unauthenticated users."""
    response = unauth_client.get(f"/{page_name}")
    assert response.status_code == 200


@pytest.mark.parametrize("page_name", valid_page_names)
def test_read_static_page_authenticated(
    auth_client: TestClient,
    page_name: str
):
    """Test that valid static pages return 200 OK for authenticated users."""
    response = auth_client.get(f"/{page_name}")
    assert response.status_code == 200


def test_read_static_page_not_found(unauth_client: TestClient):
    """Test that an invalid page name returns 404 Not Found."""
    invalid_page_name = "invalid-page"
    response = unauth_client.get(f"/{invalid_page_name}")
    assert response.status_code == 404
    assert "not found" in response.text.lower()
