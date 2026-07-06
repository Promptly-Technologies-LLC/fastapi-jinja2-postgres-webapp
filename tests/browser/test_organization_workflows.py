"""Browser E2E organization workflows."""

import uuid
from collections.abc import Iterator

import pytest
from playwright.sync_api import Page, expect

from tests.browser.conftest import login_user, register_user


@pytest.fixture(scope="session")
def _register_org_workflow_user(browser, live_server: str):
    register_user(
        browser,
        live_server,
        name="Org Workflow User",
        email="org-workflow@example.com",
        password="TestPass123!@#",
    )


@pytest.fixture()
def org_workflow_page(
    browser, live_server: str, _register_org_workflow_user
) -> Iterator[Page]:
    page = login_user(
        browser,
        live_server,
        email="org-workflow@example.com",
        password="TestPass123!@#",
    )
    yield page
    page.context.close()


def test_create_and_open_organization(org_workflow_page: Page, live_server: str):
    page = org_workflow_page
    org_name = f"Browser Org {uuid.uuid4().hex[:8]}"
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")

    page.locator(".profile-organizations-create-btn").click()
    form = page.locator("#newOrgForm")
    expect(form).to_be_visible()
    form.locator('input[name="name"]').fill(org_name)
    form.locator('button[type="submit"]').click()

    page.wait_for_url("**/organizations/**")
    expect(page.locator("body")).to_contain_text("Members")
    expect(page.locator("body")).to_contain_text(org_name)

    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")
    expect(page.locator(".profile-organization-list")).to_contain_text(org_name)
