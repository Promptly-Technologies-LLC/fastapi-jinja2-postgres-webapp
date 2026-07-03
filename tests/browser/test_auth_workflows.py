"""Browser E2E auth and account workflows."""

from collections.abc import Iterator

import pytest
from playwright.sync_api import Page, expect

from tests.browser.conftest import login_user, register_user


@pytest.fixture(scope="session")
def _register_auth_workflow_user(browser, live_server: str):
    register_user(
        browser,
        live_server,
        name="Auth Workflow User",
        email="auth-workflow@example.com",
        password="TestPass123!@#",
    )


@pytest.fixture()
def auth_workflow_page(
    browser, live_server: str, _register_auth_workflow_user
) -> Iterator[Page]:
    page = login_user(
        browser,
        live_server,
        email="auth-workflow@example.com",
        password="TestPass123!@#",
    )
    yield page
    page.context.close()


def test_login_logout_cycle(auth_workflow_page: Page, live_server: str):
    page = auth_workflow_page
    page.goto(f"{live_server}/account/logout")
    page.wait_for_function(
        "window.location.pathname === '/' || window.location.pathname === ''",
        timeout=10_000,
    )
    expect(page.locator('a:has-text("Log in")')).to_be_visible()


def test_forgot_password_shows_confirmation(browser, live_server: str):
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server}/account/forgot_password")
    page.fill("#email", "auth-workflow@example.com")
    page.click('button[type="submit"]')

    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=10_000)
    expect(toast).to_contain_text("If an account exists")
    context.close()


def test_static_about_page_reachable_from_footer(
    auth_workflow_page: Page, live_server: str
):
    page = auth_workflow_page
    page.goto(f"{live_server}/dashboard/")
    page.wait_for_load_state("networkidle")
    page.locator('footer a:has-text("About")').click()
    page.wait_for_url("**/about")
    expect(page.locator("body")).to_contain_text("About")
