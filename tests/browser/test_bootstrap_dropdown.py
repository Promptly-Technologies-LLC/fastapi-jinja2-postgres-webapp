"""
Playwright integration test: Bootstrap dropdowns must remain functional after
hx-boost page navigation.

Bug: hx-boost replaces body innerHTML via AJAX. If Bootstrap's event delegation
or the app's custom delegation handler is lost during the swap, clicking
[data-bs-toggle="dropdown"] elements does nothing until a full page refresh.
"""

import pytest
from playwright.sync_api import Page, expect

from tests.browser.conftest import login_user, register_user


@pytest.fixture(scope="session")
def _register_user(browser, live_server: str):
    """Register a user once per session (shared across tests)."""
    register_user(
        browser,
        live_server,
        name="Playwright User",
        email="playwright@example.com",
        password="TestPass123!@#",
    )


@pytest.fixture()
def logged_in_page(browser, live_server: str, _register_user):
    """Log in via a fresh browser context and land on the dashboard."""
    page = login_user(
        browser,
        live_server,
        email="playwright@example.com",
        password="TestPass123!@#",
    )
    yield page
    page.context.close()


def test_profile_dropdown_works_on_initial_load(logged_in_page: Page):
    """Sanity check: the profile dropdown works on initial (non-boosted) load."""
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    dropdown_toggle = page.locator("#navbarDropdown")
    expect(dropdown_toggle).to_be_visible(timeout=2_000)
    dropdown_toggle.click()

    dropdown_menu = page.locator(".nav-item.dropdown .dropdown-menu")
    expect(dropdown_menu).to_be_visible(timeout=2_000)


def test_profile_dropdown_works_after_boost_navigation(
    logged_in_page: Page, live_server: str
):
    """After navigating via a boosted link, the profile dropdown must open."""
    page = logged_in_page

    # Full page load of the profile page (different URL from dashboard).
    page.goto(f"{live_server}/account/profile")
    page.wait_for_load_state("networkidle")

    # Click the boosted "Dashboard" nav link — triggers hx-boost body swap.
    page.click('a.nav-link:has-text("Dashboard")')
    page.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=5_000
    )
    page.wait_for_load_state("networkidle")

    # Now try to open the profile dropdown (desktop header).
    dropdown_toggle = page.locator("#navbarDropdown")
    expect(dropdown_toggle).to_be_visible(timeout=2_000)
    dropdown_toggle.click()

    # The dropdown menu should become visible.
    dropdown_menu = page.locator(".nav-item.dropdown .dropdown-menu")
    expect(dropdown_menu).to_be_visible(timeout=2_000)
