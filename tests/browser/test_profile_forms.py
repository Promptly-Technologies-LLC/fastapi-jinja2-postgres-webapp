"""
Playwright tests for profile page HTMX form behaviors:

1. Edit profile form: clicking Edit fetches form via hx-get, submitting swaps back to display
2. Add email form: after submit, the email input is cleared
"""

import pytest
from playwright.sync_api import Page, expect

from tests.browser.conftest import login_user, register_user


@pytest.fixture(scope="session")
def _register_profile_user(browser, live_server: str):
    """Register a dedicated user for profile form tests."""
    register_user(
        browser,
        live_server,
        name="Profile Test User",
        email="profile-tests@example.com",
        password="TestPass123!@#",
    )


@pytest.fixture()
def profile_page(browser, live_server: str, _register_profile_user):
    """Log in and navigate to the profile page."""
    page = login_user(
        browser,
        live_server,
        email="profile-tests@example.com",
        password="TestPass123!@#",
    )
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")
    yield page
    page.context.close()


# Generous bound for htmx round trips under CI load; the assertions below
# still fail fast on a genuinely broken swap since they poll, not sleep.
HTMX_SWAP_TIMEOUT_MS = 10_000


def test_edit_profile_swap_cycle(profile_page: Page):
    """Clicking Edit fetches the form via hx-get; submitting swaps back to display."""
    page = profile_page
    card = page.locator("#profile-card")

    # Initially shows display mode with Edit button, no form
    expect(card.locator("button:has-text('Edit')")).to_be_visible()
    expect(card.locator("form")).to_have_count(0)

    # Click Edit — fetches form partial via hx-get. Wait for the response
    # itself (not just the eventual DOM state) so a slow server round trip
    # produces a clear network-timeout failure rather than a flaky locator
    # mismatch.
    with page.expect_response("**/user/edit-form"):
        card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(
        timeout=HTMX_SWAP_TIMEOUT_MS
    )

    # Submit the form
    with page.expect_response("**/user/update"):
        card.locator('button[type="submit"]').click()

    # Should swap back to display mode
    expect(card.locator("button:has-text('Edit')")).to_be_visible(
        timeout=HTMX_SWAP_TIMEOUT_MS
    )
    expect(card.locator('button[type="submit"]')).to_have_count(
        0, timeout=HTMX_SWAP_TIMEOUT_MS
    )


def test_edit_profile_cancel(profile_page: Page):
    """Clicking Cancel fetches the display partial without submitting."""
    page = profile_page
    card = page.locator("#profile-card")

    # Click Edit
    with page.expect_response("**/user/edit-form"):
        card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(
        timeout=HTMX_SWAP_TIMEOUT_MS
    )

    # Click Cancel
    with page.expect_response("**/user/profile-display"):
        card.locator("button:has-text('Cancel')").click()

    # Should swap back to display mode
    expect(card.locator("button:has-text('Edit')")).to_be_visible(
        timeout=HTMX_SWAP_TIMEOUT_MS
    )
    expect(card.locator('button[type="submit"]')).to_have_count(
        0, timeout=HTMX_SWAP_TIMEOUT_MS
    )


def test_add_email_form_resets_after_submit(profile_page: Page):
    """After submitting the add-email form via HTMX, the email input should
    be cleared."""
    page = profile_page

    email_input = page.locator('input[name="new_email"]')
    expect(email_input).to_be_visible()

    # Type an email and submit
    email_input.fill("new-browser-test@example.com")
    assert email_input.input_value() == "new-browser-test@example.com"

    with page.expect_response("**/account/emails/add"):
        page.click('form:has(input[name="new_email"]) button[type="submit"]')

    # hx-on::after-settle resets the form after the swap completes
    expect(email_input).to_have_value("", timeout=HTMX_SWAP_TIMEOUT_MS)
