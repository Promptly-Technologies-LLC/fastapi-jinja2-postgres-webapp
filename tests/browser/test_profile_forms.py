"""
Playwright tests for profile page HTMX form behaviors:

1. Edit profile form: clicking Edit fetches form via hx-get, submitting swaps back to display
2. Add email form: after submit, the email input is cleared
"""
import pytest
from playwright.sync_api import Page, expect


@pytest.fixture(scope="session")
def _register_profile_user(browser, live_server: str):
    """Register a dedicated user for profile form tests."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    p = context.new_page()
    p.goto(f"{live_server}/account/register")
    p.fill("#name", "Profile Test User")
    p.fill("#email", "profile-tests@example.com")
    p.fill("#password", "TestPass123!@#")
    p.fill("#confirm_password", "TestPass123!@#")
    p.click('button[type="submit"]')
    p.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    context.close()


@pytest.fixture()
def profile_page(browser, live_server: str, _register_profile_user):
    """Log in and navigate to the profile page."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    p = context.new_page()
    p.goto(f"{live_server}/account/login")
    p.fill("#email", "profile-tests@example.com")
    p.fill("#password", "TestPass123!@#")
    p.click('button[type="submit"]')
    p.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    p.goto(f"{live_server}/user/profile")
    p.wait_for_load_state("networkidle")
    yield p
    context.close()


def test_edit_profile_swap_cycle(profile_page: Page):
    """Clicking Edit fetches the form via hx-get; submitting swaps back to display."""
    page = profile_page
    card = page.locator("#profile-card")

    # Initially shows display mode with Edit button, no form
    expect(card.locator("button:has-text('Edit')")).to_be_visible()
    expect(card.locator("form")).to_have_count(0)

    # Click Edit — fetches form partial via hx-get
    card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(timeout=5_000)

    # Submit the form
    card.locator('button[type="submit"]').click()

    # Should swap back to display mode
    expect(card.locator("button:has-text('Edit')")).to_be_visible(timeout=5_000)
    expect(card.locator('button[type="submit"]')).to_have_count(0, timeout=5_000)


def test_edit_profile_cancel(profile_page: Page):
    """Clicking Cancel fetches the display partial without submitting."""
    page = profile_page
    card = page.locator("#profile-card")

    # Click Edit
    card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(timeout=5_000)

    # Click Cancel
    card.locator("button:has-text('Cancel')").click()

    # Should swap back to display mode
    expect(card.locator("button:has-text('Edit')")).to_be_visible(timeout=5_000)
    expect(card.locator('button[type="submit"]')).to_have_count(0, timeout=5_000)


def test_add_email_form_resets_after_submit(profile_page: Page):
    """After submitting the add-email form via HTMX, the email input should
    be cleared."""
    page = profile_page

    email_input = page.locator('input[name="new_email"]')
    expect(email_input).to_be_visible()

    # Type an email and submit
    email_input.fill("new-browser-test@example.com")
    assert email_input.input_value() == "new-browser-test@example.com"

    page.click('form:has(input[name="new_email"]) button[type="submit"]')

    # hx-on::after-settle resets the form after the swap completes
    expect(email_input).to_have_value("", timeout=5_000)
