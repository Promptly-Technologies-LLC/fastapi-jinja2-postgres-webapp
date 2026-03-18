"""
Playwright regression tests for toast display behavior.

Covers three toast delivery paths:
1. HTMX success toast — OOB swap appended to a successful HTMX response
2. HTMX error toast — toast delivered via error response (e.g. bad credentials)
3. Flash cookie toast — cookie set on redirect, displayed on next page load

Also verifies auto-dismiss (~5 s) and manual close via the X button.
"""
import io
import pytest
from PIL import Image
from playwright.sync_api import Page, expect


@pytest.fixture(scope="session")
def _register_toast_user(browser, live_server: str):
    """Register a dedicated user for toast tests."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    p = context.new_page()
    p.goto(f"{live_server}/account/register")
    p.fill("#name", "Toast Test User")
    p.fill("#email", "toast-tests@example.com")
    p.fill("#password", "TestPass123!@#")
    p.fill("#confirm_password", "TestPass123!@#")
    p.click('button[type="submit"]')
    p.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    context.close()


@pytest.fixture()
def logged_in_page(browser, live_server: str, _register_toast_user):
    """Log in and return a page on the dashboard."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    p = context.new_page()
    p.goto(f"{live_server}/account/login")
    p.fill("#email", "toast-tests@example.com")
    p.fill("#password", "TestPass123!@#")
    p.click('button[type="submit"]')
    p.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    yield p
    context.close()


@pytest.fixture()
def anon_page(browser, live_server: str, _register_toast_user):
    """Return a page that is NOT logged in."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    p = context.new_page()
    p.goto(f"{live_server}/account/login")
    p.wait_for_load_state("networkidle")
    yield p
    context.close()


# --- 1. HTMX success toast (OOB swap) ---


def test_htmx_success_toast_appears(logged_in_page: Page, live_server: str):
    """Updating profile name via HTMX produces a success toast."""
    page = logged_in_page
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")

    card = page.locator("#profile-card")
    # Enter edit mode
    card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(timeout=5_000)

    # Submit the form (name unchanged is fine)
    card.locator('button[type="submit"]').click()

    # A success toast should appear in the container
    toast = page.locator("#toast-container .toast.text-bg-success")
    expect(toast).to_be_visible(timeout=5_000)
    expect(toast).to_contain_text("Profile updated successfully")


def _submit_avatar(page: Page, live_server: str, tmp_path):
    """Navigate to profile, upload an avatar, and submit. Returns the page."""
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")

    card = page.locator("#profile-card")
    card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(timeout=5_000)

    # Create a valid 200x200 PNG image
    img = Image.new("RGB", (200, 200), color="blue")
    img_path = tmp_path / "avatar.png"
    img.save(img_path, format="PNG")

    card.locator('input[name="avatar_file"]').set_input_files(str(img_path))
    card.locator('button[type="submit"]').click()
    return page


def test_avatar_update_toast_appears(logged_in_page: Page, live_server: str, tmp_path):
    """Updating avatar should show a success toast."""
    page = _submit_avatar(logged_in_page, live_server, tmp_path)

    toast = page.locator("#toast-container .toast.text-bg-success")
    expect(toast).to_be_visible(timeout=10_000)
    expect(toast).to_contain_text("Profile updated successfully")


def test_avatar_update_no_full_reload(logged_in_page: Page, live_server: str, tmp_path):
    """Avatar update should use OOB swaps, not a full page reload."""
    page = logged_in_page
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")

    # Mark the DOM so we can detect if the page was fully reloaded
    page.evaluate("() => { window.__noReload = true; }")

    card = page.locator("#profile-card")
    card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(timeout=5_000)

    img = Image.new("RGB", (200, 200), color="red")
    img_path = tmp_path / "avatar.png"
    img.save(img_path, format="PNG")
    card.locator('input[name="avatar_file"]').set_input_files(str(img_path))
    card.locator('button[type="submit"]').click()

    # Wait for profile display to swap back in
    expect(card.locator("button:has-text('Edit')")).to_be_visible(timeout=10_000)

    # The navbar avatar should also have updated (OOB swap)
    navbar_avatar = page.locator("#navbar-avatar img")
    expect(navbar_avatar).to_be_visible(timeout=5_000)

    # DOM marker should survive — proves no full page reload happened
    marker = page.evaluate("() => window.__noReload")
    assert marker is True, "Page was fully reloaded instead of using OOB swaps"



# --- 2. HTMX error toast (error response path) ---


def test_htmx_error_toast_appears(anon_page: Page):
    """Submitting bad credentials via HTMX shows a danger toast."""
    page = anon_page

    page.fill("#email", "toast-tests@example.com")
    page.fill("#password", "WrongPassword999!")
    page.click('button[type="submit"]')

    toast = page.locator("#toast-container .toast.text-bg-danger")
    expect(toast).to_be_visible(timeout=5_000)


# --- 3. Flash cookie toast (redirect + cookie) ---


def test_flash_cookie_toast_appears(anon_page: Page, live_server: str):
    """Forgot-password flow sets a flash cookie; toast appears after redirect."""
    page = anon_page

    page.goto(f"{live_server}/account/forgot_password")
    page.wait_for_load_state("networkidle")

    page.fill("#email", "toast-tests@example.com")
    page.click('button[type="submit"]')

    # The server sets HX-Redirect + flash cookie.  After the redirect the
    # toast should be visible on the new page.
    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=10_000)
    expect(toast).to_contain_text("If an account exists")


# --- 4. Auto-dismiss ---


def test_toast_auto_dismisses(anon_page: Page, live_server: str):
    """Flash-cookie toasts (via showToast) disappear automatically after ~5 s."""
    page = anon_page

    page.goto(f"{live_server}/account/forgot_password")
    page.wait_for_load_state("networkidle")

    page.fill("#email", "toast-tests@example.com")
    page.click('button[type="submit"]')

    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=10_000)

    # showToast removes the element after 5 s — wait with buffer
    expect(toast).to_have_count(0, timeout=8_000)


# --- 5. Manual close button ---


def test_toast_close_button(logged_in_page: Page, live_server: str):
    """Clicking the close button on a toast hides it."""
    page = logged_in_page
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")

    card = page.locator("#profile-card")
    card.locator("button:has-text('Edit')").click()
    expect(card.locator('button:has-text("Save Changes")')).to_be_visible(timeout=5_000)
    card.locator('button[type="submit"]').click()

    toast = page.locator("#toast-container .toast")
    expect(toast).to_be_visible(timeout=5_000)

    # Click the close button — Bootstrap hides but doesn't remove from DOM
    toast.locator('button[data-bs-dismiss="toast"]').click()

    # Toast should become invisible
    expect(toast).not_to_be_visible(timeout=2_000)
