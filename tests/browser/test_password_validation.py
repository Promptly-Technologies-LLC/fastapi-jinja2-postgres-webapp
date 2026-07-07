"""HTML password validation in the browser."""

from collections.abc import Iterator

import pytest
from playwright.sync_api import Page

from utils.core.auth import HTML_PASSWORD_PATTERN


@pytest.fixture()
def register_page(browser, live_server: str) -> Iterator[Page]:
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server}/account/register")
    page.wait_for_load_state("networkidle")
    yield page
    context.close()


def test_password_input_pattern_matches_server_regex(register_page: Page):
    pattern = register_page.locator("#password").get_attribute("pattern")
    assert pattern == HTML_PASSWORD_PATTERN


def test_confirm_password_mismatch_blocks_validity(register_page: Page):
    register_page.fill("#password", "TestPass123!@#")
    register_page.fill("#confirm_password", "DifferentPass123!@#")
    register_page.evaluate(
        "() => document.getElementById('confirm_password').dispatchEvent(new Event('input'))"
    )
    message = register_page.evaluate(
        "() => document.getElementById('confirm_password').validationMessage"
    )
    assert "match" in message.lower()


def test_confirm_password_match_clears_custom_validity(register_page: Page):
    register_page.fill("#password", "TestPass123!@#")
    register_page.fill("#confirm_password", "TestPass123!@#")
    register_page.evaluate(
        "() => document.getElementById('confirm_password').dispatchEvent(new Event('input'))"
    )
    validity = register_page.evaluate(
        "() => document.getElementById('confirm_password').validity.valid"
    )
    assert validity is True


@pytest.mark.parametrize(
    "password,should_be_valid",
    [
        ("noupper1!", False),
        ("NOLOWER1!", False),
        ("NoDigits!!", False),
        ("NoSpecial1", False),
        ("TestPass123!@#", True),
    ],
)
def test_password_requirement_cases(
    register_page: Page, password: str, should_be_valid: bool
):
    register_page.fill("#password", password)
    validity = register_page.evaluate(
        "() => document.getElementById('password').validity.valid"
    )
    assert validity is should_be_valid
