"""Browser E2E organization RBAC and role management workflows."""

import re
import uuid
from collections.abc import Iterator

import pytest
from playwright.sync_api import Page, expect

from tests.browser.conftest import login_user, register_user
from tests.browser.db_helpers import add_member_to_organization, browser_db_session
from utils.core.enums import ValidPermissions


@pytest.fixture(scope="session")
def _register_rbac_owner(browser, live_server: str):
    register_user(
        browser,
        live_server,
        name="RBAC Owner",
        email="rbac-owner@example.com",
        password="TestPass123!@#",
    )


@pytest.fixture(scope="session")
def rbac_org_id(browser, live_server: str, _register_rbac_owner) -> int:
    page = login_user(
        browser,
        live_server,
        email="rbac-owner@example.com",
        password="TestPass123!@#",
    )
    org_name = f"RBAC Org {uuid.uuid4().hex[:8]}"
    page.goto(f"{live_server}/user/profile")
    page.wait_for_load_state("networkidle")
    page.locator(".profile-organizations-create-btn").click()
    form = page.locator("#newOrgForm")
    form.locator('input[name="name"]').fill(org_name)
    form.locator('button[type="submit"]').click()
    page.wait_for_url(re.compile(r".*/organizations/\d+"))
    org_id = int(page.url.rstrip("/").split("/")[-1])
    page.context.close()
    return org_id


@pytest.fixture(scope="session")
def _seed_rbac_member(rbac_org_id: int):
    with browser_db_session() as session:
        add_member_to_organization(
            session,
            rbac_org_id,
            email="rbac-member@example.com",
            password="Member123!@#",
            name="RBAC Member",
        )


@pytest.fixture()
def owner_org_page(
    browser, live_server: str, _register_rbac_owner, rbac_org_id: int
) -> Iterator[Page]:
    page = login_user(
        browser,
        live_server,
        email="rbac-owner@example.com",
        password="TestPass123!@#",
    )
    page.goto(f"{live_server}/organizations/{rbac_org_id}")
    page.wait_for_load_state("networkidle")
    yield page
    page.context.close()


@pytest.fixture()
def member_org_page(
    browser,
    live_server: str,
    rbac_org_id: int,
    _seed_rbac_member,
) -> Iterator[Page]:
    page = login_user(
        browser,
        live_server,
        email="rbac-member@example.com",
        password="Member123!@#",
    )
    page.goto(f"{live_server}/organizations/{rbac_org_id}")
    page.wait_for_load_state("networkidle")
    yield page
    page.context.close()


def test_owner_sees_management_controls(owner_org_page: Page):
    page = owner_org_page
    expect(
        page.locator('button[data-bs-target="#editOrganizationModal"]')
    ).to_be_visible()
    expect(
        page.locator('button[data-bs-target="#deleteOrganizationModal"]')
    ).to_be_visible()
    expect(page.locator('button[data-bs-target="#createRoleModal"]')).to_be_visible()
    expect(page.locator('button[data-bs-target="#inviteMemberModal"]')).to_be_visible()


def test_member_cannot_see_management_controls(member_org_page: Page):
    page = member_org_page
    expect(page.locator('button:has-text("Edit Organization")')).to_have_count(0)
    expect(page.locator('button:has-text("Delete Organization")')).to_have_count(0)
    expect(page.locator('button:has-text("Create Role")')).to_have_count(0)
    expect(page.locator('button:has-text("Invite Member")')).to_have_count(0)
    expect(page.locator("body")).to_contain_text("Members")


def test_owner_creates_and_edits_custom_role(owner_org_page: Page):
    page = owner_org_page
    role_name = f"Custom Role {uuid.uuid4().hex[:6]}"
    updated_name = f"{role_name} Updated"

    page.locator('button[data-bs-target="#createRoleModal"]').click()
    modal = page.locator("#createRoleModal")
    expect(modal).to_be_visible()
    modal.locator('input[name="name"]').fill(role_name)
    perm_value = ValidPermissions.INVITE_USER.value
    modal.locator(f'label[for="perm_{perm_value.replace(" ", "_")}"]').click()
    modal.locator('form button[type="submit"]').click()

    expect(page.locator("#roles-table-body")).to_contain_text(role_name, timeout=10_000)

    page.locator('#roles-table-body button:has-text("Edit Role")').first.click()
    edit_modal = page.locator('[id^="editRoleModal"]').filter(has=page.locator("form"))
    expect(edit_modal).to_be_visible()
    edit_modal.locator('input[name="name"]').fill(updated_name)
    edit_modal.locator('button[type="submit"]:has-text("Save Changes")').click()

    expect(page.locator("#roles-table-body")).to_contain_text(
        updated_name, timeout=10_000
    )
    expect(
        page.locator(f"#roles-table-body tr:has-text('{updated_name}')")
    ).to_have_count(1)
