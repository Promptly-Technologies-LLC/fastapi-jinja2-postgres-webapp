"""Browser E2E invitation accept and expired-token workflows."""

import uuid

from playwright.sync_api import expect

from tests.browser.db_helpers import (
    browser_db_session,
    get_host_organization,
    get_member_role_id,
    seed_invitation,
)
from utils.core.models import Account, Invitation, User
from sqlmodel import select


def _accept_url(live_server: str, token: str) -> str:
    return f"{live_server}/invitations/accept?token={token}"


def test_expired_invitation_shows_warning_on_register(browser, live_server: str):
    invitee_email = f"expired-invite-{uuid.uuid4().hex[:8]}@example.com"
    with browser_db_session() as session:
        org = get_host_organization(session)
        assert org.id is not None
        invitation = seed_invitation(
            session,
            organization_id=org.id,
            role_id=get_member_role_id(session, org.id),
            invitee_email=invitee_email,
            expired=True,
        )
        token = invitation.token

    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(_accept_url(live_server, token))
    page.wait_for_url("**/account/register**")
    expect(page.locator(".alert-warning")).to_contain_text("expired")
    expect(page.locator("#email")).to_have_value(invitee_email)
    expect(page.locator('input[name="invitation_token"]')).to_have_value(token)
    context.close()


def test_valid_invitation_register_accept_lands_on_organization(
    browser, live_server: str
):
    invitee_email = f"new-invitee-{uuid.uuid4().hex[:8]}@example.com"
    org_name = None
    org_id = None
    token = None

    with browser_db_session() as session:
        org = get_host_organization(session)
        assert org.id is not None
        org_id = org.id
        org_name = org.name
        invitation = seed_invitation(
            session,
            organization_id=org.id,
            role_id=get_member_role_id(session, org.id),
            invitee_email=invitee_email,
        )
        token = invitation.token

    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(_accept_url(live_server, token))
    page.wait_for_url("**/account/register**")
    expect(page.locator("#email")).to_have_value(invitee_email)

    page.fill("#name", "Invited Browser User")
    page.fill("#password", "TestPass123!@#")
    page.fill("#confirm_password", "TestPass123!@#")
    page.click('button[type="submit"]')

    page.wait_for_url(f"**/organizations/{org_id}**", timeout=15_000)
    expect(page.locator("body")).to_contain_text(org_name or "")
    expect(page.locator("body")).to_contain_text("Members")

    with browser_db_session() as session:
        account = session.exec(
            select(Account).where(Account.email == invitee_email)
        ).one()
        user = session.exec(select(User).where(User.account_id == account.id)).one()
        invitation = session.exec(
            select(Invitation).where(Invitation.token == token)
        ).one()
        assert invitation.used is True
        assert invitation.accepted_by_user_id == user.id
        assert any(role.organization_id == org_id for role in user.roles)
    context.close()


def test_expired_invitation_disables_registration_submit(browser, live_server: str):
    invitee_email = f"blocked-expired-{uuid.uuid4().hex[:8]}@example.com"
    with browser_db_session() as session:
        org = get_host_organization(session)
        assert org.id is not None
        invitation = seed_invitation(
            session,
            organization_id=org.id,
            role_id=get_member_role_id(session, org.id),
            invitee_email=invitee_email,
            expired=True,
        )
        token = invitation.token

    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(
        f"{live_server}/account/register?email={invitee_email}&invitation_token={token}"
    )
    expect(page.locator(".alert-warning")).to_contain_text("expired")
    submit = page.locator('form button[type="submit"]')
    expect(submit).to_be_disabled()
    expect(submit).to_have_attribute("aria-disabled", "true")

    with browser_db_session() as session:
        account = session.exec(
            select(Account).where(Account.email == invitee_email)
        ).first()
        assert account is None
    context.close()
