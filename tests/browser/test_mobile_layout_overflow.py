"""Regression: pages must not widen the document on narrow viewports."""

import re
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest
from playwright.sync_api import Browser, Page

from tests.conftest import add_owner_to_organization

MOBILE_VIEWPORT = {"width": 390, "height": 844}
DESKTOP_VIEWPORT = {"width": 1280, "height": 720}
STYLES_CSS = Path("static/css/styles.css").read_text()
EXTRAS_CSS = Path("static/css/extras.css").read_text()


def _inject_static_css(html: str) -> str:
    """set_content cannot fetch testserver static URLs; inline project CSS."""
    html = re.sub(
        r'<link[^>]+href="[^"]*styles\.css"[^>]*>',
        f"<style>{STYLES_CSS}</style>",
        html,
        count=1,
    )
    return re.sub(
        r'<link[^>]+href="[^"]*extras\.css"[^>]*>',
        f"<style>{EXTRAS_CSS}</style>",
        html,
        count=1,
    )


def _document_overflow_ratio(page: Page) -> float:
    return page.evaluate(
        """() => document.documentElement.scrollWidth / window.innerWidth"""
    )


@contextmanager
def _viewport_page(browser: Browser, html: str, viewport: dict) -> Iterator[Page]:
    context = browser.new_context(viewport=viewport)
    page = context.new_page()
    page.set_content(html, wait_until="load")
    try:
        yield page
    finally:
        context.close()


def _evaluate_at_viewport(browser: Browser, html: str, viewport: dict, script: str):
    with _viewport_page(browser, html, viewport) as page:
        return page.evaluate(script)


def _wrap_body_with_styles(body_html: str) -> str:
    return (
        "<!DOCTYPE html><html><head>"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<style>{STYLES_CSS}</style>"
        f"<style>{EXTRAS_CSS}</style>"
        "</head><body>"
        f"{body_html}</body></html>"
    )


@pytest.mark.usefixtures("env_vars")
def test_organization_header_long_unspaced_name_stacks_on_mobile(
    browser,
    auth_client_owner,
    test_organization,
    session,
):
    test_organization.name = "FastAPIJinjaPostgres" * 8
    session.add(test_organization)
    session.commit()
    assert test_organization.id is not None

    html = _inject_static_css(
        auth_client_owner.get(f"/organizations/{test_organization.id}").text
    )

    layout_check = """() => {
        const header = document.querySelector('.organization-page-header');
        const title = document.querySelector('.organization-page-header-title');
        const actions = document.querySelector('.organization-page-header-actions');
        if (!header || !title || !actions) {
            return { ok: false, reason: 'missing organization header elements' };
        }
        const titleRect = title.getBoundingClientRect();
        const actionsRect = actions.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = titleRect.bottom <= actionsRect.top + 2;
        return {
            ok: ratio <= 1.0
                && stacked
                && titleRect.right <= window.innerWidth + 1
                && actionsRect.right <= window.innerWidth + 1,
            ratio,
            stacked,
            titleRight: titleRect.right,
            actionsRight: actionsRect.right,
            viewport: window.innerWidth,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_dashboard_org_selector_layout_by_viewport(
    browser,
    auth_client_owner,
    org_owner,
    session,
    test_organization,
    second_test_organization,
):
    add_owner_to_organization(session, org_owner, second_test_organization)
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const row = document.querySelector('.dashboard-org-selector');
        const label = document.querySelector('.dashboard-org-selector-label');
        const toggle = document.querySelector('#orgSelect');
        if (!row || !label || !toggle) {
            return { ok: false, reason: 'missing org selector controls' };
        }
        const rowStyle = getComputedStyle(row);
        const labelRect = label.getBoundingClientRect();
        const toggleRect = toggle.getBoundingClientRect();
        const stacked = rowStyle.flexDirection === 'column'
            && labelRect.bottom <= toggleRect.top + 2
            && Math.abs(toggleRect.width - row.getBoundingClientRect().width) < 4;
        const sideBySide = rowStyle.flexDirection === 'row'
            && labelRect.right <= toggleRect.left + 2;
        return {
            ok: stacked || sideBySide,
            flexDirection: rowStyle.flexDirection,
            stacked,
            sideBySide,
            toggleWidth: toggleRect.width,
            rowWidth: row.getBoundingClientRect().width,
        };
    }"""

    mobile_result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)
    assert mobile_result.get("stacked"), mobile_result

    desktop_result = _evaluate_at_viewport(
        browser, html, DESKTOP_VIEWPORT, layout_check
    )
    assert desktop_result.get("sideBySide"), desktop_result


@pytest.mark.usefixtures("env_vars")
def test_dashboard_single_org_label_and_name_on_one_line(
    browser,
    auth_client_owner,
    test_organization,
):
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const label = document.querySelector('.dashboard-org-selector-label');
        const name = document.querySelector('.dashboard-org-selector-name');
        if (!label || !name) {
            return { ok: false, reason: 'missing single-org label or name' };
        }
        const labelRect = label.getBoundingClientRect();
        const nameRect = name.getBoundingClientRect();
        const sameLine = nameRect.left > labelRect.left
            && labelRect.top <= nameRect.bottom + 2
            && nameRect.top <= labelRect.bottom + 2;
        return {
            ok: sameLine,
            labelLeft: labelRect.left,
            nameLeft: nameRect.left,
            labelTop: labelRect.top,
            nameTop: nameRect.top,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_dashboard_org_selector_long_name_fits_mobile_viewport(
    browser,
    auth_client_owner,
    test_organization,
    session,
):
    test_organization.name = "FastAPIJinjaPostgres" * 8
    session.add(test_organization)
    session.commit()

    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const name = document.querySelector('.dashboard-org-selector-name');
        const row = document.querySelector('.dashboard-org-selector');
        if (!name || !row) {
            return { ok: false, reason: 'missing single-org name display' };
        }
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const nameRect = name.getBoundingClientRect();
        const rowRect = row.getBoundingClientRect();
        return {
            ok: ratio <= 1.0
                && nameRect.right <= window.innerWidth + 1
                && rowRect.right <= window.innerWidth + 1,
            ratio,
            nameRight: nameRect.right,
            viewport: window.innerWidth,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_dashboard_resource_list_items_stack_on_mobile(
    browser,
    auth_client_owner,
    test_organization,
    session,
):
    from utils.app.models import OrganizationResource

    assert test_organization.id is not None
    session.add(
        OrganizationResource(
            organization_id=test_organization.id,
            title="MobileResourceTitle" * 6,
            description="Long description for mobile layout " * 4,
        )
    )
    session.commit()

    auth_client_owner.cookies.set("selected_organization_id", str(test_organization.id))
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const header = document.querySelector('.dashboard-resource-item-header');
        const title = document.querySelector('.dashboard-resource-item-title');
        const date = document.querySelector('.dashboard-resource-item-date');
        if (!header || !title || !date) {
            return { ok: false, reason: 'missing resource list item' };
        }
        const headerStyle = getComputedStyle(header);
        const titleRect = title.getBoundingClientRect();
        const dateRect = date.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = headerStyle.flexDirection === 'column'
            && dateRect.top >= titleRect.bottom - 2;
        return {
            ok: ratio <= 1.0 && stacked,
            ratio,
            stacked,
            flexDirection: headerStyle.flexDirection,
            titleRight: titleRect.right,
            viewport: window.innerWidth,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_dashboard_document_width_fits_mobile_viewport(
    browser,
    auth_client_owner,
):
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    with _viewport_page(browser, html, MOBILE_VIEWPORT) as page:
        ratio = _document_overflow_ratio(page)

    assert ratio <= 1.0, f"document scrollWidth exceeds viewport ({ratio:.3f}x)"


@pytest.mark.usefixtures("env_vars")
def test_organization_page_document_width_fits_mobile_viewport(
    browser,
    auth_client_owner,
    test_organization,
):
    assert test_organization.id is not None
    html = _inject_static_css(
        auth_client_owner.get(f"/organizations/{test_organization.id}").text
    )

    with _viewport_page(browser, html, MOBILE_VIEWPORT) as page:
        ratio = _document_overflow_ratio(page)

    assert ratio <= 1.0, f"document scrollWidth exceeds viewport ({ratio:.3f}x)"


@pytest.mark.usefixtures("env_vars")
def test_profile_email_rows_stack_on_mobile(
    browser,
    auth_client,
    test_account,
    test_account_email,
    session,
):
    from datetime import UTC, datetime

    from utils.core.models import AccountEmail

    session.add(
        AccountEmail(
            account_id=test_account.id,
            email="secondary." + ("mobile" * 12) + "@example.com",
            is_primary=False,
            verified=True,
            verified_at=datetime.now(UTC),
        )
    )
    session.commit()

    html = _inject_static_css(auth_client.get("/user/profile").text)

    layout_check = """() => {
        const body = document.querySelector('.profile-email-list-item-body');
        const leading = document.querySelector('.profile-email-leading');
        const actions = document.querySelector('.profile-email-actions');
        const removeBtn = document.querySelector('.profile-email-actions .btn-outline-danger');
        if (!body || !leading || !actions || !removeBtn) {
            return { ok: false, reason: 'missing email row controls' };
        }
        const bodyStyle = getComputedStyle(body);
        const leadingRect = leading.getBoundingClientRect();
        const actionsRect = actions.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = bodyStyle.flexDirection === 'column'
            && actionsRect.top >= leadingRect.bottom - 2;
        const fullWidthButton = Math.abs(
            removeBtn.getBoundingClientRect().width - actionsRect.width
        ) < 4;
        const promoteBtn = document.querySelector('.profile-email-actions .btn-outline-primary');
        const buttonsStacked = !promoteBtn
            || promoteBtn.getBoundingClientRect().bottom <= removeBtn.getBoundingClientRect().top + 2;
        return {
            ok: ratio <= 1.0 && stacked && fullWidthButton && buttonsStacked,
            ratio,
            stacked,
            fullWidthButton,
            flexDirection: bodyStyle.flexDirection,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_profile_organizations_header_stacks_on_mobile(
    browser,
    auth_client_owner,
):
    html = _inject_static_css(auth_client_owner.get("/user/profile").text)

    layout_check = """() => {
        const header = document.querySelector('.profile-organizations-card-header');
        const title = document.querySelector('.profile-organizations-card-title');
        const button = document.querySelector('.profile-organizations-create-btn');
        if (!header || !title || !button) {
            return { ok: false, reason: 'missing organizations header' };
        }
        const headerStyle = getComputedStyle(header);
        const titleRect = title.getBoundingClientRect();
        const buttonRect = button.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = headerStyle.flexDirection === 'column'
            && buttonRect.top >= titleRect.bottom - 2;
        const contentWidth = header.clientWidth
            - parseFloat(headerStyle.paddingLeft)
            - parseFloat(headerStyle.paddingRight);
        const fullWidthButton = Math.abs(buttonRect.width - contentWidth) < 4;
        return {
            ok: ratio <= 1.0 && stacked && fullWidthButton,
            ratio,
            stacked,
            fullWidthButton,
            flexDirection: headerStyle.flexDirection,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_profile_organization_list_items_stack_on_mobile(
    browser,
    auth_client_owner,
    test_organization,
    session,
):
    test_organization.name = "ProfileOrganizationName" * 6
    session.add(test_organization)
    session.commit()

    html = _inject_static_css(auth_client_owner.get("/user/profile").text)

    layout_check = """() => {
        const header = document.querySelector('.profile-organization-item-header');
        const name = document.querySelector('.profile-organization-item-name');
        const date = document.querySelector('.profile-organization-item-date');
        if (!header || !name || !date) {
            return { ok: false, reason: 'missing organization list item' };
        }
        const headerStyle = getComputedStyle(header);
        const nameRect = name.getBoundingClientRect();
        const dateRect = date.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = headerStyle.flexDirection === 'column'
            && dateRect.top >= nameRect.bottom - 2;
        return {
            ok: ratio <= 1.0 && stacked,
            ratio,
            stacked,
            flexDirection: headerStyle.flexDirection,
            nameRight: nameRect.right,
            viewport: window.innerWidth,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_profile_form_actions_stack_on_mobile(browser, auth_client):
    from tests.conftest import htmx_headers

    form_html = auth_client.get("/user/edit-form", headers=htmx_headers()).text
    html = _wrap_body_with_styles(f'<div id="profile-card">{form_html}</div>')

    layout_check = """() => {
        const actions = document.querySelector('.profile-form-actions');
        const save = actions ? actions.querySelector('.btn-primary') : null;
        const cancel = actions ? actions.querySelector('.profile-form-cancel-btn') : null;
        if (!actions || !save || !cancel) {
            return { ok: false, reason: 'missing profile form actions' };
        }
        const actionsStyle = getComputedStyle(actions);
        const saveRect = save.getBoundingClientRect();
        const cancelRect = cancel.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = actionsStyle.flexDirection === 'column'
            && cancelRect.top >= saveRect.bottom - 2;
        const fullWidthButtons = Math.abs(saveRect.width - actions.getBoundingClientRect().width) < 4
            && Math.abs(cancelRect.width - actions.getBoundingClientRect().width) < 4;
        return {
            ok: ratio <= 1.0 && stacked && fullWidthButtons,
            ratio,
            stacked,
            fullWidthButtons,
            flexDirection: actionsStyle.flexDirection,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_profile_page_document_width_fits_mobile_viewport(
    browser,
    auth_client_owner,
):
    html = _inject_static_css(auth_client_owner.get("/user/profile").text)

    with _viewport_page(browser, html, MOBILE_VIEWPORT) as page:
        ratio = _document_overflow_ratio(page)

    assert ratio <= 1.0, f"document scrollWidth exceeds viewport ({ratio:.3f}x)"


@pytest.mark.usefixtures("env_vars")
def test_footer_columns_centered_on_mobile(
    browser,
    auth_client_owner,
):
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const copyrightCol = document.querySelector('.site-footer-copyright');
        const quickLinksCol = document.querySelector('.site-footer-links');
        const contactCol = document.querySelector('.site-footer-contact');
        if (!copyrightCol || !quickLinksCol || !contactCol) {
            return { ok: false, reason: 'missing footer sections' };
        }
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const copyrightCentered = getComputedStyle(copyrightCol).textAlign === 'center';
        const quickLinksCentered = getComputedStyle(quickLinksCol).textAlign === 'center';
        const contactCentered = getComputedStyle(contactCol).textAlign === 'center';
        return {
            ok: ratio <= 1.0 && copyrightCentered && quickLinksCentered && contactCentered,
            ratio,
            copyrightCentered,
            quickLinksCentered,
            contactCentered,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_footer_copyright_column_left_aligned_on_desktop(
    browser,
    auth_client_owner,
):
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const copyrightCol = document.querySelector('.site-footer-copyright');
        if (!copyrightCol) {
            return { ok: false, reason: 'missing copyright section' };
        }
        return {
            ok: getComputedStyle(copyrightCol).textAlign === 'start'
                || getComputedStyle(copyrightCol).textAlign === 'left',
            textAlign: getComputedStyle(copyrightCol).textAlign,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, DESKTOP_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_navbar_brand_fits_mobile_viewport(
    browser,
    auth_client_owner,
):
    html = _inject_static_css(auth_client_owner.get("/dashboard/").text)

    layout_check = """() => {
        const brand = document.querySelector('.site-navbar-brand');
        const toggler = document.querySelector('.navbar-toggler');
        if (!brand || !toggler) {
            return { ok: false, reason: 'missing navbar brand or toggler' };
        }
        const brandRect = brand.getBoundingClientRect();
        const togglerRect = toggler.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const brandStyle = getComputedStyle(brand);
        const fitsViewport = brandRect.right <= window.innerWidth + 1
            && togglerRect.right <= window.innerWidth + 1
            && togglerRect.left >= brandRect.right - 2;
        const wraps = brandStyle.overflowWrap === 'anywhere'
            || brandStyle.wordBreak === 'break-word';
        return {
            ok: ratio <= 1.0 && fitsViewport && wraps,
            ratio,
            fitsViewport,
            wraps,
            brandRight: brandRect.right,
            togglerLeft: togglerRect.left,
            viewport: window.innerWidth,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_pending_invitation_row_stacks_on_mobile(
    browser,
    auth_client_owner,
    test_organization,
    test_invitation,
):
    assert test_organization.id is not None
    html = _inject_static_css(
        auth_client_owner.get(f"/organizations/{test_organization.id}").text
    )

    layout_check = """() => {
        const body = document.querySelector('.invitation-list-item-body');
        const leading = document.querySelector('.invitation-list-leading');
        const actions = document.querySelector('.invitation-actions-cell');
        if (!body || !leading || !actions) {
            return { ok: false, reason: 'missing invitation row controls' };
        }
        const bodyStyle = getComputedStyle(body);
        const leadingRect = leading.getBoundingClientRect();
        const actionsRect = actions.getBoundingClientRect();
        const ratio = document.documentElement.scrollWidth / window.innerWidth;
        const stacked = bodyStyle.flexDirection === 'column'
            && actionsRect.top >= leadingRect.bottom - 2;
        const fullWidthActions = Math.abs(
            actionsRect.width - body.getBoundingClientRect().width
        ) < 4;
        return {
            ok: ratio <= 1.0 && stacked && fullWidthActions,
            ratio,
            stacked,
            fullWidthActions,
            flexDirection: bodyStyle.flexDirection,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, MOBILE_VIEWPORT, layout_check)

    assert result.get("ok"), result


@pytest.mark.usefixtures("env_vars")
def test_pending_invitation_row_side_by_side_on_desktop(
    browser,
    auth_client_owner,
    test_organization,
    test_invitation,
):
    assert test_organization.id is not None
    html = _inject_static_css(
        auth_client_owner.get(f"/organizations/{test_organization.id}").text
    )

    layout_check = """() => {
        const body = document.querySelector('.invitation-list-item-body');
        const leading = document.querySelector('.invitation-list-leading');
        const actions = document.querySelector('.invitation-actions-cell');
        if (!body || !leading || !actions) {
            return { ok: false, reason: 'missing invitation row controls' };
        }
        const bodyStyle = getComputedStyle(body);
        const leadingRect = leading.getBoundingClientRect();
        const actionsRect = actions.getBoundingClientRect();
        return {
            ok: bodyStyle.flexDirection === 'row'
                && leadingRect.right <= actionsRect.left + 2,
            flexDirection: bodyStyle.flexDirection,
            leadingRight: leadingRect.right,
            actionsLeft: actionsRect.left,
        };
    }"""

    result = _evaluate_at_viewport(browser, html, DESKTOP_VIEWPORT, layout_check)

    assert result.get("ok"), result
