from pathlib import Path
import pytest


def test_no_syntax_errors(template_syntax_errors):
    """Test that all templates have valid Jinja2 syntax."""
    assert not template_syntax_errors, template_syntax_errors


def test_no_hardcoded_routes(hardcoded_routes):
    """Test that templates don't contain hardcoded routes."""
    assert not hardcoded_routes, hardcoded_routes


def test_no_missing_context_variables(missing_context_variables):
    """Test that routes pass all required variables to their templates."""
    assert not missing_context_variables, missing_context_variables


def test_valid_endpoints(validate_endpoints):
    """Test that url_for() calls in templates reference valid FastAPI endpoints."""
    from main import app

    errors = validate_endpoints(app)
    assert not errors, errors


# ---------------------------------------------------------------------------
# HTMX-specific template assertions (Phase 1-5)
# ---------------------------------------------------------------------------


def test_base_template_includes_htmx():
    content = Path("templates/base.html").read_text()
    assert "htmx.org" in content, "base.html must load the HTMX library"
    assert (
        'src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.8/dist/htmx.min.js"' in content
    )


def test_base_template_includes_toast_container():
    content = Path("templates/base.html").read_text()
    assert 'id="toast-container"' in content


def test_base_template_has_extra_head_block():
    content = Path("templates/base.html").read_text()
    assert "extra_head" in content


def test_base_template_has_extra_scripts_block():
    content = Path("templates/base.html").read_text()
    assert "extra_scripts" in content


def test_base_template_includes_viewport_meta():
    content = Path("templates/base.html").read_text()
    assert 'name="viewport"' in content
    assert "width=device-width" in content


def test_extras_css_contains_page_overflow_containment():
    content = Path("static/css/extras.css").read_text()
    assert "overflow-x: hidden" in content
    assert "min-width: 0" in content
    assert "html {" in content
    assert "body > header" in content
    assert "main {" in content


def test_inject_static_css_inlines_project_stylesheets():
    from tests.browser.test_mobile_layout_overflow import _inject_static_css

    html = (
        '<link href="/static/css/styles.css" rel="stylesheet">'
        '<link href="/static/css/extras.css" rel="stylesheet">'
    )
    merged = _inject_static_css(html)
    assert "<style>" in merged
    assert "overflow-x: hidden" in merged
    assert "organization-page-header-title" in merged
    assert 'href="/static/css/extras.css"' not in merged


def test_organization_page_header_actions_stack_with_gap_on_mobile():
    content = Path("templates/organization/organization.html").read_text()
    assert "organization-page-header" in content
    assert "organization-page-header-title" in content
    assert "organization-page-header-actions" in content
    assert "flex-wrap" in content
    assert "flex-column flex-md-row gap-2" in content
    assert "me-md-2" in content


def test_extras_css_organization_page_header_wraps_long_names():
    content = Path("static/css/extras.css").read_text()
    assert ".organization-page-header-title" in content
    assert "overflow-wrap: anywhere" in content


def test_dashboard_org_selector_structure():
    content = Path("templates/dashboard/index.html").read_text()
    assert "dashboard-org-selector" in content
    assert "dashboard-org-selector-control" in content
    assert "dashboard-org-selector-name" in content
    assert "organizations | length > 1" in content
    assert "select_organization" in content
    assert 'id="orgSelect"' in content


def test_dashboard_resource_list_structure():
    content = Path("templates/dashboard/index.html").read_text()
    assert "dashboard-resource-list" in content
    assert "dashboard-resource-item-header" in content
    assert "dashboard-resource-item-title" in content
    assert "dashboard-resource-item-description" in content


def test_extras_css_stacks_dashboard_org_selector_on_mobile():
    content = Path("static/css/extras.css").read_text()
    assert ".dashboard-org-selector" in content
    mobile_block = content.split("@media (max-width: 767.98px)", 1)[1]
    assert ".dashboard-org-selector" in mobile_block
    assert "flex-direction: column" in mobile_block
    assert ".dashboard-resource-item-header" in mobile_block


def test_profile_email_list_structure():
    content = Path("templates/users/profile.html").read_text()
    assert "profile-email-list-item-body" in content
    assert "profile-email-leading" in content
    assert "profile-email-actions" in content
    assert "profile-add-email-form" in content


def test_profile_organizations_macro_structure():
    content = Path("templates/users/macros/organizations.html").read_text()
    assert "profile-organizations-card-header" in content
    assert "profile-organizations-card-title" in content
    assert "profile-organization-item-header" in content
    assert "flex-wrap" in content


def test_profile_form_actions_structure():
    content = Path("templates/users/partials/profile_form.html").read_text()
    assert "profile-form-actions" in content
    assert "profile-form-cancel-btn" in content


def test_extras_css_stacks_profile_sections_on_mobile():
    content = Path("static/css/extras.css").read_text()
    assert ".profile-email-list-item-body" in content
    assert ".profile-organizations-card-header" in content
    assert ".profile-form-actions" in content
    mobile_block = content.split("@media (max-width: 767.98px)", 1)[1]
    assert ".profile-email-list-item-body" in mobile_block
    assert ".profile-organizations-card-header" in mobile_block
    assert ".profile-form-actions" in mobile_block


def test_footer_copyright_column_centered_on_mobile():
    content = Path("templates/base/partials/footer.html").read_text()
    assert "text-center text-md-start" in content


def test_site_navbar_brand_structure():
    content = Path("templates/base/partials/header.html").read_text()
    assert "site-navbar-brand" in content
    assert 'class="navbar-brand site-navbar-brand"' in content


def test_extras_css_wraps_navbar_brand_below_lg():
    content = Path("static/css/extras.css").read_text()
    assert ".site-navbar-brand" in content
    assert "overflow-wrap: anywhere" in content
    navbar_block = content.split("@media (max-width: 991.98px)", 1)[1]
    assert ".site-navbar-brand" in navbar_block


def test_toast_partial_exists():
    assert Path("templates/base/partials/toast.html").is_file()


@pytest.mark.parametrize(
    "partial",
    [
        "organization/partials/roles_table.html",
        "organization/partials/role_row.html",
        "organization/partials/members_table.html",
        "organization/partials/member_row.html",
        "organization/partials/invitations_list.html",
        "users/partials/profile_display.html",
        "users/partials/profile_form.html",
    ],
)
def test_organization_partial_exists(partial):
    path = Path("templates") / partial
    assert path.is_file(), f"Missing partial: {partial}"


def test_roles_table_has_stable_id():
    content = Path("templates/organization/modals/roles_card.html").read_text()
    assert 'id="roles-table-body"' in content


def test_members_table_has_stable_id():
    content = Path("templates/organization/modals/members_card.html").read_text()
    assert 'id="members-table-body"' in content


def test_invitations_list_has_stable_id():
    content = Path("templates/organization/modals/members_card.html").read_text()
    assert 'id="invitations-list"' in content


def test_create_role_form_has_hx_post():
    content = Path("templates/organization/modals/roles_card.html").read_text()
    assert "hx-post" in content


def test_invite_member_form_has_hx_post():
    content = Path("templates/organization/modals/members_card.html").read_text()
    assert "hx-post" in content


def test_pending_invitations_include_cancel_confirm():
    content = Path("templates/organization/partials/invitations_list.html").read_text()
    assert "url_for('delete_invitation')" in content
    assert "url_for('resend_invitation')" in content
    assert "hx-confirm" in content
    assert "invitation-list-item-body" in content
    assert "invitation-list-leading" in content


def test_extras_css_stacks_pending_invitations_on_mobile():
    content = Path("static/css/extras.css").read_text()
    assert ".invitation-list-item-body" in content
    mobile_block = content.split("@media (max-width: 767.98px)", 1)[1]
    assert ".invitation-list-item-body" in mobile_block
    assert "flex-direction: column" in mobile_block
    assert "margin-left: 0" in mobile_block


def test_remove_member_forms_include_confirm():
    for path in (
        "templates/organization/modals/members_card.html",
        "templates/organization/partials/members_table.html",
        "templates/organization/partials/member_row.html",
    ):
        content = Path(path).read_text()
        assert "url_for('remove_user_from_organization')" in content
        assert "hx-confirm" in content


def test_edit_organization_form_has_hx_post():
    content = Path(
        "templates/organization/modals/edit_organization_modal.html"
    ).read_text()
    assert "hx-post" in content


def test_delete_organization_form_has_hx_post():
    content = Path(
        "templates/organization/modals/delete_organization_modal.html"
    ).read_text()
    assert "hx-post" in content


def test_nav_has_hx_boost():
    content = Path("templates/base/partials/header.html").read_text()
    assert 'hx-boost="true"' in content


class TestMobileNavConsolidation:
    """Tests for consolidated mobile navigation (issue #80).

    On mobile, profile dropdown items should appear as regular nav links
    in the hamburger menu, and the dropdown should be hidden.
    """

    def setup_method(self):
        self.content = Path("templates/base/partials/header.html").read_text()

    def test_mobile_profile_link_exists(self):
        """Mobile-only Profile link should exist with d-lg-none visibility."""
        assert "d-lg-none" in self.content
        # There should be a mobile-only nav item linking to profile
        assert "mobile-nav-profile" in self.content

    def test_mobile_logout_link_exists(self):
        """Mobile-only Logout link should exist with d-lg-none visibility."""
        assert "mobile-nav-logout" in self.content

    def test_desktop_dropdown_hidden_on_mobile(self):
        """The profile dropdown should be hidden on mobile (d-none d-lg-flex)."""
        # The dropdown container should have classes to hide on mobile
        assert "d-lg-flex" in self.content
        # Verify the dropdown is inside a container hidden on mobile
        assert "d-none d-lg-flex" in self.content

    def test_mobile_nav_items_inside_collapsible(self):
        """Mobile nav items should be inside the navbarContent collapsible."""
        # Find the collapsible section and verify mobile nav items are inside it
        collapse_start = self.content.index('id="navbarContent"')
        collapse_section = self.content[collapse_start:]
        assert "mobile-nav-profile" in collapse_section
        assert "mobile-nav-logout" in collapse_section
