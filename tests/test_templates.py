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
    assert 'src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.8/dist/htmx.min.js"' in content


def test_base_template_includes_toast_container():
    content = Path("templates/base.html").read_text()
    assert 'id="toast-container"' in content


def test_base_template_has_extra_head_block():
    content = Path("templates/base.html").read_text()
    assert "extra_head" in content


def test_base_template_has_extra_scripts_block():
    content = Path("templates/base.html").read_text()
    assert "extra_scripts" in content


def test_toast_partial_exists():
    assert Path("templates/base/partials/toast.html").is_file()


@pytest.mark.parametrize("partial", [
    "organization/partials/roles_table.html",
    "organization/partials/role_row.html",
    "organization/partials/members_table.html",
    "organization/partials/member_row.html",
    "organization/partials/invitations_list.html",
    "users/partials/profile_display.html",
    "users/partials/profile_form.html",
])
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


def test_edit_organization_form_has_hx_post():
    content = Path("templates/organization/modals/edit_organization_modal.html").read_text()
    assert "hx-post" in content


def test_delete_organization_form_has_hx_post():
    content = Path("templates/organization/modals/delete_organization_modal.html").read_text()
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
        assert 'd-lg-none' in self.content
        # There should be a mobile-only nav item linking to profile
        assert 'mobile-nav-profile' in self.content

    def test_mobile_logout_link_exists(self):
        """Mobile-only Logout link should exist with d-lg-none visibility."""
        assert 'mobile-nav-logout' in self.content

    def test_desktop_dropdown_hidden_on_mobile(self):
        """The profile dropdown should be hidden on mobile (d-none d-lg-flex)."""
        # The dropdown container should have classes to hide on mobile
        assert 'd-lg-flex' in self.content
        # Verify the dropdown is inside a container hidden on mobile
        assert 'd-none d-lg-flex' in self.content

    def test_mobile_nav_items_inside_collapsible(self):
        """Mobile nav items should be inside the navbarContent collapsible."""
        # Find the collapsible section and verify mobile nav items are inside it
        collapse_start = self.content.index('id="navbarContent"')
        collapse_section = self.content[collapse_start:]
        assert 'mobile-nav-profile' in collapse_section
        assert 'mobile-nav-logout' in collapse_section
