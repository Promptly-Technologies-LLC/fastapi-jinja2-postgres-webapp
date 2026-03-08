import re
from pathlib import Path
from typing import Set
import jinja2
from jinja2 import meta, Environment
from jinja2 import nodes
import pytest


def get_all_template_files():
    """Recursively find all template files in the templates directory"""
    template_dir = Path("templates")
    return list(template_dir.glob("**/*.html"))


def test_no_hardcoded_routes():
    """Test that templates don't contain hardcoded routes"""
    template_files = get_all_template_files()
    
    # Make sure we found some templates
    assert len(template_files) > 0, "No template files found"
    
    # Patterns to look for hardcoded routes
    # We're looking for attributes that might contain routes but don't use url_for
    patterns = [
        r'action\s*=\s*["\'](?!{{.*?url_for.*?}})[^"\']*?/',  # action attribute with relative path
        r'hx-get\s*=\s*["\'](?!{{.*?url_for.*?}})[^"\']*?/',  # hx-get with relative path
        r'hx-post\s*=\s*["\'](?!{{.*?url_for.*?}})[^"\']*?/',  # hx-post with relative path
        r'hx-put\s*=\s*["\'](?!{{.*?url_for.*?}})[^"\']*?/',  # hx-put with relative path
        r'hx-patch\s*=\s*["\'](?!{{.*?url_for.*?}})[^"\']*?/',  # hx-patch with relative path
        r'hx-delete\s*=\s*["\'](?!{{.*?url_for.*?}})[^"\']*?/',  # hx-delete with relative path
        r'href\s*=\s*["\'](?!{{.*?url_for.*?}}|#|https?://|mailto:|tel:)[^"\']*?/',  # href with relative path
    ]
    
    # Compile the patterns for better performance
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    
    # Check each template file
    for template_file in template_files:
        with open(template_file, 'r') as f:
            content = f.read()
            
            for i, pattern in enumerate(compiled_patterns):
                matches = pattern.findall(content)
                if matches:
                    attribute = patterns[i].split(r'\s*=')[0].replace(r'\\', '').replace(r'\s*', '')
                    assert False, f"Hardcoded route found in {template_file}: {attribute}={matches[0]}"


def extract_template_variables(template_path: Path) -> Set[str]:
    """
    Extract all undeclared variables from a Jinja2 template.
    
    Args:
        template_path: Path to the template file
        
    Returns:
        Set of variable names used in the template
    """
    with open(template_path, 'r') as f:
        template_source = f.read()
    
    env = Environment()
    try:
        ast = env.parse(template_source)
        variables = meta.find_undeclared_variables(ast)
        return variables
    except jinja2.exceptions.TemplateSyntaxError as e:
        pytest.fail(f"Syntax error in template {template_path}: {str(e)}")


@pytest.mark.parametrize("template_file", get_all_template_files())
def test_template_syntax(template_file: Path):
    """Test that templates have valid Jinja2 syntax"""
    with open(template_file, 'r') as f:
        template_source = f.read()
    
    env = Environment()
    try:
        # Just parse the template to check for syntax errors
        env.parse(template_source)
        # If we get here, the template has valid syntax
        assert True
    except jinja2.exceptions.TemplateSyntaxError as e:
        pytest.fail(f"Syntax error in template {template_file}: {str(e)}")


@pytest.mark.parametrize("template_file", get_all_template_files())
def test_extends_paths_are_valid(template_file: Path):
    """Test that {% extends ... %} paths point to valid files."""
    with open(template_file, 'r') as f:
        template_source = f.read()

    # Use a loader so Jinja2 knows the base directory for relative paths
    env = Environment(loader=jinja2.FileSystemLoader("templates"))
    try:
        ast = env.parse(template_source)
        # Find the extends node, if it exists
        extends_node = ast.find(nodes.Extends)

        if extends_node:
            # Get the path specified in {% extends "..." %}
            # The template can be different types of expressions
            if isinstance(extends_node.template, nodes.Const):
                parent_template_path = extends_node.template.value
            else:
                # For other expression types, skip this test
                return

            # Check if the resolved path exists relative to the templates dir
            full_path = Path("templates") / parent_template_path
            assert full_path.is_file(), (
                f"In {template_file}: extends path '{parent_template_path}' "
                f"does not point to a valid file ({full_path})"
            )
        # If no extends node, this test passes for this file
    except jinja2.exceptions.TemplateSyntaxError as e:
        # If syntax is invalid, this test fails, but test_template_syntax should catch it more specifically.
        # We fail here too to be explicit.
        pytest.fail(f"Syntax error in template {template_file}: {str(e)}")


@pytest.mark.parametrize("template_file", get_all_template_files())
def test_template_required_variables(template_file: Path):
    """Test that we can identify required variables for each template"""
    # Extract variables from the template
    variables = extract_template_variables(template_file)
    
    # Print the variables for debugging
    print(f"Template: {template_file}")
    print(f"Required variables: {variables}")
    
    # TODO: Add tests to ensure that each route passes the required variables to the template



# ---------------------------------------------------------------------------
# HTMX-specific template assertions (Phase 1-5)
# ---------------------------------------------------------------------------

from pathlib import Path
import pytest


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
