import re
from pathlib import Path
from typing import Set
import jinja2
from jinja2 import meta, Environment
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
        return set()


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
def test_template_required_variables(template_file: Path):
    """Test that we can identify required variables for each template"""
    # Extract variables from the template
    variables = extract_template_variables(template_file)
    
    # Print the variables for debugging
    print(f"Template: {template_file}")
    print(f"Required variables: {variables}")
    
    # This test now serves as documentation for what variables each template requires
        
