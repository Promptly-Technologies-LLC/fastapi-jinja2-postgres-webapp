"""Utilities for frontend page-render and redirect-chain tests."""

from __future__ import annotations

from urllib.parse import urlparse

from starlette.testclient import TestClient

REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

RENDER_FAILURE_MARKERS = (
    "UndefinedError",
    "TemplateSyntaxError",
    "Internal Server Error",
    "Traceback (most recent call last)",
    "jinja2.exceptions",
)


def assert_partial_rendered(
    response,
    *,
    expected_status: int = 200,
) -> None:
    """Assert a response is an HTML fragment without template failure markers."""
    assert response.status_code == expected_status, (
        f"Expected HTTP {expected_status}, got {response.status_code}"
    )
    body = response.text
    assert "<!DOCTYPE html>" not in body, (
        "Expected an HTML partial, got a full document"
    )
    for marker in RENDER_FAILURE_MARKERS:
        assert marker not in body, f"Found render failure marker {marker!r} in body"


def assert_full_page_rendered(
    response,
    *,
    expected_status: int = 200,
) -> None:
    """Assert a response is a full HTML page without template failure markers."""
    assert response.status_code == expected_status, (
        f"Expected HTTP {expected_status}, got {response.status_code}"
    )
    body = response.text
    assert "<!DOCTYPE html>" in body or "<html" in body.lower(), (
        "Expected a full HTML document, got a partial or non-HTML response"
    )
    for marker in RENDER_FAILURE_MARKERS:
        assert marker not in body, f"Found render failure marker {marker!r} in body"


def _redirect_path(client: TestClient, location: str) -> str:
    if location.startswith(("http://", "https://")):
        parsed = urlparse(location)
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")
    if location.startswith("/"):
        return location
    base = str(client.base_url).rstrip("/")
    return f"{base}/{location.lstrip('/')}"


def follow_redirect_chain(
    client: TestClient,
    response,
    *,
    max_hops: int = 10,
):
    """Follow 3xx Location headers until a non-redirect response or hop limit."""
    current = response
    for _ in range(max_hops):
        if current.status_code not in REDIRECT_STATUS_CODES:
            return current
        location = current.headers.get("location")
        assert location, f"Redirect {current.status_code} missing Location header"
        current = client.get(_redirect_path(client, location))
    raise AssertionError(f"Exceeded maximum redirect hops ({max_hops})")


def assert_redirect_renders_full_page(
    client: TestClient,
    response,
    *,
    expected_first_status: int = 303,
) -> None:
    """Assert a redirect response chains to a renderable full HTML page."""
    assert response.status_code == expected_first_status, (
        f"Expected HTTP {expected_first_status}, got {response.status_code}"
    )
    final = follow_redirect_chain(client, response)
    assert_full_page_rendered(final)
