"""
Test that Bootstrap and htmx scripts are loaded in <head> with defer,
keeping them outside the hx-boost body swap zone so Bootstrap's
document-level event delegation persists across navigations.
"""

from main import app


def test_scripts_in_head_not_body(unauth_client):
    """
    Bootstrap and htmx <script> tags must be in <head> (with defer), not
    in <body>. When they live in <body>, hx-boost re-processes them during
    body swaps, which strips Bootstrap's event delegation handlers and
    breaks dropdowns/collapses until a full page refresh.
    """
    response = unauth_client.get(
        app.url_path_for("read_home"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.text

    # Split on </head> to separate head from body
    head, body = html.split("</head>", 1)

    # Bootstrap and htmx must be in <head> with defer
    assert "bootstrap.bundle.min.js" in head, (
        "Bootstrap script must be in <head>"
    )
    assert "htmx" in head, "htmx script must be in <head>"
    assert 'defer' in head, "Scripts in <head> must use defer"

    # They must NOT be in <body>
    assert "bootstrap.bundle.min.js" not in body, (
        "Bootstrap script must not be in <body> — hx-boost will "
        "re-process it during swaps, destroying event delegation"
    )
    assert "htmx.min.js" not in body, (
        "htmx script must not be in <body>"
    )

    # App JS must also be in <head> with defer
    assert "app.js" in head, "app.js must be in <head>"
