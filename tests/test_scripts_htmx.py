"""
Test that the front-end scripts are loaded in <head> with defer, keeping them
outside the hx-boost body swap zone so their document-level event delegation
(dropdowns, modals, collapse, toasts) persists across navigations.
"""

from main import app


def test_scripts_in_head_not_body(unauth_client):
    """
    htmx and our component JS (ui.js, app.js) <script> tags must be in <head>
    (with defer), not in <body>. When they live in <body>, hx-boost
    re-processes them during body swaps, which strips the document-level event
    delegation and breaks dropdowns/modals/collapses until a full page refresh.
    """
    response = unauth_client.get(
        app.url_path_for("read_home"),
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.text

    # Split on </head> to separate head from body
    head, body = html.split("</head>", 1)

    # htmx and our component scripts must be in <head> with defer
    assert "htmx" in head, "htmx script must be in <head>"
    assert "js/ui.js" in head, "ui.js must be in <head>"
    assert "js/app.js" in head, "app.js must be in <head>"
    assert "defer" in head, "Scripts in <head> must use defer"

    # They must NOT be in <body>
    assert "htmx.min.js" not in body, "htmx script must not be in <body>"
    assert "js/ui.js" not in body, (
        "ui.js must not be in <body> — hx-boost will re-process it during "
        "swaps, destroying event delegation"
    )

    # Bootstrap has been removed entirely; make sure it does not creep back in.
    assert "bootstrap" not in html.lower(), (
        "Bootstrap must not be referenced — the app ships its own CSS/JS"
    )
