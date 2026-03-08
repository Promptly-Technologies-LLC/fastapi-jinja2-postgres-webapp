from starlette.requests import Request
from starlette.responses import Response


def is_htmx_request(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def htmx_redirect(response: Response, url: str) -> None:
    """Set HX-Redirect header so HTMX performs a client-side navigation."""
    response.headers["HX-Redirect"] = url
