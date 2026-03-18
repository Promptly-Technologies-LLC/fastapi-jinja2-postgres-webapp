import json
from urllib.parse import quote, unquote
from starlette.requests import Request
from starlette.responses import Response
from fastapi.templating import Jinja2Templates
from starlette.templating import _TemplateResponse as TemplateResponse
from utils.core.auth import COOKIE_SECURE


def is_htmx_request(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


def htmx_redirect(response: Response, url: str) -> None:
    """Set HX-Redirect header so HTMX performs a client-side navigation."""
    response.headers["HX-Redirect"] = url


def toast_response(
    request: Request,
    templates: Jinja2Templates,
    message: str,
    level: str = "success",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> TemplateResponse:
    """Return a toast partial TemplateResponse (OOB swap into #toast-container)."""
    response = templates.TemplateResponse(
        request,
        "base/partials/toast.html",
        {"message": message, "level": level},
        status_code=status_code,
    )
    if headers:
        response.headers.update(headers)
    return response


def _render_toast_html(
    request: Request,
    templates: Jinja2Templates,
    message: str,
    level: str = "success",
) -> str:
    """Render the toast partial to an HTML string."""
    resp = templates.TemplateResponse(
        request,
        "base/partials/toast.html",
        {"message": message, "level": level},
    )
    return bytes(resp.body).decode()


def append_toast(
    response: TemplateResponse,
    request: Request,
    templates: Jinja2Templates,
    message: str,
    level: str = "success",
) -> TemplateResponse:
    """Append an OOB toast partial to an existing TemplateResponse body."""
    toast_html = _render_toast_html(request, templates, message, level)
    original_body = bytes(response.body).decode()
    response.body = (original_body + toast_html).encode()
    # Update content-length header
    response.headers["content-length"] = str(len(response.body))
    return response


# --- Flash cookie helpers for non-HTMX PRG redirects ---

FLASH_COOKIE_NAME = "flash_message"


def set_flash_cookie(response: Response, message: str, level: str = "success") -> None:
    """Set a flash message cookie that will be consumed on the next page load.

    The JSON value is URL-encoded before being set as a cookie to avoid
    Python's http.cookies module mangling characters like commas (\\054)
    and quotes, which breaks client-side JSON.parse().
    """
    value = quote(json.dumps({"message": message, "level": level}), safe="")
    response.set_cookie(
        key=FLASH_COOKIE_NAME,
        value=value,
        httponly=False,  # JS needs to read it
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60,  # expire after 60 seconds
    )


def get_flash_cookie(request: Request) -> dict | None:
    """Read and return the flash message from the cookie, or None."""
    raw = request.cookies.get(FLASH_COOKIE_NAME)
    if not raw:
        return None
    try:
        return json.loads(unquote(raw))
    except (json.JSONDecodeError, TypeError):
        return None
