import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from routers.core import (
    account,
    dashboard,
    organization,
    role,
    user,
    static_pages,
    invitation,
)
from utils.core.dependencies import (
    get_user_from_request,
    require_unauthenticated_client,
)
from utils.core.auth import refresh_token_is_persistent, set_auth_cookies
from utils.core.rate_limit import get_trusted_proxy_hosts
from utils.core.csrf import (
    CSRF_COOKIE_NAME,
    UNSAFE_HTTP_METHODS,
    csrf_enabled,
    extract_submitted_csrf_token,
    generate_csrf_token,
    set_csrf_cookie,
    validate_csrf_token,
)
from utils.core.htmx import (
    is_htmx_request,
    toast_response,
    get_flash_cookie,
    FLASH_COOKIE_NAME,
)
from exceptions.http_exceptions import (
    AlreadyAuthenticatedError,
    AuthenticationError,
    CsrfError,
    PasswordValidationError,
    CredentialsError,
    RateLimitError,
)
from exceptions.exceptions import NeedsNewTokens
from routers.app import billing as billing_router
from utils.app.credentials import billing_enabled, validate_billing_environment
from utils.app.billing import billing_nav_href
from utils.core.db import set_up_db

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_billing_environment()
    set_up_db()
    yield


# Initialize the FastAPI app
app: FastAPI = FastAPI(lifespan=lifespan)

trusted_proxy_hosts = get_trusted_proxy_hosts()
if trusted_proxy_hosts:
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=list(trusted_proxy_hosts))

# Mount static files (e.g., CSS, JS) and initialize Jinja2 templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# --- Flash cookie middleware ---
# Reads the flash cookie into request.state so templates can render it
# server-side, then clears the cookie on the response.


@app.middleware("http")
async def nav_billing_middleware(request: Request, call_next):
    request.state.billing_nav_href = None
    if billing_enabled():
        access_token = request.cookies.get("access_token")
        if access_token:
            from sqlmodel import Session, select
            from sqlalchemy.orm import selectinload

            from utils.core.db import get_engine
            from utils.core.dependencies import get_optional_user_from_access_token
            from utils.core.models import Role, User

            engine = get_engine()
            with Session(engine) as session:
                user = get_optional_user_from_access_token(access_token, session)
                if user and user.id is not None:
                    eager_user = session.exec(
                        select(User)
                        .where(User.id == user.id)
                        .options(
                            selectinload(User.roles).selectinload(Role.organization),
                            selectinload(User.roles).selectinload(Role.permissions),
                        )
                    ).first()
                    if eager_user is not None:
                        request.state.billing_nav_href = billing_nav_href(
                            request, eager_user
                        )
    return await call_next(request)


@app.middleware("http")
async def flash_cookie_middleware(request: Request, call_next):
    flash = get_flash_cookie(request)
    request.state.flash = flash
    response = await call_next(request)
    if flash:
        response.delete_cookie(FLASH_COOKIE_NAME, path="/")
    return response


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    token = request.cookies.get(CSRF_COOKIE_NAME) or generate_csrf_token()
    request.state.csrf_token = token

    if csrf_enabled() and request.method in UNSAFE_HTTP_METHODS:
        if not request.url.path.startswith("/webhooks/"):
            submitted = await extract_submitted_csrf_token(request)
            if not validate_csrf_token(request, submitted):
                return await csrf_error_handler(request, CsrfError())

    response = await call_next(request)
    if request.cookies.get(CSRF_COOKIE_NAME) != token:
        set_csrf_cookie(response, token)
    return response


# --- Include Routers ---


app.include_router(account.router)
app.include_router(dashboard.router)
app.include_router(invitation.router)
app.include_router(organization.router)
app.include_router(role.router)
app.include_router(static_pages.router)
app.include_router(user.router)
if billing_enabled():
    app.include_router(billing_router.router)
    app.include_router(billing_router.webhook_router)


# --- Exception Handling Middlewares ---


# Handle AuthenticationError by redirecting to login page
@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = str(request.url_for("read_login"))
        return response
    return RedirectResponse(
        url=app.url_path_for("read_login"), status_code=status.HTTP_303_SEE_OTHER
    )


# Handle AlreadyAuthenticatedError by redirecting to dashboard
@app.exception_handler(AlreadyAuthenticatedError)
async def already_authenticated_error_handler(
    request: Request, exc: AlreadyAuthenticatedError
):
    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = str(request.url_for("read_dashboard"))
        return response
    return RedirectResponse(
        url=app.url_path_for("read_dashboard"), status_code=status.HTTP_302_FOUND
    )


# Handle RateLimitError (429 Too Many Requests)
@app.exception_handler(RateLimitError)
async def rate_limit_error_handler(request: Request, exc: RateLimitError):
    if is_htmx_request(request):
        return toast_response(
            request,
            templates,
            exc.detail,
            level="danger",
            status_code=429,
            headers={"Retry-After": str(exc.retry_after)},
        )
    user = await get_user_from_request(request)
    response = templates.TemplateResponse(
        request,
        "errors/error.html",
        {"status_code": 429, "detail": exc.detail, "errors": None, "user": user},
        status_code=429,
    )
    response.headers["Retry-After"] = str(exc.retry_after)
    return response


@app.exception_handler(CsrfError)
async def csrf_error_handler(request: Request, exc: CsrfError):
    if is_htmx_request(request):
        return toast_response(
            request,
            templates,
            exc.detail,
            level="danger",
            status_code=403,
        )
    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {"status_code": 403, "detail": exc.detail, "errors": None, "user": user},
        status_code=403,
    )


# Handle CredentialsError (invalid email/password) with toast for HTMX
@app.exception_handler(CredentialsError)
async def credentials_exception_handler(request: Request, exc: CredentialsError):
    if is_htmx_request(request):
        return toast_response(
            request,
            templates,
            exc.detail or "Invalid email or password.",
            level="danger",
            status_code=401,
        )
    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {
            "status_code": exc.status_code,
            "detail": exc.detail,
            "errors": None,
            "user": user,
        },
        status_code=exc.status_code,
    )


# Handle NeedsNewTokens by setting new tokens and redirecting to same page
@app.exception_handler(NeedsNewTokens)
async def needs_new_tokens_handler(request: Request, exc: NeedsNewTokens):
    # Preserve query string so GET routes with query params work after token refresh
    redirect_url = str(request.url)
    response = RedirectResponse(
        url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT
    )
    set_auth_cookies(
        response,
        exc.access_token,
        exc.refresh_token,
        persistent=refresh_token_is_persistent(exc.refresh_token),
    )
    return response


# Handle PasswordValidationError by rendering the validation_error page
@app.exception_handler(PasswordValidationError)
async def password_validation_exception_handler(
    request: Request, exc: PasswordValidationError
) -> Response:
    if is_htmx_request(request):
        detail = exc.detail
        if isinstance(detail, dict):
            message = detail.get("message", str(detail))
        else:
            message = str(detail)
        return toast_response(
            request,
            templates,
            message,
            level="danger",
            status_code=422,
        )
    detail = exc.detail
    if isinstance(detail, dict):
        field = detail.get("field", "Error")
        message = detail.get("message", str(detail))
    else:
        field = "Error"
        message = str(detail)
    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {
            "status_code": 422,
            "detail": None,
            "errors": {field.replace("_", " ").title(): message},
            "user": user,
        },
        status_code=422,
    )


# Handle RequestValidationError by rendering the error page
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = {}

    # Map error types to user-friendly message templates
    error_templates = {
        "pattern_mismatch": "this field cannot be empty or contain only whitespace",
        "string_too_short": "this field is required",
        "missing": "this field is required",
        "string_pattern_mismatch": "this field cannot be empty or contain only whitespace",
        "enum": "invalid value",
    }

    for error in exc.errors():
        # Handle different error locations carefully
        location = error["loc"]

        # Skip type errors for the whole body
        if len(location) == 1 and location[0] == "body":
            continue

        # For form fields, the location might be just (field_name,)
        # For JSON body, it might be (body, field_name)
        # For array items, it might be (field_name, array_index)
        field_name = location[-2] if isinstance(location[-1], int) else location[-1]

        # Format the field name to be more user-friendly
        display_name = field_name.replace("_", " ").title()

        # Use mapped message if available, otherwise use FastAPI's message
        error_type = error.get("type", "")
        message_template = error_templates.get(error_type, error["msg"])

        # For array items, append the index to the message
        if isinstance(location[-1], int):
            message_template = f"Item {location[-1] + 1}: {message_template}"

        errors[display_name] = message_template

    if is_htmx_request(request):
        message = (
            "; ".join(f"{k}: {v}" for k, v in errors.items())
            if errors
            else "Validation error"
        )
        return toast_response(
            request,
            templates,
            message,
            level="danger",
            status_code=422,
        )

    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {"status_code": 422, "detail": None, "errors": errors, "user": user},
        status_code=422,
    )


# Handle StarletteHTTPException (including 404, 405, etc.) by rendering the error page
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if is_htmx_request(request):
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return toast_response(
            request,
            templates,
            detail,
            level="danger",
            status_code=exc.status_code,
        )
    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {
            "status_code": exc.status_code,
            "detail": exc.detail,
            "errors": None,
            "user": user,
        },
        status_code=exc.status_code,
    )


# Add handler for uncaught exceptions (500 Internal Server Error)
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Log the error for debugging
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    if is_htmx_request(request):
        return toast_response(
            request,
            templates,
            "Internal Server Error",
            level="danger",
            status_code=500,
        )

    user = await get_user_from_request(request)

    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {
            "status_code": 500,
            "detail": "Internal Server Error",
            "errors": None,
            "user": user,
        },
        status_code=500,
    )


# --- Home Page ---


@app.get("/")
async def read_home(
    request: Request, _: None = Depends(require_unauthenticated_client)
):
    return templates.TemplateResponse(request, "index.html", {"user": None})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
