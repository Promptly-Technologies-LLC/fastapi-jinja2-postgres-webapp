import logging
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from routers.core import account, dashboard, organization, role, user, static_pages, invitation
from utils.core.dependencies import (
    get_optional_user,
    get_user_from_request
)
from exceptions.http_exceptions import (
    AuthenticationError,
    PasswordValidationError
)
from exceptions.exceptions import (
    NeedsNewTokens
)
from utils.core.db import set_up_db
from utils.core.models import User

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Optional startup logic
    load_dotenv()
    set_up_db()
    yield
    # Optional shutdown logic


# Initialize the FastAPI app
app: FastAPI = FastAPI(lifespan=lifespan)

# Mount static files (e.g., CSS, JS) and initialize Jinja2 templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# --- Include Routers ---


app.include_router(account.router)
app.include_router(dashboard.router)
app.include_router(invitation.router)
app.include_router(organization.router)
app.include_router(role.router)
app.include_router(static_pages.router)
app.include_router(user.router)


# --- Exception Handling Middlewares ---


# Handle AuthenticationError by redirecting to login page
@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    return RedirectResponse(
        url=app.url_path_for("read_login"),
        status_code=status.HTTP_303_SEE_OTHER
    )


# Handle NeedsNewTokens by setting new tokens and redirecting to same page
@app.exception_handler(NeedsNewTokens)
async def needs_new_tokens_handler(request: Request, exc: NeedsNewTokens):
    response = RedirectResponse(
        url=request.url.path, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    response.set_cookie(
        key="access_token",
        value=exc.access_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    response.set_cookie(
        key="refresh_token",
        value=exc.refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return response


# Handle PasswordValidationError by rendering the validation_error page
@app.exception_handler(PasswordValidationError)
async def password_validation_exception_handler(
    request: Request,
    exc: PasswordValidationError
) -> Response:
    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/validation_error.html",
        {
            "status_code": 422,
            "errors": {"error": exc.detail},
            "user": user
        },
        status_code=422,
    )


# Handle RequestValidationError by rendering the validation_error page
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):
    errors = {}

    # Map error types to user-friendly message templates
    error_templates = {
        "pattern_mismatch": "this field cannot be empty or contain only whitespace",
        "string_too_short": "this field is required",
        "missing": "this field is required",
        "string_pattern_mismatch": "this field cannot be empty or contain only whitespace",
        "enum": "invalid value"
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

    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/validation_error.html",
        {
            "status_code": 422,
            "errors": errors,
            "user": user
        },
        status_code=422,
    )


# Handle StarletteHTTPException (including 404, 405, etc.) by rendering the error page
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    user = await get_user_from_request(request)
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {"status_code": exc.status_code, "detail": exc.detail, "user": user},
        status_code=exc.status_code,
    )


# Add handler for uncaught exceptions (500 Internal Server Error)
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Log the error for debugging
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    user = await get_user_from_request(request)

    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {
            "status_code": 500,
            "detail": "Internal Server Error",
            "user": user
        },
        status_code=500,
    )


# --- Home Page ---


@app.get("/")
async def read_home(
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    if user:
        return RedirectResponse(url=app.url_path_for("read_dashboard"), status_code=302)
    return templates.TemplateResponse(
        request,
        "index.html",
        {"user": user}
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
