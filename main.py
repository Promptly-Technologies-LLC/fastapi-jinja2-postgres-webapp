import logging
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError, HTTPException, StarletteHTTPException
from sqlmodel import Session
from routers import authentication, organization, role, user
from utils.auth import (
    HTML_PASSWORD_PATTERN,
    get_user_with_relations,
    get_optional_user,
    NeedsNewTokens,
    get_user_from_reset_token,
    PasswordValidationError,
    AuthenticationError
)
from utils.models import User
from utils.db import get_session, set_up_db
from utils.images import MAX_FILE_SIZE, MIN_DIMENSION, MAX_DIMENSION, ALLOWED_CONTENT_TYPES

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Optional startup logic
    set_up_db()
    yield
    # Optional shutdown logic


app: FastAPI = FastAPI(lifespan=lifespan)

# Mount static files (e.g., CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")


# --- Exception Handling Middlewares ---


# Handle AuthenticationError by redirecting to login page
@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    return RedirectResponse(
        url="/login",
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
async def password_validation_exception_handler(request: Request, exc: PasswordValidationError):
    return templates.TemplateResponse(
        request,
        "errors/validation_error.html",
        {
            "status_code": 422,
            "errors": {"error": exc.detail}
        },
        status_code=422,
    )


# Handle RequestValidationError by rendering the validation_error page
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = {}
    for error in exc.errors():
        # Handle different error locations more carefully
        location = error["loc"]

        # Skip type errors for the whole body
        if len(location) == 1 and location[0] == "body":
            continue

        # For form fields, the location might be just (field_name,)
        # For JSON body, it might be (body, field_name)
        field_name = location[-1]  # Take the last item in the location tuple
        errors[field_name] = error["msg"]

    return templates.TemplateResponse(
        request,
        "errors/validation_error.html",
        {
            "status_code": 422,
            "errors": errors
        },
        status_code=422,
    )


# Handle StarletteHTTPException (including 404, 405, etc.) by rendering the error page
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {"status_code": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )


# Add handler for uncaught exceptions (500 Internal Server Error)
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    # Log the error for debugging
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return templates.TemplateResponse(
        request,
        "errors/error.html",
        {
            "status_code": 500,
            "detail": "Internal Server Error"
        },
        status_code=500,
    )


# --- Unauthenticated Routes ---


# Define a dependency for common parameters
async def common_unauthenticated_parameters(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    error_message: Optional[str] = None,
) -> dict:
    return {"request": request, "user": user, "error_message": error_message}


@app.get("/")
async def read_home(
    params: dict = Depends(common_unauthenticated_parameters)
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(params["request"], "index.html", params)


@app.get("/login")
async def read_login(
    params: dict = Depends(common_unauthenticated_parameters),
    email_updated: Optional[str] = "false"
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)
    params["email_updated"] = email_updated
    return templates.TemplateResponse(params["request"], "authentication/login.html", params)


@app.get("/register")
async def read_register(
    params: dict = Depends(common_unauthenticated_parameters)
):
    if params["user"]:
        return RedirectResponse(url="/dashboard", status_code=302)

    params["password_pattern"] = HTML_PASSWORD_PATTERN
    return templates.TemplateResponse(params["request"], "authentication/register.html", params)


@app.get("/forgot_password")
async def read_forgot_password(
    params: dict = Depends(common_unauthenticated_parameters),
    show_form: Optional[str] = "true",
):
    params["show_form"] = show_form == "true"

    return templates.TemplateResponse(params["request"], "authentication/forgot_password.html", params)


@app.get("/about")
async def read_about(params: dict = Depends(common_unauthenticated_parameters)):
    return templates.TemplateResponse(params["request"], "about.html", params)


@app.get("/privacy_policy")
async def read_privacy_policy(params: dict = Depends(common_unauthenticated_parameters)):
    return templates.TemplateResponse(params["request"], "privacy_policy.html", params)


@app.get("/terms_of_service")
async def read_terms_of_service(params: dict = Depends(common_unauthenticated_parameters)):
    return templates.TemplateResponse(params["request"], "terms_of_service.html", params)


@app.get("/auth/reset_password")
async def read_reset_password(
    email: str,
    token: str,
    params: dict = Depends(common_unauthenticated_parameters),
    session: Session = Depends(get_session)
):
    authorized_user, _ = get_user_from_reset_token(email, token, session)

    # Raise informative error to let user know the token is invalid and may have expired
    if not authorized_user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    params["email"] = email
    params["token"] = token
    params["password_pattern"] = HTML_PASSWORD_PATTERN

    return templates.TemplateResponse(params["request"], "authentication/reset_password.html", params)


# --- Authenticated Routes ---


# Define a dependency for common parameters
async def common_authenticated_parameters(
    request: Request,
    user: User = Depends(get_user_with_relations),
    error_message: Optional[str] = None
) -> dict:
    return {"request": request, "user": user, "error_message": error_message}


# Redirect to home if user is not authenticated
@app.get("/dashboard")
async def read_dashboard(
    params: dict = Depends(common_authenticated_parameters)
):
    return templates.TemplateResponse(params["request"], "dashboard/index.html", params)


@app.get("/profile")
async def read_profile(
    params: dict = Depends(common_authenticated_parameters),
    email_update_requested: Optional[str] = "false",
    email_updated: Optional[str] = "false"
):
    # Add image constraints to the template context
    params.update({
        "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),  # Convert bytes to MB
        "min_dimension": MIN_DIMENSION,
        "max_dimension": MAX_DIMENSION,
        "allowed_formats": list(ALLOWED_CONTENT_TYPES.keys()),
        "email_update_requested": email_update_requested,
        "email_updated": email_updated
    })
    return templates.TemplateResponse(params["request"], "users/profile.html", params)


@app.get("/organizations/{org_id}")
async def read_organization(
    org_id: int,
    params: dict = Depends(common_authenticated_parameters)
):
    # Get the organization only if the user is a member of it
    org = next(
        (org for org in params["user"].organizations if org.id == org_id),
        None
    )
    if not org:
        raise organization.OrganizationNotFoundError()

    # Eagerly load roles and users
    org.roles
    org.users
    params["organization"] = org

    return templates.TemplateResponse(params["request"], "users/organization.html", params)


# --- Include Routers ---


app.include_router(authentication.router)
app.include_router(organization.router)
app.include_router(role.router)
app.include_router(user.router)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
