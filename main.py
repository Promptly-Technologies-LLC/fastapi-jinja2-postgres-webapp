import logging
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError, StarletteHTTPException
from routers import about, account, dashboard, organization, privacy_policy, role, terms_of_service, user
from utils.dependencies import (
    get_optional_user
)
from exceptions.http_exceptions import (
    AuthenticationError,
    PasswordValidationError
)
from exceptions.exceptions import (
    NeedsNewTokens
)
from utils.db import set_up_db
from utils.models import User

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Optional startup logic
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
app.include_router(about.router)
app.include_router(dashboard.router)
app.include_router(organization.router)
app.include_router(privacy_policy.router)
app.include_router(role.router)
app.include_router(terms_of_service.router)
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


# --- Home Page ---


@app.get("/")
async def read_home(
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user}
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
