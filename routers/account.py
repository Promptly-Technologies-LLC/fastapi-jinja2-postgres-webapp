# auth.py
from logging import getLogger
from typing import Optional, Tuple
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, BackgroundTasks, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr
from sqlmodel import Session, select
from utils.models import User, DataIntegrityError, Account
from utils.db import get_session
from utils.auth import (
    HTML_PASSWORD_PATTERN,
    COMPILED_PASSWORD_PATTERN,
    oauth2_scheme_cookie,
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    validate_token,
    send_reset_email,
    send_email_update_confirmation
)
from utils.dependencies import (
    get_authenticated_account,
    get_optional_user,
    get_account_from_reset_token,
    get_account_from_email_update_token,
    get_account_from_credentials
)
from exceptions.http_exceptions import (
    EmailAlreadyRegisteredError,
    CredentialsError,
    PasswordValidationError
)

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/account", tags=["account"])
templates = Jinja2Templates(directory="templates")


# --- Route-specific dependencies ---


def validate_password_strength_and_match(
    password: str = Form(...),
    confirm_password: str = Form(...)
) -> str:
    """
    Validates password strength and confirms passwords match.
    
    Args:
        password: Password from form
        confirm_password: Confirmation password from form
        
    Raises:
        PasswordValidationError: If password is weak or passwords don't match
    
    Returns:
        str: The validated password
    """
    # Validate password strength
    if not COMPILED_PASSWORD_PATTERN.match(password):
        raise PasswordValidationError(
            field="password",
            message="Password does not satisfy the security policy"
        )
    
    # Validate passwords match
    if password != confirm_password:
        raise PasswordValidationError(
            field="confirm_password",
            message="The passwords you entered do not match"
        )
    
    return password


# --- Routes ---


@router.post("/delete", response_class=RedirectResponse)
async def delete_account(
    email: EmailStr = Form(...),
    password: str = Form(...),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session)
):
    """
    Delete a user account after verifying credentials.
    """
    # Verify the provided email matches the authenticated user
    if email != account.email:
        raise CredentialsError(message="Email does not match authenticated account")

    # Verify password
    if not verify_password(password, account.hashed_password):
        raise PasswordValidationError(
            field="password",
            message="Password is incorrect"
        )

    # Delete the account and associated user
    # Note: The user will be deleted automatically by cascade relationship
    session.delete(account)
    session.commit()

    # Log out the user
    return RedirectResponse(url="/account/logout", status_code=303)


@router.get("/login")
async def read_login(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    email_updated: Optional[str] = "false"
):
    """
    Render login page or redirect to dashboard if already logged in.
    """
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        "authentication/login.html",
        {"request": request, "user": user, "email_updated": email_updated}
    )


@router.get("/register")
async def read_register(
    request: Request,
    user: Optional[User] = Depends(get_optional_user)
):
    """
    Render registration page or redirect to dashboard if already logged in.
    """
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)

    return templates.TemplateResponse(
        "authentication/register.html",
        {"request": request, "user": user, "password_pattern": HTML_PASSWORD_PATTERN}
    )


@router.get("/forgot_password")
async def read_forgot_password(
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    show_form: Optional[str] = "true",
):
    """
    Render forgot password page or redirect to dashboard if already logged in.
    """
    if user:
        return RedirectResponse(url="/dashboard", status_code=302)

    return templates.TemplateResponse(
        "authentication/forgot_password.html",
        {"request": request, "user": user, "show_form": show_form == "true"}
    )


@router.get("/reset_password")
async def read_reset_password(
    request: Request,
    email: str,
    token: str,
    user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session)
):
    """
    Render reset password page after validating token.
    """
    authorized_account, _ = get_account_from_reset_token(email, token, session)

    # Raise informative error to let user know the token is invalid and may have expired
    if not authorized_account:
        raise CredentialsError(message="Invalid or expired token")

    return templates.TemplateResponse(
        "authentication/reset_password.html",
        {"request": request, "user": user, "email": email, "token": token, "password_pattern": HTML_PASSWORD_PATTERN}
    )


@router.post("/register", response_class=RedirectResponse)
async def register(
    name: str = Form(...),
    email: EmailStr = Form(...),
    session: Session = Depends(get_session),
    _: None = Depends(validate_password_strength_and_match),
    password: str = Form(...)
) -> RedirectResponse:
    """
    Register a new user account.
    """
    # Check if the email is already registered
    account: Optional[Account] = session.exec(select(Account).where(
        Account.email == email)).one_or_none()

    if account:
        raise EmailAlreadyRegisteredError()

    # Hash the password
    hashed_password = get_password_hash(password)

    # Create the account
    account = Account(email=email, hashed_password=hashed_password)
    session.add(account)
    session.flush()  # Flush to get the account ID
    
    # Create the user
    account.user = User(name=name)
    session.add(account)
    session.commit()
    session.refresh(account)

    # Create access token
    access_token = create_access_token(data={"sub": email})
    refresh_token = create_refresh_token(data={"sub": email})
    
    # Set cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict"
    )

    return response


@router.post("/login", response_class=RedirectResponse)
async def login(
    account_and_session: Tuple[Account, Session] = Depends(get_account_from_credentials)
) -> RedirectResponse:
    """
    Log in a user with valid credentials.
    """
    account, session = account_and_session

    # Create access token
    access_token = create_access_token(
        data={"sub": account.email, "fresh": True}
    )
    refresh_token = create_refresh_token(data={"sub": account.email})

    # Set cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    return response


# Updated refresh_token endpoint
@router.post("/refresh", response_class=RedirectResponse)
async def refresh_token(
    tokens: tuple[Optional[str], Optional[str]] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """
    Refresh the access token using a valid refresh token.
    """
    _, refresh_token = tokens
    if not refresh_token:
        return RedirectResponse(url="/login", status_code=303)

    decoded_token = validate_token(refresh_token, token_type="refresh")
    if not decoded_token:
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

    user_email = decoded_token.get("sub")
    account = session.exec(select(Account).where(
        Account.email == user_email)).one_or_none()
    if not account:
        return RedirectResponse(url="/login", status_code=303)

    new_access_token = create_access_token(
        data={"sub": account.email, "fresh": False}
    )
    new_refresh_token = create_refresh_token(data={"sub": account.email})

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
    )

    return response


@router.post("/forgot_password")
async def forgot_password(
    background_tasks: BackgroundTasks,
    request: Request,
    email: EmailStr = Form(...),
    session: Session = Depends(get_session)
):
    """
    Send a password reset email to the user.
    """
    # TODO: Make this a dependency?
    account = session.exec(select(Account).where(
        Account.email == email)).one_or_none()

    if account:
        background_tasks.add_task(send_reset_email, email, session)

    # Get the referer header, default to /forgot_password if not present
    referer = request.headers.get("referer", "/forgot_password")

    # Extract the path from the full URL
    redirect_path = urlparse(referer).path

    # Add the query parameter to the redirect path
    return RedirectResponse(url=f"{redirect_path}?show_form=false", status_code=303)


@router.post("/reset_password")
async def reset_password(
    email: EmailStr = Form(...),
    token: str = Form(...),
    new_password: str = Depends(validate_password_strength_and_match),
    session: Session = Depends(get_session)
):
    """
    Reset a user's password using a valid token.
    """
    
    # Get account from reset token
    authorized_account, reset_token = get_account_from_reset_token(
        email, token, session
    )

    if not authorized_account or not reset_token:
        raise CredentialsError("Invalid or expired password reset token; please request a new one")

    # Update password and mark token as used
    authorized_account.hashed_password = get_password_hash(new_password)

    reset_token.used = True
    session.commit()
    session.refresh(authorized_account)

    return RedirectResponse(url="/login", status_code=303)


@router.get("/logout", response_class=RedirectResponse)
def logout():
    """
    Log out a user by clearing their cookies.
    """
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


@router.post("/update_email")
async def request_email_update(
    email: EmailStr = Form(...),
    new_email: EmailStr = Form(...),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session)
):
    """
    Request to update a user's email address.
    """
    # Verify the provided email matches the authenticated user
    if email != account.email:
        raise CredentialsError(message="Email does not match authenticated user")

    if email == new_email:
        raise CredentialsError(message="New email is the same as the current email")

    # Check if the new email is already registered
    existing_user = session.exec(
        select(Account.id).where(Account.email == new_email)
    ).first()

    if existing_user:
        raise EmailAlreadyRegisteredError()

    if not account.id:
        raise DataIntegrityError(resource="Account id")

    # Send confirmation email
    send_email_update_confirmation(
        current_email=email,
        new_email=new_email,
        account_id=account.id,
        session=session
    )

    return RedirectResponse(
        url="/profile?email_update_requested=true",
        status_code=303
    )


@router.get("/confirm_email_update")
async def confirm_email_update(
    account_id: int,
    token: str,
    new_email: str,
    session: Session = Depends(get_session)
):
    """
    Confirm an email update using a valid token.
    """
    # TODO: Just eager load the update token with the account
    account, update_token = get_account_from_email_update_token(
        account_id, token, session
    )

    if not account or not update_token:
        raise CredentialsError("Invalid or expired email update token; please request a new one")
        
    account.email = new_email
    update_token.used = True
    session.commit()

    # Create new tokens with the updated email
    access_token = create_access_token(data={"sub": new_email, "fresh": True})
    refresh_token = create_refresh_token(data={"sub": new_email})

    # Set cookies before redirecting
    response = RedirectResponse(
        url="/profile?email_updated=true",
        status_code=303
    )

    # Add secure cookie attributes
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax"
    )
    return response
