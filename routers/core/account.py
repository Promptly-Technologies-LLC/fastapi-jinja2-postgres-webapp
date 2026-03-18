# auth.py
from logging import getLogger
from typing import Optional, Tuple
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, BackgroundTasks, Form, Request, Query
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.datastructures import URLPath
from pydantic import EmailStr
from sqlmodel import Session, select
from utils.core.models import User, DataIntegrityError, Account, AccountEmail, Invitation
from utils.core.dependencies import get_session
from utils.core.models import RefreshToken
from utils.core.auth import (
    HTML_PASSWORD_PATTERN,
    COMPILED_PASSWORD_PATTERN,
    COOKIE_SECURE,
    MAX_EMAILS_PER_ACCOUNT,
    oauth2_scheme_cookie,
    get_password_hash,
    create_access_token,
    create_tracked_refresh_token,
    revoke_all_refresh_tokens,
    validate_token,
    send_reset_email_task,
    send_email_verification,
    send_email_verified_notification,
    send_primary_email_changed_notification,
    send_email_removed_notification,
    create_recovery_token,
    generate_recovery_url,
)
from utils.core.dependencies import (
    get_authenticated_account,
    get_optional_user,
    get_account_from_reset_token,
    get_account_from_email_verification_token,
    get_account_from_recovery_token,
    get_account_from_credentials,
    require_unauthenticated_client,
    get_verified_account
)
from exceptions.http_exceptions import (
    EmailAlreadyRegisteredError,
    CannotRemovePrimaryEmailError,
    CredentialsError,
    EmailNotVerifiedError,
    MaxEmailsReachedError,
    PasswordValidationError,
    InvalidInvitationTokenError,
    InvitationEmailMismatchError,
    InvitationProcessingError
)
from routers.core.dashboard import router as dashboard_router
from routers.core.user import router as user_router
from routers.core.organization import router as org_router
from utils.core.invitations import process_invitation
from utils.core.rate_limit import (
    check_login_ip_rate_limit,
    check_login_email_rate_limit,
    check_register_ip_rate_limit,
    check_forgot_password_ip_rate_limit,
    check_forgot_password_email_rate_limit,
    login_email_limiter,
)
from utils.core.htmx import is_htmx_request, toast_response, set_flash_cookie
logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/account", tags=["account"])
templates = Jinja2Templates(directory="templates")


# --- Route-specific dependencies ---


def validate_password_strength_and_match(
    password: str = Form(..., title="Password", description="Account password"),
    confirm_password: str = Form(..., title="Confirm password", description="Re-enter password to confirm")
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
            message="Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one number, and one special character"
        )
    
    # Validate passwords match
    if password != confirm_password:
        raise PasswordValidationError(
            field="confirm_password",
            message="The passwords you entered do not match"
        )
    
    return password


# --- Routes ---


@router.get("/logout", response_class=RedirectResponse)
def logout(
    tokens: tuple[Optional[str], Optional[str]] = Depends(oauth2_scheme_cookie),
    session: Session = Depends(get_session),
):
    """
    Log out a user by revoking their refresh token and clearing cookies.
    """
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    _, refresh_token_value = tokens
    if refresh_token_value:
        decoded = validate_token(refresh_token_value, token_type="refresh")
        if decoded and decoded.get("jti"):
            db_token = session.exec(
                select(RefreshToken).where(RefreshToken.jti == decoded["jti"])
            ).first()
            if db_token:
                db_token.revoked = True
                session.commit()

    return response


@router.get("/login")
async def read_login(
    request: Request,
    _: None = Depends(require_unauthenticated_client),
    invitation_token: Optional[str] = Query(None)
):
    """
    Render login page or redirect to dashboard if already logged in.
    """
    return templates.TemplateResponse(
        request,
        "account/login.html",
        {
            "user": None,
            "invitation_token": invitation_token
        }
    )


@router.get("/register")
async def read_register(
    request: Request,
    _: None = Depends(require_unauthenticated_client),
    email: Optional[EmailStr] = Query(None),
    invitation_token: Optional[str] = Query(None)
):
    """
    Render registration page or redirect to dashboard if already logged in.
    """
    return templates.TemplateResponse(
        request,
        "account/register.html",
        {
            "user": None,
            "password_pattern": HTML_PASSWORD_PATTERN,
            "email": email,
            "invitation_token": invitation_token
        }
    )


@router.get("/forgot_password")
async def read_forgot_password(
    request: Request,
    _: None = Depends(require_unauthenticated_client),
    show_form: Optional[str] = "true",
):
    """
    Render forgot password page or redirect to dashboard if already logged in.
    """
    return templates.TemplateResponse(
        request,
        "account/forgot_password.html",
        {"user": None, "show_form": show_form == "true"}
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
        request,
        "account/reset_password.html",
        {"user": user, "email": email, "token": token, "password_pattern": HTML_PASSWORD_PATTERN}
    )


@router.post("/delete", response_class=RedirectResponse)
async def delete_account(
    account: Account = Depends(get_verified_account),
    session: Session = Depends(get_session)
):
    """
    Delete a user account after verifying credentials.
    """
    # Delete the account and associated user
    # Note: The user will be deleted automatically by cascade relationship
    session.delete(account)
    session.commit()

    # Log out the user
    return RedirectResponse(url=router.url_path_for("logout"), status_code=303)


@router.post("/register", response_class=RedirectResponse)
async def register(
    request: Request,
    _ip_check: None = Depends(check_register_ip_rate_limit),
    name: str = Form(..., min_length=1, strip_whitespace=True, title="Name", description="Your full name"),
    email: EmailStr = Form(..., title="Email", description="Email address for the new account"),
    session: Session = Depends(get_session),
    _: None = Depends(validate_password_strength_and_match),
    password: str = Form(..., title="Password", description="Account password"),
    invitation_token: Optional[str] = Form(None, title="Invitation token", description="Optional invitation token to join an organization")
) -> Response:
    """
    Register a new user account, optionally processing an invitation.
    """
    # Check if the email is already registered
    existing_account: Optional[Account] = session.exec(select(Account).where(
        Account.email == email)).one_or_none()

    if existing_account:
        raise EmailAlreadyRegisteredError()

    # Hash the password
    hashed_password = get_password_hash(password)

    # Create the account and user instances (don't commit yet)
    account = Account(email=email, hashed_password=hashed_password)
    session.add(account)
    session.flush() # Flush here to get account.id before creating User

    # Ensure account has an ID after flush
    if not account.id:
        logger.error(f"Account ID not generated after flush for email {email}. Aborting registration.")
        session.rollback() # Rollback the account add
        raise DataIntegrityError(resource="Account ID generation")

    new_user = User(name=name, account_id=account.id) # Use account.id
    session.add(new_user)

    # Create the primary AccountEmail entry
    from datetime import datetime, UTC
    account_email = AccountEmail(
        account_id=account.id,
        email=email,
        is_primary=True,
        verified=True,
        verified_at=datetime.now(UTC),
    )
    session.add(account_email)

    # Default redirect target
    redirect_url = dashboard_router.url_path_for("read_dashboard")

    # Process invitation if token is provided (BEFORE final commit)
    if invitation_token:
        logger.info(f"Registration attempt with invitation token: {invitation_token} for email {email}")
        # Fetch the invitation
        statement = select(Invitation).where(Invitation.token == invitation_token)
        invitation = session.exec(statement).first()

        if not invitation or not invitation.is_active():
            logger.warning(f"Invalid or inactive invitation token provided during registration: {invitation_token}")
            # Consider raising a more generic error to avoid exposing token validity
            raise InvalidInvitationTokenError()

        # Verify email matches
        if email != invitation.invitee_email:
            logger.warning(
                f"Invitation email mismatch for token {invitation_token} during registration. "
                f"Account: {email}, Invitation: {invitation.invitee_email}"
            )
            # Consider raising a more generic error to avoid confirming email existence
            raise InvitationEmailMismatchError()

        # Process the invitation (adds changes to the session)
        try:
            logger.info(f"Processing invitation {invitation.id} for new user {new_user.name} ({email}) during registration.")
            process_invitation(invitation, new_user, session)
            # Set redirect to the organization page
            redirect_url = org_router.url_path_for("read_organization", org_id=invitation.organization_id)
            logger.info(f"Redirecting new user {new_user.name} to organization {invitation.organization_id} after accepting invitation {invitation.id}.")
        except Exception as e:
             logger.error(
                 f"Error processing invitation {invitation.id} for new user {new_user.name} ({email}) during registration: {e}",
                 exc_info=True
             )
             session.rollback()
             raise InvitationProcessingError()

    else:
        logger.info(f"Standard registration for email {email}. Redirecting to dashboard.")

    # Commit all changes (Account, User, potentially Invitation)
    try:
        session.commit()
    except Exception as e:
        logger.error(f"Error committing transaction during registration for {email}: {e}", exc_info=True)
        session.rollback()
        # Use DataIntegrityError for commit failure
        raise DataIntegrityError(resource="Account/User registration")

    # Refresh the account to ensure all relationships (like user) are loaded after commit
    session.refresh(account)
    # We might need the user object refreshed too if process_invitation modified it directly
    # session.refresh(new_user) # Let's assume process_invitation only modifies the invitation object for now

    # Create access token using the committed account's email
    access_token = create_access_token(data={"sub": account.email, "fresh": True})
    refresh_token = create_tracked_refresh_token(account.id, account.email, session)
    session.commit()

    # Set cookie — use HX-Redirect for HTMX, 303 for regular form submissions
    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = str(redirect_url)
    else:
        response = RedirectResponse(url=str(redirect_url), status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict"
    )

    return response


@router.post("/login", response_class=RedirectResponse)
async def login(
    request: Request,
    _ip_check: None = Depends(check_login_ip_rate_limit),
    _email_check: EmailStr = Depends(check_login_email_rate_limit),
    account_and_session: Tuple[Account, Session] = Depends(get_account_from_credentials),
    invitation_token: Optional[str] = Form(None, title="Invitation token", description="Optional invitation token to join an organization after login")
) -> Response:
    """
    Log in a user with valid credentials and process invitation if token is provided.
    """
    account, session = account_and_session

    # Successful login: reset the per-email rate limiter so legitimate users
    # are not penalised for earlier mistyped attempts.
    login_email_limiter.reset(f"email:{account.email.lower().strip()}")

    # Default redirect target
    redirect_url = dashboard_router.url_path_for("read_dashboard")

    if invitation_token:
        logger.info(f"Login attempt with invitation token: {invitation_token} for account {account.email}")
        # Fetch the invitation
        statement = select(Invitation).where(Invitation.token == invitation_token)
        invitation = session.exec(statement).first()

        if not invitation or not invitation.is_active():
            logger.warning(f"Invalid or inactive invitation token provided during login: {invitation_token}")
            raise InvalidInvitationTokenError()

        # Verify email matches (check primary and any verified secondary emails)
        account_emails = session.exec(
            select(AccountEmail.email).where(
                AccountEmail.account_id == account.id,
                AccountEmail.verified == True,  # noqa: E712
            )
        ).all()
        if invitation.invitee_email not in account_emails:
            logger.warning(
                f"Invitation email mismatch for token {invitation_token}. "
                f"Account: {account.email}, Invitation: {invitation.invitee_email}"
            )
            raise InvitationEmailMismatchError()

        # Ensure user relationship is loaded for process_invitation
        if not account.user:
            logger.debug(f"Refreshing user relationship for account {account.id}")
            session.refresh(account, attribute_names=["user"])
            if not account.user:
                 # This should not happen if the account has a valid user relationship
                 logger.error(f"Failed to load user for account {account.id} during invitation processing.")
                 raise DataIntegrityError(resource="User relation")

        # Process the invitation
        try:
            if account.user and account.user.id:
                logger.info(f"Processing invitation {invitation.id} for user {account.user.id} during login.")
                process_invitation(invitation, account.user, session)
                session.commit()
                # Set redirect to the organization page
                redirect_url = org_router.url_path_for("read_organization", org_id=invitation.organization_id)
                logger.info(f"Redirecting user {account.user.id} to organization {invitation.organization_id} after accepting invitation {invitation.id}.")
            else:
                logger.error("User has no ID during invitation processing.")
                raise DataIntegrityError(resource="User ID")
        except Exception as e:
            logger.error(
                f"Error processing invitation during login: {e}",
                exc_info=True
            )
            session.rollback()
            # Raise the specific invitation processing error
            raise InvitationProcessingError()

    else:
        logger.info(f"Standard login for account {account.email}. Redirecting to dashboard.")

    # Create access token
    assert account.id is not None
    access_token = create_access_token(
        data={"sub": account.email, "fresh": True}
    )
    refresh_token = create_tracked_refresh_token(account.id, account.email, session)
    session.commit()

    # Set cookie — use HX-Redirect for HTMX, 303 for regular form submissions
    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = str(redirect_url)
    else:
        response = RedirectResponse(url=str(redirect_url), status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
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
        return RedirectResponse(url=router.url_path_for("read_login"), status_code=303)

    decoded_token = validate_token(refresh_token, token_type="refresh")
    if not decoded_token:
        response = RedirectResponse(url=router.url_path_for("read_login"), status_code=303)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

    # Validate JTI server-side
    jti = decoded_token.get("jti")
    if not jti:
        response = RedirectResponse(url=router.url_path_for("read_login"), status_code=303)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

    user_email = decoded_token.get("sub")
    account = session.exec(select(Account).where(
        Account.email == user_email)).one_or_none()
    if not account:
        return RedirectResponse(url=router.url_path_for("read_login"), status_code=303)

    db_token = session.exec(
        select(RefreshToken).where(RefreshToken.jti == jti)
    ).first()

    if not db_token or db_token.account_id != account.id:
        return RedirectResponse(url=router.url_path_for("read_login"), status_code=303)

    assert account.id is not None
    if db_token.revoked:
        # Token reuse detected — revoke all tokens for this account
        logger.warning(
            f"Refresh token reuse detected for account {account.id} on /refresh endpoint. "
            "Revoking all refresh tokens."
        )
        revoke_all_refresh_tokens(account.id, session)
        session.commit()
        response = RedirectResponse(url=router.url_path_for("read_login"), status_code=303)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

    # Revoke current token and issue new ones
    db_token.revoked = True
    new_access_token = create_access_token(
        data={"sub": account.email, "fresh": False}
    )
    new_refresh_token = create_tracked_refresh_token(account.id, account.email, session)
    session.commit()

    response = RedirectResponse(url=dashboard_router.url_path_for("read_dashboard"), status_code=303)
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )

    return response


@router.post("/forgot_password")
async def forgot_password(
    background_tasks: BackgroundTasks,
    request: Request,
    _ip_check: None = Depends(check_forgot_password_ip_rate_limit),
    email: EmailStr = Depends(check_forgot_password_email_rate_limit),
    session: Session = Depends(get_session)
):
    """
    Send a password reset email to the user.
    """
    # TODO: Make this a dependency?
    account = session.exec(select(Account).where(
        Account.email == email)).one_or_none()

    if account:
        background_tasks.add_task(send_reset_email_task, email)

    # Get the referer header, default to /forgot_password if not present
    referer = request.headers.get("referer", "/forgot_password")

    # Extract the path from the full URL
    redirect_path = urlparse(referer).path

    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = f"{redirect_path}?show_form=false"
    else:
        response = RedirectResponse(url=f"{redirect_path}?show_form=false", status_code=303)
    set_flash_cookie(response, "If an account exists with this email, a password reset link will be sent.")
    return response


@router.post("/reset_password")
async def reset_password(
    request: Request,
    email: EmailStr = Form(..., title="Email", description="Account email address"),
    token: str = Form(..., title="Reset token", description="Password reset token from email"),
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

    assert authorized_account.id is not None
    # Update password and mark token as used
    authorized_account.hashed_password = get_password_hash(new_password)

    reset_token.used = True
    session.commit()
    session.refresh(authorized_account)

    # Auto-login: issue new auth cookies so the user doesn't have to re-enter credentials
    access_token = create_access_token(data={"sub": authorized_account.email, "fresh": True})
    refresh_token = create_tracked_refresh_token(authorized_account.id, authorized_account.email, session)
    session.commit()

    redirect_url = str(dashboard_router.url_path_for("read_dashboard"))
    message = "Password reset successfully."

    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = redirect_url
    else:
        response = RedirectResponse(url=redirect_url, status_code=303)

    response.set_cookie(
        key="access_token", value=access_token,
        httponly=True, secure=COOKIE_SECURE, samesite="strict",
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=COOKIE_SECURE, samesite="strict",
    )
    set_flash_cookie(response, message)
    return response


@router.get("/recover")
async def recover_account(
    token: str = Query(...),
    session: Session = Depends(get_session),
):
    """
    Recover an account using a recovery token sent via email.
    Restores the victim's email as primary, revokes all sessions,
    and redirects to password reset.
    """
    account, recovery_token = get_account_from_recovery_token(token, session)

    if not account or not recovery_token:
        raise CredentialsError(message="Invalid or expired recovery token")

    assert account.id is not None
    # Mark recovery token as used
    recovery_token.used = True

    # Delete ALL existing AccountEmail rows (purge attacker's emails)
    # Flush deletes before inserting the restored email to avoid unique constraint
    # violations — SQLAlchemy's autoflush processes INSERTs before DELETEs.
    existing_emails = session.exec(
        select(AccountEmail).where(AccountEmail.account_id == account.id)
    ).all()
    for email_row in existing_emails:
        session.delete(email_row)
    session.flush()

    # Restore the victim's email as primary
    from datetime import datetime as dt, UTC as utc_tz
    restored_email = AccountEmail(
        account_id=account.id,
        email=recovery_token.email,
        is_primary=True,
        verified=True,
        verified_at=dt.now(utc_tz),
    )
    session.add(restored_email)

    # Update Account.email
    account.email = recovery_token.email

    # Revoke all refresh tokens
    revoke_all_refresh_tokens(account.id, session)

    # Create a password reset token
    from utils.core.models import PasswordResetToken
    reset_token = PasswordResetToken(account_id=account.id)
    session.add(reset_token)

    session.commit()
    session.refresh(reset_token)

    # Redirect to password reset page
    from utils.core.auth import generate_password_reset_url
    reset_url = generate_password_reset_url(recovery_token.email, reset_token.token)
    response = RedirectResponse(url=reset_url, status_code=303)
    set_flash_cookie(response, "Account recovered. Please set a new password.")
    return response


# --- Multi-email management routes ---


@router.post("/emails/add")
async def add_email(
    request: Request,
    new_email: EmailStr = Form(..., title="New email", description="New email address to add"),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session),
):
    """
    Request to add a new email address to the account.
    Sends a verification link to the new email address.
    """
    # Check email not already registered on any account
    existing = session.exec(
        select(AccountEmail).where(AccountEmail.email == new_email)
    ).first()
    if existing:
        raise EmailAlreadyRegisteredError()

    # Check account hasn't reached the limit
    email_count = len(session.exec(
        select(AccountEmail).where(AccountEmail.account_id == account.id)
    ).all())
    if email_count >= MAX_EMAILS_PER_ACCOUNT:
        raise MaxEmailsReachedError()

    assert account.id is not None
    # Send verification email (suppresses if unexpired token exists)
    sent = send_email_verification(account.id, new_email, session)

    message = "Verification email sent. Check your inbox." if sent else "A verification email was already sent. Please check your inbox."

    if is_htmx_request(request):
        return toast_response(request, templates, message, level="success")
    profile_path: URLPath = user_router.url_path_for("read_profile")
    response = RedirectResponse(url=str(profile_path), status_code=303)
    set_flash_cookie(response, message)
    return response


@router.get("/emails/verify")
async def verify_email(
    token: str,
    session: Session = Depends(get_session),
):
    """
    Verify a new email address using the token from the verification link.

    Always redirects to the login page because verification links are clicked
    from an email client (cross-site navigation), so samesite=strict auth
    cookies are never sent — even when the user has an active session.
    """
    account, verification_token = get_account_from_email_verification_token(token, session)

    if not account or not verification_token:
        raise CredentialsError(message="Invalid or expired verification token")

    assert account.id is not None

    # Race condition guard: check email not already taken
    existing = session.exec(
        select(AccountEmail).where(AccountEmail.email == verification_token.new_email)
    ).first()
    if existing:
        raise EmailAlreadyRegisteredError()

    # Create the AccountEmail row
    from datetime import datetime as dt, UTC as utc_tz
    account_email = AccountEmail(
        account_id=account.id,
        email=verification_token.new_email,
        is_primary=False,
        verified=True,
        verified_at=dt.now(utc_tz),
    )
    session.add(account_email)

    # Mark token as used
    verification_token.used = True
    session.commit()

    # Send notification to primary email
    send_email_verified_notification(account.email, verification_token.new_email)

    login_path: URLPath = router.url_path_for("read_login")
    response = RedirectResponse(url=str(login_path), status_code=303)
    set_flash_cookie(response, "Email address verified and added to your account.")
    return response


@router.post("/emails/promote")
async def promote_email(
    request: Request,
    email_id: int = Form(..., title="Email ID", description="ID of the email to promote"),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session),
):
    """
    Promote a secondary email address to primary.
    """
    assert account.id is not None
    # Look up the AccountEmail
    target_email = session.exec(
        select(AccountEmail).where(
            AccountEmail.id == email_id,
            AccountEmail.account_id == account.id,
        )
    ).first()

    if not target_email:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Email address not found")

    # If already primary, no-op
    if target_email.is_primary:
        profile_path: URLPath = user_router.url_path_for("read_profile")
        response = RedirectResponse(url=str(profile_path), status_code=303)
        return response

    # Must be verified
    if not target_email.verified:
        raise EmailNotVerifiedError()

    # Find the current primary
    current_primary = session.exec(
        select(AccountEmail).where(
            AccountEmail.account_id == account.id,
            AccountEmail.is_primary == True,  # noqa: E712
        )
    ).first()

    old_primary_email = account.email

    # Swap primary flags
    if current_primary:
        current_primary.is_primary = False
    target_email.is_primary = True

    # Update Account.email
    account.email = target_email.email

    # Revoke all refresh tokens
    revoke_all_refresh_tokens(account.id, session)
    session.commit()

    # Issue new tokens with the new primary email
    access_token = create_access_token(data={"sub": account.email, "fresh": True})
    refresh_token = create_tracked_refresh_token(account.id, account.email, session)
    session.commit()

    # Create recovery token and send notification to the old primary
    recovery_token_str = create_recovery_token(account.id, old_primary_email, session)
    session.commit()
    recovery_url = generate_recovery_url(recovery_token_str)
    send_primary_email_changed_notification(old_primary_email, target_email.email, recovery_url)

    profile_path = user_router.url_path_for("read_profile")
    if is_htmx_request(request):
        response = Response(status_code=200)
        response.headers["HX-Redirect"] = str(profile_path)
    else:
        response = RedirectResponse(url=str(profile_path), status_code=303)
    set_flash_cookie(response, "Primary email address updated.")
    response.set_cookie(
        key="access_token", value=access_token,
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
    return response


@router.post("/emails/remove")
async def remove_email(
    request: Request,
    email_id: int = Form(..., title="Email ID", description="ID of the email to remove"),
    account: Account = Depends(get_authenticated_account),
    session: Session = Depends(get_session),
):
    """
    Remove a non-primary email address from the account.
    """
    assert account.id is not None
    target_email = session.exec(
        select(AccountEmail).where(
            AccountEmail.id == email_id,
            AccountEmail.account_id == account.id,
        )
    ).first()

    if not target_email:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Email address not found")

    if target_email.is_primary:
        raise CannotRemovePrimaryEmailError()

    removed_address = target_email.email
    session.delete(target_email)
    session.commit()

    # Create recovery token and send notification to the removed address
    recovery_token_str = create_recovery_token(account.id, removed_address, session)
    session.commit()
    recovery_url = generate_recovery_url(recovery_token_str)
    send_email_removed_notification(removed_address, recovery_url)

    if is_htmx_request(request):
        return toast_response(request, templates, "Email address removed.", level="success")
    profile_path: URLPath = user_router.url_path_for("read_profile")
    response = RedirectResponse(url=str(profile_path), status_code=303)
    set_flash_cookie(response, "Email address removed.")
    return response
