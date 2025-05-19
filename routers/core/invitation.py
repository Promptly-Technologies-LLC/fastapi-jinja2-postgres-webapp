from uuid import uuid4
from typing import Optional
from fastapi import APIRouter, Depends, Form, Query, status
from fastapi.responses import RedirectResponse
from fastapi.exceptions import HTTPException
from pydantic import EmailStr
from sqlmodel import Session, select
from logging import getLogger

from utils.core.dependencies import get_authenticated_user, get_optional_user, get_session
from utils.core.models import User, Role, Account, Invitation, ValidPermissions, Organization
from utils.core.invitations import send_invitation_email, process_invitation
from exceptions.http_exceptions import (
    UserIsAlreadyMemberError,
    ActiveInvitationExistsError,
    InvalidRoleForOrganizationError,
    OrganizationNotFoundError,
    InvitationEmailSendError,
    InvalidInvitationTokenError,
    InvitationEmailMismatchError,
)
from exceptions.exceptions import EmailSendFailedError
# Import the account router to generate URLs for login/register
from routers.core.account import router as account_router
from routers.core.organization import router as org_router # Already imported, check usage

# Setup logger
logger = getLogger("uvicorn.error")

router = APIRouter(
    prefix="/invitations",
    tags=["invitations"],
)


# Dependency to get a valid invitation
def get_valid_invitation(
    token: str = Query(...),
    session: Session = Depends(get_session)
) -> Invitation:
    """Dependency to retrieve a valid, active invitation based on the token."""
    statement = select(Invitation).where(Invitation.token == token)
    invitation = session.exec(statement).first()
    if not invitation or not invitation.is_active():
        raise InvalidInvitationTokenError()
    return invitation


@router.post("/", name="create_invitation")
async def create_invitation(
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    invitee_email: EmailStr = Form(...),
    role_id: int = Form(...),
    organization_id: int = Form(...),
):
    # Fetch the organization
    organization = session.get(Organization, organization_id)
    if not organization:
        raise OrganizationNotFoundError()
    
    # Check if the current user has permission to invite users to this organization
    if not current_user.has_permission(ValidPermissions.INVITE_USER, organization):
        raise HTTPException(status_code=403, detail="You don't have permission to invite users to this organization")
    
    # Verify the role exists and belongs to this organization
    role = session.get(Role, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.organization_id != organization_id:
        raise InvalidRoleForOrganizationError()
    
    # Check if invitee is already a member of the organization
    existing_account = session.exec(select(Account).where(Account.email == invitee_email)).first()
    if existing_account:
        # Check if any user with this account is already a member
        existing_user = session.exec(select(User).where(User.account_id == existing_account.id)).first()
        if existing_user:
            # Check if user has any role in this organization
            if any(role.organization_id == organization_id for role in existing_user.roles):
                raise UserIsAlreadyMemberError()
    
    # Check for active invitations with the same email
    active_invitations = Invitation.get_active_for_org(session, organization_id)
    if any(invitation.invitee_email == invitee_email for invitation in active_invitations):
        raise ActiveInvitationExistsError()
    
    # Create the invitation
    token = str(uuid4())
    invitation = Invitation(
        organization_id=organization_id,
        role_id=role_id,
        invitee_email=invitee_email,
        token=token,
    )
    
    session.add(invitation)

    try:
        # Refresh to ensure relationships are loaded *before* sending email
        session.flush() # Ensure invitation gets an ID if needed by email sender, flush changes
        session.refresh(invitation)
        # Ensure organization is loaded before passing to email function
        # (May already be loaded, but explicit refresh is safer)
        if not invitation.organization:
            session.refresh(organization) # Refresh the org object fetched earlier
            invitation.organization = organization # Assign if needed

        # Send email synchronously BEFORE committing
        send_invitation_email(invitation, session)

        # Commit *only* if email sending was successful
        session.commit()
        session.refresh(invitation) # Refresh again after commit if needed elsewhere

    except EmailSendFailedError as e:
        logger.error(f"Invitation email failed for {invitee_email} in org {organization_id}: {e}")
        session.rollback() # Rollback the invitation creation
        raise InvitationEmailSendError() # Raise HTTP 500
    except Exception as e:
        # Catch any other unexpected errors during flush/refresh/email/commit
        logger.error(
            f"Unexpected error during invitation creation/sending for {invitee_email} "
            f"in org {organization_id}: {e}",
            exc_info=True
        )
        session.rollback()
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

    # Redirect back to organization page (PRG pattern)
    return RedirectResponse(url=f"/organizations/{organization_id}", status_code=303)


@router.get("/accept", name="accept_invitation")
async def accept_invitation(
    invitation: Invitation = Depends(get_valid_invitation),
    current_user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session),
):
    """Handles the acceptance of an invitation via the link in the email."""
    # Check if an account exists for the invitee email
    account_statement = select(Account).where(Account.email == invitation.invitee_email)
    existing_account = session.exec(account_statement).first()

    if existing_account:
        # Account exists - check if user is logged in and matches the invitation
        if current_user and current_user.account_id == existing_account.id:
            # Ensure the account relationship is loaded before accessing its email
            if not current_user.account:
                session.refresh(current_user, attribute_names=["account"])
            
            # Check if refreshed account has an email (should always exist, but good practice)
            if not current_user.account or not current_user.account.email:
                logger.error(f"User {current_user.id} is missing account details after refresh.")
                raise HTTPException(status_code=500, detail="Internal server error retrieving user account.")

            # Logged in as the correct user, process the invitation directly
            logger.info(
                f"User {current_user.id} ({current_user.account.email}) accepting invitation {invitation.id} directly."
            )
            try:
                process_invitation(invitation, current_user, session)
                session.commit()
                # Redirect to the organization page
                redirect_url = org_router.url_path_for("read_organization", org_id=invitation.organization_id)
                return RedirectResponse(url=str(redirect_url), status_code=status.HTTP_303_SEE_OTHER)
            except Exception as e:
                logger.error(
                    f"Error processing invitation {invitation.id} for user {current_user.id}: {e}",
                    exc_info=True
                )
                session.rollback()
                # Re-raise or return a generic error response
                raise HTTPException(status_code=500, detail="Failed to process invitation.")
        else:
            # Account exists, but user is not logged in or is the wrong user
            # Redirect to login, passing the token
            logger.info(
                f"Invitation {invitation.id} requires login for {invitation.invitee_email}. Redirecting."
            )
            login_url = account_router.url_path_for("read_login")
            redirect_url_with_token = f"{login_url}?invitation_token={invitation.token}"
            return RedirectResponse(url=redirect_url_with_token, status_code=status.HTTP_303_SEE_OTHER)
    else:
        # Account does not exist - redirect to registration
        logger.info(
            f"Invitation {invitation.id} requires registration for {invitation.invitee_email}. Redirecting."
        )
        register_url = account_router.url_path_for("read_register")
        redirect_url_with_params = (
            f"{register_url}?email={invitation.invitee_email}&invitation_token={invitation.token}"
        )
        return RedirectResponse(url=redirect_url_with_params, status_code=status.HTTP_303_SEE_OTHER)
