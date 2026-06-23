from datetime import timedelta
from uuid import uuid4
from typing import Optional
from fastapi import APIRouter, Depends, Form, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import HTTPException
from pydantic import EmailStr
from sqlmodel import Session, select
from logging import getLogger

from utils.core.dependencies import (
    get_authenticated_user,
    get_optional_user,
    get_session,
)
from utils.core.models import User, Role, Account, Invitation, Organization, utc_now
from utils.core.enums import ValidPermissions
from utils.app.enums import AppPermissions
from utils.core.invitations import (
    send_invitation_email,
    process_invitation,
    require_active_invitation_by_token,
)
from exceptions.http_exceptions import (
    UserIsAlreadyMemberError,
    InvalidRoleForOrganizationError,
    OrganizationNotFoundError,
    InvitationEmailSendError,
    InvitationNotFoundError,
    InsufficientPermissionsError,
    RoleNotFoundError,
)
from exceptions.exceptions import EmailSendFailedError
from utils.core.htmx import is_htmx_request, append_toast
from utils.core.organizations import load_org_for_members_partial
from routers.core.account import router as account_router
from routers.core.organization import router as org_router

logger = getLogger("uvicorn.error")

templates = Jinja2Templates(directory="templates")

router = APIRouter(
    prefix="/invitations",
    tags=["invitations"],
)


def get_valid_invitation(
    token: str = Query(...), session: Session = Depends(get_session)
) -> Invitation:
    """Dependency to retrieve a valid, active invitation based on the token."""
    return require_active_invitation_by_token(session, token)


def _redirect_for_inactive_invitation(
    invitation: Optional[Invitation],
    token: str,
    session: Session,
) -> RedirectResponse:
    """Send user to register/login so invitation_token_warning banners can display."""
    if invitation:
        existing_account = session.exec(
            select(Account).where(Account.email == invitation.invitee_email)
        ).first()
        if existing_account:
            login_url = account_router.url_path_for("read_login")
            redirect_url = f"{login_url}?invitation_token={token}"
        else:
            register_url = account_router.url_path_for("read_register")
            redirect_url = (
                f"{register_url}?email={invitation.invitee_email}"
                f"&invitation_token={token}"
            )
    else:
        login_url = account_router.url_path_for("read_login")
        redirect_url = f"{login_url}?invitation_token={token}"

    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


def _members_table_response(
    request: Request,
    session: Session,
    organization_id: int,
    current_user: User,
    toast_message: str | None = None,
) -> Response:
    organization, user_permissions, pending_invitations = load_org_for_members_partial(
        session, organization_id, current_user
    )
    response = templates.TemplateResponse(
        request,
        "organization/partials/members_table.html",
        {
            "organization": organization,
            "pending_invitations": pending_invitations,
            "user": current_user,
            "user_permissions": user_permissions,
            "ValidPermissions": ValidPermissions,
            "all_permissions": list(ValidPermissions) + list(AppPermissions),
        },
    )
    if toast_message:
        response = append_toast(response, request, templates, toast_message)
    return response


@router.post("/", name="create_invitation")
async def create_invitation(
    request: Request,
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    invitee_email: EmailStr = Form(
        ..., title="Invitee email", description="Email address of the person to invite"
    ),
    role_id: int = Form(
        ..., title="Role ID", description="ID of the role to assign to the invitee"
    ),
    organization_id: int = Form(
        ...,
        title="Organization ID",
        description="ID of the organization to invite the user to",
    ),
):
    organization = session.get(Organization, organization_id)
    if not organization:
        raise OrganizationNotFoundError()

    if not current_user.has_permission(ValidPermissions.INVITE_USER, organization):
        raise InsufficientPermissionsError(
            "You don't have permission to invite users to this organization"
        )

    role = session.get(Role, role_id)
    if not role:
        raise RoleNotFoundError()
    if role.organization_id != organization_id:
        raise InvalidRoleForOrganizationError()

    existing_account = session.exec(
        select(Account).where(Account.email == invitee_email)
    ).first()
    if existing_account:
        existing_user = session.exec(
            select(User).where(User.account_id == existing_account.id)
        ).first()
        if existing_user:
            if any(
                role.organization_id == organization_id for role in existing_user.roles
            ):
                raise UserIsAlreadyMemberError()

    Invitation.invalidate_pending_for_email(session, organization_id, invitee_email)
    session.flush()

    token = str(uuid4())
    invitation = Invitation(
        organization_id=organization_id,
        role_id=role_id,
        invitee_email=invitee_email,
        token=token,
    )

    session.add(invitation)

    try:
        session.flush()
        session.refresh(invitation)
        if not invitation.organization:
            session.refresh(organization)
            invitation.organization = organization

        send_invitation_email(invitation, session)
        session.commit()
        session.refresh(invitation)

    except EmailSendFailedError as e:
        logger.error(
            f"Invitation email failed for {invitee_email} in org {organization_id}: {e}"
        )
        session.rollback()
        raise InvitationEmailSendError()
    except Exception as e:
        logger.error(
            f"Unexpected error during invitation creation/sending for {invitee_email} "
            f"in org {organization_id}: {e}",
            exc_info=True,
        )
        session.rollback()
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

    if is_htmx_request(request):
        response = _members_table_response(
            request,
            session,
            organization_id,
            current_user,
            "Invitation sent successfully.",
        )
        response.headers["HX-Trigger"] = "modalDismiss"
        return response
    return RedirectResponse(url=f"/organizations/{organization_id}", status_code=303)


@router.post("/resend", name="resend_invitation", response_class=RedirectResponse)
async def resend_invitation(
    request: Request,
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    invitation_id: int = Form(
        ..., title="Invitation ID", description="ID of the invitation to resend"
    ),
    organization_id: int = Form(
        ...,
        title="Organization ID",
        description="ID of the organization the invitation belongs to",
    ),
) -> Response:
    organization = session.get(Organization, organization_id)
    if not organization:
        raise OrganizationNotFoundError()

    if not current_user.has_permission(ValidPermissions.INVITE_USER, organization):
        raise InsufficientPermissionsError(
            "You don't have permission to resend invitations for this organization"
        )

    invitation = session.get(Invitation, invitation_id)
    if (
        not invitation
        or invitation.organization_id != organization_id
        or invitation.used
    ):
        raise InvitationNotFoundError()

    invitation.token = str(uuid4())
    invitation.expires_at = utc_now() + timedelta(days=7)

    try:
        session.flush()
        session.refresh(invitation)
        if not invitation.organization:
            session.refresh(organization)
            invitation.organization = organization

        send_invitation_email(invitation, session)
        session.commit()
        session.refresh(invitation)

    except EmailSendFailedError as e:
        logger.error(
            f"Invitation resend failed for {invitation.invitee_email} "
            f"in org {organization_id}: {e}"
        )
        session.rollback()
        raise InvitationEmailSendError()
    except Exception as e:
        logger.error(
            f"Unexpected error during invitation resend for {invitation.invitee_email} "
            f"in org {organization_id}: {e}",
            exc_info=True,
        )
        session.rollback()
        raise HTTPException(status_code=500, detail="An unexpected error occurred.")

    if is_htmx_request(request):
        return _members_table_response(
            request,
            session,
            organization_id,
            current_user,
            "Invitation resent.",
        )
    return RedirectResponse(url=f"/organizations/{organization_id}", status_code=303)


@router.post("/delete", name="delete_invitation", response_class=RedirectResponse)
async def delete_invitation(
    request: Request,
    current_user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session),
    invitation_id: int = Form(
        ..., title="Invitation ID", description="ID of the invitation to delete"
    ),
    organization_id: int = Form(
        ...,
        title="Organization ID",
        description="ID of the organization the invitation belongs to",
    ),
) -> Response:
    organization = session.get(Organization, organization_id)
    if not organization:
        raise OrganizationNotFoundError()

    if not current_user.has_permission(ValidPermissions.INVITE_USER, organization):
        raise InsufficientPermissionsError(
            "You don't have permission to cancel invitations for this organization"
        )

    invitation = session.get(Invitation, invitation_id)
    if not invitation or invitation.organization_id != organization_id:
        raise InvitationNotFoundError()

    session.delete(invitation)
    session.commit()

    if is_htmx_request(request):
        return _members_table_response(
            request,
            session,
            organization_id,
            current_user,
            "Invitation cancelled successfully.",
        )
    return RedirectResponse(url=f"/organizations/{organization_id}", status_code=303)


@router.get("/accept", name="accept_invitation")
async def accept_invitation(
    token: str = Query(...),
    current_user: Optional[User] = Depends(get_optional_user),
    session: Session = Depends(get_session),
):
    """Handles the acceptance of an invitation via the link in the email."""
    invitation = session.exec(
        select(Invitation).where(Invitation.token == token)
    ).first()

    if not invitation or not invitation.is_active():
        return _redirect_for_inactive_invitation(invitation, token, session)

    account_statement = select(Account).where(Account.email == invitation.invitee_email)
    existing_account = session.exec(account_statement).first()

    if existing_account:
        if current_user and current_user.account_id == existing_account.id:
            if not current_user.account:
                session.refresh(current_user, attribute_names=["account"])

            if not current_user.account or not current_user.account.email:
                logger.error(
                    f"User {current_user.id} is missing account details after refresh."
                )
                raise HTTPException(
                    status_code=500,
                    detail="Internal server error retrieving user account.",
                )

            logger.info(
                f"User {current_user.id} ({current_user.account.email}) accepting invitation {invitation.id} directly."
            )
            try:
                process_invitation(invitation, current_user, session)
                session.commit()
                redirect_url = org_router.url_path_for(
                    "read_organization", org_id=invitation.organization_id
                )
                return RedirectResponse(
                    url=str(redirect_url), status_code=status.HTTP_303_SEE_OTHER
                )
            except Exception as e:
                logger.error(
                    f"Error processing invitation {invitation.id} for user {current_user.id}: {e}",
                    exc_info=True,
                )
                session.rollback()
                raise HTTPException(
                    status_code=500, detail="Failed to process invitation."
                )
        else:
            logger.info(
                f"Invitation {invitation.id} requires login for {invitation.invitee_email}. Redirecting."
            )
            login_url = account_router.url_path_for("read_login")
            redirect_url_with_token = f"{login_url}?invitation_token={invitation.token}"
            return RedirectResponse(
                url=redirect_url_with_token, status_code=status.HTTP_303_SEE_OTHER
            )
    else:
        logger.info(
            f"Invitation {invitation.id} requires registration for {invitation.invitee_email}. Redirecting."
        )
        register_url = account_router.url_path_for("read_register")
        redirect_url_with_params = f"{register_url}?email={invitation.invitee_email}&invitation_token={invitation.token}"
        return RedirectResponse(
            url=redirect_url_with_params, status_code=status.HTTP_303_SEE_OTHER
        )
