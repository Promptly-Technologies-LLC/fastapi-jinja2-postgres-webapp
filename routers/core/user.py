from fastapi import APIRouter, Depends, Form, UploadFile, File, Request, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlmodel import Session, select
from typing import Optional, List
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import selectinload
from utils.core.models import User, UserAvatar, DataIntegrityError, Organization, Role, Invitation
from utils.core.dependencies import get_authenticated_user, get_user_with_relations, get_session
from utils.core.images import validate_and_process_image, MAX_FILE_SIZE, MIN_DIMENSION, MAX_DIMENSION, ALLOWED_CONTENT_TYPES
from utils.core.enums import ValidPermissions
from exceptions.http_exceptions import (
    InsufficientPermissionsError,
    UserNotFoundError,
    OrganizationNotFoundError
)
from routers.core.organization import router as organization_router
from utils.core.htmx import is_htmx_request, append_toast

router = APIRouter(prefix="/user", tags=["user"])
templates = Jinja2Templates(directory="templates")


def _load_org_for_members_partial(session: Session, organization_id: int, user: User) -> tuple:
    """Re-query org with members fully loaded and compute user_permissions."""
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(
            selectinload(Organization.roles).selectinload(Role.users).selectinload(User.account),
            selectinload(Organization.roles).selectinload(Role.users).selectinload(User.roles),
            selectinload(Organization.roles).selectinload(Role.permissions),
        )
    ).first()
    user_permissions = set()
    for role in user.roles:
        if role.organization_id == organization_id:
            for permission in role.permissions:
                user_permissions.add(permission.name)
    active_invitations = Invitation.get_active_for_org(session, organization_id)
    return organization, user_permissions, active_invitations


# --- Routes ---


@router.get("/profile")
async def read_profile(
    request: Request,
    user: User = Depends(get_user_with_relations),
    show_form: Optional[str] = "true"
):
    # Add image constraints to the template context
    return templates.TemplateResponse(
        request,
        "users/profile.html", {
            "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),  # Convert bytes to MB
            "min_dimension": MIN_DIMENSION,
            "max_dimension": MAX_DIMENSION,
            "allowed_formats": list(ALLOWED_CONTENT_TYPES.keys()),
            "show_form": show_form == "true",
            "user": user
        }
    )


@router.post("/update", response_class=RedirectResponse)
async def update_profile(
    request: Request,
    name: Optional[str] = Form(None, strip_whitespace=True, title="Name", description="Updated display name"),
    avatar_file: Optional[UploadFile] = File(None),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Handle avatar update
    if avatar_file and avatar_file.filename:
        avatar_data = await avatar_file.read()
        avatar_content_type = avatar_file.content_type

        processed_image, content_type = validate_and_process_image(
            avatar_data,
            avatar_content_type
        )
        if user.avatar:
            user.avatar.avatar_data = processed_image
            user.avatar.avatar_content_type = content_type
        else:
            assert user.id is not None
            user.avatar = UserAvatar(
                user_id=user.id,
                avatar_data=processed_image,
                avatar_content_type=content_type
            )

    # Update user details
    user.name = name

    session.commit()
    session.refresh(user)

    if is_htmx_request(request):
        response = templates.TemplateResponse(
            request,
            "users/partials/profile_display.html",
            {
                "user": user,
                "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),
                "min_dimension": MIN_DIMENSION,
                "max_dimension": MAX_DIMENSION,
                "allowed_formats": list(ALLOWED_CONTENT_TYPES.keys()),
            },
        )
        response.headers["HX-Trigger"] = "profileUpdated"
        return append_toast(response, request, templates, "Profile updated successfully.")
    return RedirectResponse(url=router.url_path_for("read_profile"), status_code=303)


@router.get("/avatar")
async def get_avatar(
    user: User = Depends(get_authenticated_user)
):
    """Serve avatar image from database"""
    if not user.avatar:
        raise DataIntegrityError(
            resource="User avatar"
        )

    return Response(
        content=user.avatar.avatar_data,
        media_type=user.avatar.avatar_content_type
    )


@router.post("/role/update", response_class=RedirectResponse)
def update_user_role(
    request: Request,
    user_id: int = Form(..., title="User ID", description="ID of the user whose roles are being updated"),
    organization_id: int = Form(..., title="Organization ID", description="ID of the organization"),
    roles: Optional[List[int]] = Form(None, title="Role IDs", description="List of role IDs to assign to the user"),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> Response:
    """Update the roles of a user in an organization"""
    # Check if the current user has permission to edit user roles
    if not user.has_permission(ValidPermissions.EDIT_USER_ROLE, organization_id):
        raise InsufficientPermissionsError()

    # Find the organization
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(selectinload(Organization.roles))
    ).first()

    if not organization:
        raise OrganizationNotFoundError()

    # Find the target user
    target_user = session.exec(
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.roles))
    ).first()

    if not target_user:
        raise UserNotFoundError()

    # Get all roles for this organization
    org_roles = {role.id: role for role in organization.roles}

    # Remove all current organization roles from the user
    for role in list(target_user.roles):
        if role.organization_id == organization_id:
            target_user.roles.remove(role)

    # Add selected roles to the user
    if roles:
        for role_id in roles:
            fetched_role = org_roles.get(role_id)
            if fetched_role is not None:
                target_user.roles.append(fetched_role)

    session.commit()

    if is_htmx_request(request):
        organization, user_permissions, active_invitations = _load_org_for_members_partial(session, organization_id, user)
        response = templates.TemplateResponse(
            request,
            "organization/partials/members_table.html",
            {
                "organization": organization,
                "active_invitations": active_invitations,
                "user": user,
                "user_permissions": user_permissions,
                "ValidPermissions": ValidPermissions,
            },
        )
        response.headers["HX-Trigger"] = "modalDismiss"
        return append_toast(response, request, templates, "User role updated successfully.")
    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )


@router.post("/organization/remove", response_class=RedirectResponse)
def remove_user_from_organization(
    request: Request,
    user_id: int = Form(..., title="User ID", description="ID of the user to remove"),
    organization_id: int = Form(..., title="Organization ID", description="ID of the organization to remove the user from"),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> Response:
    """Remove a user from an organization by removing all their roles in that organization"""
    # Check if the current user has permission to remove users
    if not user.has_permission(ValidPermissions.REMOVE_USER, organization_id):
        raise InsufficientPermissionsError()

    # Find the organization
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
    ).first()

    if not organization:
        raise OrganizationNotFoundError()

    # Find the target user
    target_user = session.exec(
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.roles))
    ).first()

    if not target_user:
        raise UserNotFoundError()

    # Prevent removing oneself
    if target_user.id == user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot remove yourself from the organization"
        )

    # Remove all organization roles from the user
    for role in list(target_user.roles):
        if role.organization_id == organization_id:
            target_user.roles.remove(role)

    session.commit()

    if is_htmx_request(request):
        organization, user_permissions, active_invitations = _load_org_for_members_partial(session, organization_id, user)
        response = templates.TemplateResponse(
            request,
            "organization/partials/members_table.html",
            {
                "organization": organization,
                "active_invitations": active_invitations,
                "user": user,
                "user_permissions": user_permissions,
                "ValidPermissions": ValidPermissions,
            },
        )
        return append_toast(response, request, templates, "User removed from organization.")
    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )
