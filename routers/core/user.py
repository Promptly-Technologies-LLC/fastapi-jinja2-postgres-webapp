from fastapi import APIRouter, Depends, Form, UploadFile, File, Request, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlmodel import Session, select
from typing import Optional, List
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import selectinload
from utils.core.models import User, DataIntegrityError, Organization
from utils.core.dependencies import get_authenticated_user, get_user_with_relations, get_session
from utils.core.images import validate_and_process_image, MAX_FILE_SIZE, MIN_DIMENSION, MAX_DIMENSION, ALLOWED_CONTENT_TYPES
from utils.core.enums import ValidPermissions
from exceptions.http_exceptions import (
    InsufficientPermissionsError,
    UserNotFoundError,
    OrganizationNotFoundError
)
from routers.core.organization import router as organization_router

router = APIRouter(prefix="/user", tags=["user"])
templates = Jinja2Templates(directory="templates")


# --- Routes ---


@router.get("/profile")
async def read_profile(
    request: Request,
    user: User = Depends(get_user_with_relations),
    email_update_requested: Optional[str] = "false",
    email_updated: Optional[str] = "false"
):
    # Add image constraints to the template context
    return templates.TemplateResponse(
        request,
        "users/profile.html", {
            "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),  # Convert bytes to MB
            "min_dimension": MIN_DIMENSION,
            "max_dimension": MAX_DIMENSION,
            "allowed_formats": list(ALLOWED_CONTENT_TYPES.keys()),
            "email_update_requested": email_update_requested,
            "email_updated": email_updated,
            "user": user
        }
    )


@router.post("/update", response_class=RedirectResponse)
async def update_profile(
    name: Optional[str] = Form(None),
    avatar_file: Optional[UploadFile] = File(None),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
):
    # Handle avatar update
    if avatar_file:
        avatar_data = await avatar_file.read()
        avatar_content_type = avatar_file.content_type
        
        processed_image, content_type = validate_and_process_image(
            avatar_data,
            avatar_content_type
        )
        user.avatar_data = processed_image
        user.avatar_content_type = content_type

    # Update user details
    user.name = name

    session.commit()
    session.refresh(user)
    return RedirectResponse(url=router.url_path_for("read_profile"), status_code=303)


@router.get("/avatar")
async def get_avatar(
    user: User = Depends(get_authenticated_user)
):
    """Serve avatar image from database"""
    if not user.avatar_data:
        raise DataIntegrityError(
            resource="User avatar"
        )

    return Response(
        content=user.avatar_data,
        media_type=user.avatar_content_type
    )


@router.post("/role/update", response_class=RedirectResponse)
def update_user_role(
    user_id: int = Form(...),
    organization_id: int = Form(...),
    roles: Optional[List[int]] = Form(None),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
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
    
    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )


@router.post("/organization/remove", response_class=RedirectResponse)
def remove_user_from_organization(
    user_id: int = Form(...),
    organization_id: int = Form(...),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
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
    
    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )
