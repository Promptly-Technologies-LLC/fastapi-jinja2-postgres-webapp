from logging import getLogger
from typing import Annotated
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from sqlalchemy.orm import selectinload
from utils.db import get_session, create_default_roles
from utils.dependencies import get_authenticated_user, get_user_with_relations
from utils.models import Organization, User, Role, Account, utc_time
from utils.enums import ValidPermissions
from exceptions.http_exceptions import (
    OrganizationNotFoundError, OrganizationNameTakenError, 
    InsufficientPermissionsError, OrganizationSetupError,
    UserNotFoundError, UserAlreadyMemberError, DataIntegrityError
)
from pydantic import EmailStr

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/organizations", tags=["organizations"])
templates = Jinja2Templates(directory="templates")


# --- Routes ---


@router.get("/{org_id}")
async def read_organization(
    org_id: int,
    request: Request,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
):
    # Get the organization only if the user is a member of it
    org = next(
        (org for org in user.organizations if org.id == org_id),
        None
    )
    if not org:
        raise OrganizationNotFoundError()
    
    # Calculate the user's permissions for this organization
    user_permissions = set()
    for role in user.roles:
        if role.organization_id == org_id:
            for permission in role.permissions:
                user_permissions.add(permission.name)
    
    # Load the organization with fully loaded roles and users
    organization = session.exec(
        select(Organization)
        .where(Organization.id == org_id)
        .options(
            selectinload(Organization.roles).selectinload(Role.users).selectinload(User.account),
            selectinload(Organization.roles).selectinload(Role.users).selectinload(User.roles),
            selectinload(Organization.roles).selectinload(Role.permissions)
        )
    ).first()
    
    # Pass all required context to the template
    return templates.TemplateResponse(
        request, 
        "organization/organization.html", 
        {
            "organization": organization, 
            "user": user,
            "user_permissions": user_permissions,
            "ValidPermissions": ValidPermissions
        }
    )


@router.post("/create", response_class=RedirectResponse)
def create_organization(
    name: Annotated[str, Form(
        min_length=1,
        strip_whitespace=True,
        pattern=r"\S+",
        description="Organization name cannot be empty or contain only whitespace",
        title="Organization name"
    )],
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    logger.debug(f"Received organization name: '{name}' (length: {len(name)})")
    
    # Check if organization already exists
    db_org = session.exec(select(Organization).where(
        Organization.name == name)).first()
    if db_org:
        raise OrganizationNameTakenError()

    # Create organization first
    db_org = Organization(name=name)
    session.add(db_org)
    # This gets us the org ID without committing
    session.flush()

    # Create default roles with organization_id
    if db_org.id is None:
        logger.error("Failed to obtain organization ID after flush.")
        raise OrganizationSetupError()

    # Use the utility function to create default roles and assign permissions
    # This also handles committing the roles and permissions
    try:
        create_default_roles(session, db_org.id, check_first=False)
    except Exception as e:
        logger.exception(f"Failed to create default roles for org ID {db_org.id}")
        # Rollback might be needed if create_default_roles doesn't handle it
        session.rollback()
        raise OrganizationSetupError("Failed during role creation") from e

    # Refresh the org object to load the roles relationship
    session.refresh(db_org)

    # Get owner role for user assignment (roles should now exist)
    owner_role = next((role for role in db_org.roles if role.name == "Owner"), None)

    if owner_role is None:
        logger.error(f"'Owner' role not found for newly created org ID {db_org.id} after create_default_roles call.")
        # Rollback might be needed
        session.rollback()
        raise OrganizationSetupError("Owner role missing after creation")

    # Assign user to owner role
    user.roles.append(owner_role)

    # Commit the user role link
    try:
        session.commit()
        logger.info(f"Successfully created organization '{db_org.name}' (ID: {db_org.id}) and assigned owner (User ID: {user.id}).")
    except Exception as e:
        logger.exception(f"Failed to commit user-owner role link for org ID {db_org.id} and user ID {user.id}")
        session.rollback()
        raise OrganizationSetupError("Failed to assign owner role") from e

    session.refresh(db_org) # Refresh again to be safe before redirect

    return RedirectResponse(
        url=router.url_path_for("read_organization", org_id=db_org.id),
        status_code=303
    )


@router.post("/update/{org_id}", response_class=RedirectResponse)
def update_organization(
    org_id: int,
    name: Annotated[str, Form(
        min_length=1,
        strip_whitespace=True,
        pattern=r"\S+",
        description="Organization name cannot be empty or contain only whitespace",
        title="Organization name"
    )],
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # This will raise appropriate exceptions if org doesn't exist or user lacks access
    organization: Organization | None = next(
        (org_item for org_item in user.organizations if org_item.id == org_id), None)

    # Check if user has permission to edit organization
    if not organization or not user.has_permission(ValidPermissions.EDIT_ORGANIZATION, organization):
        raise InsufficientPermissionsError()

    # Check if new name already exists for another organization
    existing_org = session.exec(
        select(Organization)
        .where(Organization.name == name)
        .where(Organization.id != org_id)
    ).first()
    if existing_org:
        raise OrganizationNameTakenError()

    # Update organization name
    organization.name = name
    organization.updated_at = utc_time()
    session.add(organization)
    session.commit()

    return RedirectResponse(url=router.url_path_for("read_organization", org_id=org_id), status_code=303)


@router.post("/delete/{org_id}", response_class=RedirectResponse)
def delete_organization(
    org_id: int,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Find the organization the user belongs to
    organization: Organization | None = next(
        (org for org in user.organizations if org.id == org_id), None)

    # Check if the user is a member and has permission to delete the organization
    if not organization or not user.has_permission(ValidPermissions.DELETE_ORGANIZATION, organization):
        logger.warning(f"User {user.id} attempted to delete organization {org_id} without permission.")
        raise InsufficientPermissionsError()

    # Delete organization
    logger.info(f"User {user.id} deleting organization {org_id} ('{organization.name}').")
    session.delete(organization)
    session.commit()

    return RedirectResponse(url="/user/profile", status_code=303)


@router.post("/invite/{org_id}", response_class=RedirectResponse)
def invite_member(
    org_id: int,
    email: Annotated[EmailStr, Form(
        description="Email of the user to invite",
        title="Email"
    )],
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check if the user has permission to invite members
    if not user.has_permission(ValidPermissions.INVITE_USER, org_id):
        raise InsufficientPermissionsError()
    
    # Find the organization with all needed relationships
    organization = session.exec(
        select(Organization)
        .where(Organization.id == org_id)
        .options(
            selectinload(Organization.roles),
            selectinload(Organization.roles).selectinload(Role.users)
        )
    ).first()
    
    if not organization:
        raise OrganizationNotFoundError()
    
    # Find the account and associated user by email
    account = session.exec(
        select(Account)
        .where(Account.email == email)
        .options(
            selectinload(Account.user)
        )
    ).first()
    
    if not account or not account.user:
        raise UserNotFoundError()
    
    invited_user = account.user
    
    # Check if user is already a member of this organization
    is_already_member = False
    for role in organization.roles:
        if invited_user.id in [u.id for u in role.users]:
            is_already_member = True
            break
    
    if is_already_member:
        raise UserAlreadyMemberError()
    
    # Find the default "Member" role for this organization
    member_role = next(
        (role for role in organization.roles if role.name == "Member"),
        None
    )
    
    if not member_role:
        raise DataIntegrityError(resource="Organization roles")
    
    # Add the invited user to the Member role
    try:
        member_role.users.append(invited_user)
        session.commit()
    except Exception as e:
        session.rollback()
        raise
    
    # Return to the organization page
    return RedirectResponse(
        url=router.url_path_for("read_organization", org_id=org_id),
        status_code=303
    )
