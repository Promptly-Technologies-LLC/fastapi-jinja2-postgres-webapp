from logging import getLogger
from typing import Annotated
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import StringConstraints
from sqlmodel import Session, select
from utils.db import get_session, default_roles
from utils.dependencies import get_authenticated_user, get_user_with_relations
from utils.models import Organization, User, Role, utc_time
from utils.enums import ValidPermissions
from exceptions.http_exceptions import OrganizationNotFoundError, OrganizationNameTakenError, InsufficientPermissionsError

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/organizations", tags=["organizations"])
templates = Jinja2Templates(directory="templates")


# --- Routes ---


@router.get("/{org_id}")
async def read_organization(
    org_id: int,
    request: Request,
    user: User = Depends(get_user_with_relations)
):
    # Get the organization only if the user is a member of it
    org = next(
        (org for org in user.organizations if org.id == org_id),
        None
    )
    if not org:
        raise OrganizationNotFoundError()

    return templates.TemplateResponse(
        request, "users/organization.html", {"organization": org}
    )


@router.post("/create", response_class=RedirectResponse)
def create_organization(
    name: Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)] = Form(...),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
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
    initial_roles = [
        Role(name=role_name, organization_id=db_org.id)
        for role_name in default_roles
    ]
    session.add_all(initial_roles)
    session.flush()

    # Get owner role for user assignment
    owner_role = next(role for role in db_org.roles if role.name == "Owner")

    # Assign user to owner role
    user.roles.append(owner_role)

    # Commit changes
    session.commit()
    session.refresh(db_org)

    return RedirectResponse(url=f"/organizations/{db_org.id}", status_code=303)


@router.post("/update/{org_id}", name="update_organization", response_class=RedirectResponse)
def update_organization(
    org_id: int,
    name: Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)] = Form(...),
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

    return RedirectResponse(url=f"/profile", status_code=303)


@router.post("/delete/{org_id}", response_class=RedirectResponse)
def delete_organization(
    org_id: int,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check if user has permission to delete organization
    organization: Organization | None = next(
        (org for org in user.organizations if org.id == org_id), None)
    if not organization or not any(
        p.name == ValidPermissions.DELETE_ORGANIZATION
        for role in organization.roles
        for p in role.permissions
    ):
        raise InsufficientPermissionsError()

    # Delete organization
    session.delete(organization)
    session.commit()

    return RedirectResponse(url="/profile", status_code=303)
