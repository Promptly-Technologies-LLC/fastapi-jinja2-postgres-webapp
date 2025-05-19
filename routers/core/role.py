# TODO: User with permission to create/edit roles can only assign permissions
# they themselves have.
from typing import List, Sequence, Optional
from logging import getLogger
from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select, col
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import IntegrityError
from utils.core.dependencies import get_authenticated_user, get_session
from utils.core.models import Role, Permission, ValidPermissions, utc_now, User, DataIntegrityError
from exceptions.http_exceptions import InsufficientPermissionsError, InvalidPermissionError, RoleAlreadyExistsError, RoleNotFoundError, RoleHasUsersError, CannotModifyDefaultRoleError
from routers.core.organization import router as organization_router

logger = getLogger("uvicorn.error")

router = APIRouter(prefix="/roles", tags=["roles"])

# --- Routes ---

@router.post("/create", response_class=RedirectResponse)
def create_role(
    name: str = Form(...),
    organization_id: int = Form(...),
    permissions: List[ValidPermissions] = Form(...),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check that the user-selected role name is unique for the organization
    if session.exec(
        select(Role).where(
            Role.name == name,
            Role.organization_id == organization_id
        )
    ).first():
        raise RoleAlreadyExistsError()

    # Check that the user is authorized to create roles in the organization
    if not user.has_permission(ValidPermissions.CREATE_ROLE, organization_id):
        raise InsufficientPermissionsError()

    # Create role
    db_role = Role(
        name=name,
        organization_id=organization_id
    )
    session.add(db_role)

    # Select Permission records corresponding to the user-selected permissions
    # and associate them with the newly created role
    db_permissions: Sequence[Permission] = session.exec(
        select(Permission).where(col(Permission.name).in_(permissions))
    ).all()
    db_role.permissions.extend(db_permissions)

    # Commit transaction
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        # This likely means the unique constraint (org_id, name) was violated,
        # potentially due to a race condition if the pre-check passed.
        raise RoleAlreadyExistsError()

    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )


@router.post("/update", response_class=RedirectResponse)
def update_role(
    id: int = Form(...),
    name: str = Form(...),
    organization_id: int = Form(...),
    permissions: List[ValidPermissions] = Form(...),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check that the user is authorized to update the role
    if not user.has_permission(ValidPermissions.EDIT_ROLE, organization_id):
        raise InsufficientPermissionsError()

    # Select db_role to update, along with its permissions, by ID
    db_role: Optional[Role] = session.exec(
        select(Role).where(Role.id == id).options(
            selectinload(Role.permissions))
    ).first()

    if not db_role:
        raise RoleNotFoundError()

    # Prevent modification of default roles
    if db_role.name in ["Owner", "Administrator", "Member"]:
        raise CannotModifyDefaultRoleError(action="update")

    # If any user-selected permissions are not valid, raise an error
    for permission in permissions:
        if permission not in ValidPermissions:
            raise InvalidPermissionError(permission)

    # Add any user-selected permissions that are not already associated with the role
    for permission in permissions:
        if permission not in [p.name for p in db_role.permissions]:
            db_permission: Optional[Permission] = session.exec(
                select(Permission).where(Permission.name == permission)
            ).first()
            if db_permission:
                db_role.permissions.append(db_permission)
            else:
                raise DataIntegrityError(resource=f"Permission: {permission}")

    # Remove any permissions that are not user-selected
    for db_permission in db_role.permissions:
        if db_permission.name not in permissions:
            db_role.permissions.remove(db_permission)

    # Check that no existing organization role has the same name but a different ID
    if session.exec(
        select(Role).where(
            Role.name == name,
            Role.organization_id == organization_id,
            Role.id != id
        )
    ).first():
        raise RoleAlreadyExistsError()

    # Update role name and updated_at timestamp
    db_role.name = name
    db_role.updated_at = utc_now()

    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        # This likely means the unique constraint (org_id, name) was violated,
        # potentially due to a race condition if the pre-check passed.
        raise RoleAlreadyExistsError()

    session.refresh(db_role)
    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )


@router.post("/delete", response_class=RedirectResponse)
def delete_role(
    id: int = Form(...),
    organization_id: int = Form(...),
    user: User = Depends(get_authenticated_user),
    session: Session = Depends(get_session)
) -> RedirectResponse:
    # Check that the user is authorized to delete the role
    if not user.has_permission(ValidPermissions.DELETE_ROLE, organization_id):
        raise InsufficientPermissionsError()

    # Select the role to delete by ID, along with its users
    db_role: Role | None = session.exec(
        select(Role).where(Role.id == id).options(
            selectinload(Role.users)
        )
    ).first()

    if not db_role:
        raise RoleNotFoundError()

    # Prevent deletion of default roles
    if db_role.name in ["Owner", "Administrator", "Member"]:
        raise CannotModifyDefaultRoleError(action="delete")

    # Check that no users have the role
    if db_role.users:
        raise RoleHasUsersError()

    # Delete the role
    session.delete(db_role)
    session.commit()

    return RedirectResponse(
        url=organization_router.url_path_for("read_organization", org_id=organization_id),
        status_code=303
    )
