from sqlmodel import Session, select
from sqlalchemy.orm import selectinload

from utils.core.models import Organization, Role, User, Invitation


def _user_permissions_for_org(user: User, organization_id: int) -> set[str]:
    user_permissions: set[str] = set()
    for role in user.roles:
        if role.organization_id == organization_id:
            for permission in role.permissions:
                user_permissions.add(permission.name)
    return user_permissions


def load_org_for_members_partial(
    session: Session, organization_id: int, user: User
) -> tuple[Organization | None, set[str], list[Invitation]]:
    """Re-query org with members fully loaded and compute user_permissions."""
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(
            selectinload(Organization.roles)
            .selectinload(Role.users)
            .selectinload(User.account),
            selectinload(Organization.roles)
            .selectinload(Role.users)
            .selectinload(User.roles),
            selectinload(Organization.roles).selectinload(Role.permissions),
        )
    ).first()
    user_permissions = _user_permissions_for_org(user, organization_id)
    active_invitations = Invitation.get_active_for_org(session, organization_id)
    return organization, user_permissions, active_invitations


def load_org_for_roles_partial(
    session: Session, organization_id: int, user: User
) -> tuple[Organization | None, set[str]]:
    """Re-query org with roles/users/permissions and compute user_permissions."""
    organization = session.exec(
        select(Organization)
        .where(Organization.id == organization_id)
        .options(
            selectinload(Organization.roles).selectinload(Role.users),
            selectinload(Organization.roles).selectinload(Role.permissions),
        )
    ).first()
    user_permissions = _user_permissions_for_org(user, organization_id)
    return organization, user_permissions
