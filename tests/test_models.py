from datetime import timedelta, datetime, UTC
from typing import Optional
from sqlmodel import select, Session
from utils.models import (
    Permission,
    Role,
    RolePermissionLink,
    Organization,
    ValidPermissions,
    User,
    UserRoleLink,
    PasswordResetToken
)
from .conftest import SetupError


def test_permissions_persist_after_role_deletion(session: Session):
    """
    Test that permissions are not deleted when a related Role is deleted.
    Permissions links are automatically deleted due to cascade_delete=True.
    """
    # Verify all ValidPermissions exist in database
    all_permissions = session.exec(select(Permission)).all()
    assert len(all_permissions) == len(ValidPermissions)

    # Create an organization
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.commit()
    session.refresh(organization)

    # Create a role and link two specific permissions
    role = Role(name="Test Role", organization_id=organization.id)
    session.add(role)
    session.commit()
    session.refresh(role)

    # Find specific permissions to link
    delete_org_permission = next(
        p for p in all_permissions if p.name == ValidPermissions.DELETE_ORGANIZATION)
    edit_org_permission = next(
        p for p in all_permissions if p.name == ValidPermissions.EDIT_ORGANIZATION)

    role.permissions.append(delete_org_permission)
    role.permissions.append(edit_org_permission)
    session.commit()

    # Verify that RolePermissionLinks exist before deletion
    role_permissions = session.exec(select(RolePermissionLink)).all()
    assert len(role_permissions) == 2

    # Delete the role (this will cascade delete the permission links)
    session.delete(role)
    session.commit()

    # Verify that all permissions still exist
    remaining_permissions = session.exec(select(Permission)).all()
    assert len(remaining_permissions) == len(ValidPermissions)
    assert delete_org_permission in remaining_permissions
    assert edit_org_permission in remaining_permissions

    # Verify that RolePermissionLinks were cascade deleted
    remaining_role_permissions = session.exec(select(RolePermissionLink)).all()
    assert len(remaining_role_permissions) == 0


def test_user_organizations_property(session: Session, test_user: User, test_organization: Organization):
    """
    Test that User.organizations property correctly returns all organizations
    the user belongs to via their roles.
    """
    # Create a role in the test organization
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)

    # Link the user to the role
    test_user.roles.append(role)
    session.commit()

    # Refresh the user to ensure relationships are loaded
    session.refresh(test_user)

    # Test the organizations property
    assert len(test_user.organizations) == 1
    assert test_user.organizations[0].id == test_organization.id


def test_organization_users_property(session: Session, test_user: User, test_organization: Organization):
    """
    Test that Organization.users property correctly returns all users
    in the organization via their roles.
    """
    # Create a role in the test organization
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)
    session.commit()

    # Link the user to the role
    test_user.roles.append(role)
    session.commit()

    # Refresh the organization to ensure relationships are loaded
    session.refresh(test_organization)

    # Test the users property
    users_list: list[User] = test_organization.users
    assert len(users_list) == 1
    assert test_user in users_list


def test_cascade_delete_organization(session: Session, test_user: User, test_organization: Organization):
    """
    Test that deleting an organization cascades properly:
    - Deletes associated roles
    - Deletes role-user links
    - Does not delete users
    """
    # Create a role in the test organization
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)
    test_user.roles.append(role)
    session.commit()

    # Delete the organization
    session.delete(test_organization)
    session.commit()

    # Verify the role was deleted
    remaining_roles = session.exec(select(Role)).all()
    assert len(remaining_roles) == 0

    # Verify the user-role link was deleted
    remaining_links = session.exec(select(UserRoleLink)).all()
    assert len(remaining_links) == 0

    # Verify the user still exists
    remaining_user = session.exec(select(User)).first()
    assert remaining_user is not None
    assert remaining_user.id == test_user.id


def test_password_reset_token_cascade_delete(session: Session, test_user: User):
    """
    Test that password reset tokens are deleted when a user is deleted
    """
    # Create reset tokens for the user
    token1 = PasswordResetToken(user_id=test_user.id)
    token2 = PasswordResetToken(user_id=test_user.id)
    session.add(token1)
    session.add(token2)
    session.commit()

    # Verify tokens exist
    tokens = session.exec(select(PasswordResetToken)).all()
    assert len(tokens) == 2

    # Delete the user
    session.delete(test_user)
    session.commit()

    # Verify tokens were cascade deleted
    remaining_tokens = session.exec(select(PasswordResetToken)).all()
    assert len(remaining_tokens) == 0


def test_password_reset_token_is_expired(session: Session, test_user: User):
    """
    Test that password reset token expiration is properly set and checked
    """
    # Create an expired token
    expired_token = PasswordResetToken(
        user_id=test_user.id,
        expires_at=datetime.now(UTC) - timedelta(hours=1)
    )
    session.add(expired_token)

    # Create a valid token
    valid_token = PasswordResetToken(
        user_id=test_user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1)
    )
    session.add(valid_token)
    session.commit()

    # Verify expiration states
    assert expired_token.is_expired()
    assert not valid_token.is_expired()


def test_user_has_permission(session: Session, test_user: User, test_organization: Organization):
    """
    Test that User.has_permission method correctly checks if a user has a specific
    permission for a given organization.
    """
    # Create a role with specific permissions in the test organization
    role = Role(name="Test Role", organization_id=test_organization.id)
    session.add(role)
    session.commit()
    session.refresh(role)

    # Assign permissions to the role
    delete_org_permission: Optional[Permission] = session.exec(
        select(Permission).where(Permission.name ==
                                 ValidPermissions.DELETE_ORGANIZATION)
    ).first()
    edit_org_permission: Optional[Permission] = session.exec(
        select(Permission).where(Permission.name ==
                                 ValidPermissions.EDIT_ORGANIZATION)
    ).first()

    if delete_org_permission is not None and edit_org_permission is not None:
        role.permissions.append(delete_org_permission)
        role.permissions.append(edit_org_permission)
    else:
        raise SetupError(
            "Test setup failed; permission not found in database")
    session.commit()

    # Link the user to the role
    test_user.roles.append(role)
    session.commit()
    session.refresh(test_user)

    # Test the has_permission method
    assert test_user.has_permission(
        ValidPermissions.DELETE_ORGANIZATION, test_organization) is True
    assert test_user.has_permission(
        ValidPermissions.EDIT_ORGANIZATION, test_organization) is True
    assert test_user.has_permission(
        ValidPermissions.INVITE_USER, test_organization) is False
