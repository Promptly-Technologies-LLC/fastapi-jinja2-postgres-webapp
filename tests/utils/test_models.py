from datetime import timedelta, datetime, UTC
from typing import Optional
from sqlmodel import select, Session
from sqlalchemy.exc import IntegrityError
import pytest
from utils.core.models import (
    Account,
    AccountEmail,
    AccountRecoveryToken,
    EmailVerificationToken,
    Organization,
    Permission,
    PasswordResetToken,
    Role,
    RolePermissionLink,
    User,
    UserRoleLink,
)
from utils.core.enums import ValidPermissions
from utils.app.enums import AppPermissions
from tests.conftest import SetupError


# --- Schema placement tests ---


def test_private_models_have_private_schema():
    """Account, PasswordResetToken, and EmailVerificationToken must live in the 'private' schema."""
    assert Account.__table__.schema == "private"
    assert PasswordResetToken.__table__.schema == "private"
    assert EmailVerificationToken.__table__.schema == "private"


def test_public_models_not_in_private_schema():
    """Public models must not be placed in the 'private' schema."""
    for model in (User, Organization, Role, Permission, UserRoleLink, RolePermissionLink):
        assert model.__table__.schema != "private", (
            f"{model.__name__} should not be in the 'private' schema"
        )


def test_permissions_persist_after_role_deletion(session: Session):
    """
    Test that permissions are not deleted when a related Role is deleted.
    Permissions links are automatically deleted due to cascade_delete=True.
    """
    # Verify all ValidPermissions exist in database
    all_permissions = session.exec(select(Permission)).all()
    assert len(all_permissions) == len(ValidPermissions) + len(AppPermissions)

    # Create an organization
    organization = Organization(name="Test Organization")
    session.add(organization)
    session.commit()
    session.refresh(organization)
    
    # Ensure organization ID is not None (for type checking)
    if organization.id is None:
        pytest.fail("Organization ID is None, test setup failed.")

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
    assert len(remaining_permissions) == len(ValidPermissions) + len(AppPermissions)
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
    # Ensure organization ID is not None (for type checking)
    if test_organization.id is None:
        pytest.fail("Organization ID is None, test setup failed.")
        
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
    # Ensure organization ID is not None (for type checking)
    if test_organization.id is None:
        pytest.fail("Organization ID is None, test setup failed.")
        
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
    # Ensure organization ID is not None (for type checking)
    if test_organization.id is None:
        pytest.fail("Organization ID is None, test setup failed.")
        
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


def test_password_reset_token_cascade_delete(session: Session, test_account: Account):
    """
    Test that password reset tokens are deleted when an account is deleted
    """
    # Create reset tokens for the account
    token1 = PasswordResetToken(account_id=test_account.id)
    token2 = PasswordResetToken(account_id=test_account.id)
    session.add(token1)
    session.add(token2)
    session.commit()

    # Verify tokens exist
    tokens = session.exec(select(PasswordResetToken)).all()
    assert len(tokens) == 2

    # Delete the account
    session.delete(test_account)
    session.commit()

    # Verify tokens were cascade deleted
    remaining_tokens = session.exec(select(PasswordResetToken)).all()
    assert len(remaining_tokens) == 0


def test_password_reset_token_is_expired(session: Session, test_account: Account):
    """
    Test that password reset token expiration is properly set and checked
    """
    # Create an expired token
    expired_token = PasswordResetToken(
        account_id=test_account.id,
        expires_at=datetime.now(UTC) - timedelta(hours=1)
    )
    session.add(expired_token)

    # Create a valid token
    valid_token = PasswordResetToken(
        account_id=test_account.id,
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
    # Ensure organization ID is not None (for type checking)
    if test_organization.id is None:
        pytest.fail("Organization ID is None, test setup failed.")
        
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


def test_cascade_delete_account_deletes_user(session: Session, test_account: Account, test_user: User):
    """
    Test that deleting an account cascades to delete the associated user
    """
    # Verify the user exists
    assert session.exec(select(User).where(User.account_id == test_account.id)).first() is not None
    
    # Delete the account
    session.delete(test_account)
    session.commit()
    
    # Verify the user was cascade deleted
    assert session.exec(select(User).where(User.account_id == test_account.id)).first() is None


def test_role_name_unique_per_organization(session: Session, test_organization: Organization, second_test_organization: Organization):
    """
    Test that role names must be unique within the same organization, 
    but can be duplicated across different organizations.
    """
    role_name = "UniqueRoleTest"
    
    # Ensure organization IDs are not None (for type checking)
    if test_organization.id is None or second_test_organization.id is None:
        pytest.fail("Organization ID is None, test setup failed.")

    # Create a role in the first organization
    role1 = Role(name=role_name, organization_id=test_organization.id)
    session.add(role1)
    session.commit()
    session.refresh(role1)
    assert role1.id is not None

    # Attempt to create another role with the same name in the same organization
    role2_duplicate = Role(name=role_name, organization_id=test_organization.id)
    session.add(role2_duplicate)
    with pytest.raises(IntegrityError):
        session.commit()
    
    # Rollback the session after the expected error
    session.rollback()

    # Create a role with the same name in the second organization (should succeed)
    role3_different_org = Role(name=role_name, organization_id=second_test_organization.id)
    session.add(role3_different_org)
    session.commit()
    session.refresh(role3_different_org)
    assert role3_different_org.id is not None

    # Verify the final state
    roles_org1 = session.exec(select(Role).where(Role.organization_id == test_organization.id)).all()
    roles_org2 = session.exec(select(Role).where(Role.organization_id == second_test_organization.id)).all()

    # Org 1 should have exactly one role with the test name after the failed attempt
    count_org1_roles_with_name = sum(1 for role in roles_org1 if role.name == role_name)
    assert count_org1_roles_with_name == 1
    
    # Org 2 should only have the one role we added
    assert len(roles_org2) == 1
    assert roles_org2[0].name == role_name


# --- AccountEmail model tests ---


def test_account_email_creation(session: Session, test_account: Account):
    """Test creating an AccountEmail and verifying fields persist."""
    account_email = AccountEmail(
        account_id=test_account.id,
        email="primary@example.com",
        is_primary=True,
        verified=True,
        verified_at=datetime.now(UTC),
    )
    session.add(account_email)
    session.commit()
    session.refresh(account_email)

    assert account_email.id is not None
    assert account_email.account_id == test_account.id
    assert account_email.email == "primary@example.com"
    assert account_email.is_primary is True
    assert account_email.verified is True
    assert account_email.verified_at is not None
    assert account_email.created_at is not None


def test_account_email_unique_email_constraint(session: Session, test_account: Account):
    """Test that the same email string cannot appear on two different accounts."""
    # Create first AccountEmail
    email1 = AccountEmail(
        account_id=test_account.id,
        email="unique@example.com",
        is_primary=True,
        verified=True,
    )
    session.add(email1)
    session.commit()

    # Create a second account
    account2 = Account(email="other@example.com", hashed_password="hash")
    session.add(account2)
    session.commit()

    # Try to create an AccountEmail with the same email on a different account
    email2 = AccountEmail(
        account_id=account2.id,
        email="unique@example.com",
        is_primary=True,
        verified=True,
    )
    session.add(email2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_account_relationship_to_emails(session: Session, test_account: Account):
    """Test that account.emails returns a list of AccountEmail objects."""
    email1 = AccountEmail(
        account_id=test_account.id,
        email="first@example.com",
        is_primary=True,
        verified=True,
    )
    email2 = AccountEmail(
        account_id=test_account.id,
        email="second@example.com",
        is_primary=False,
        verified=True,
    )
    session.add(email1)
    session.add(email2)
    session.commit()
    session.refresh(test_account)

    assert len(test_account.emails) == 2
    emails = {e.email for e in test_account.emails}
    assert emails == {"first@example.com", "second@example.com"}


def test_account_email_cascade_delete(session: Session, test_account: Account):
    """Test that AccountEmail rows are deleted when the account is deleted."""
    email = AccountEmail(
        account_id=test_account.id,
        email="cascade@example.com",
        is_primary=True,
        verified=True,
    )
    session.add(email)
    session.commit()

    session.delete(test_account)
    session.commit()

    remaining = session.exec(select(AccountEmail)).all()
    assert len(remaining) == 0


# --- EmailVerificationToken model tests ---


def test_email_verification_token_creation(session: Session, test_account: Account):
    """Test creating an EmailVerificationToken and verifying fields persist."""
    token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="newemail@example.com",
    )
    session.add(token)
    session.commit()
    session.refresh(token)

    assert token.id is not None
    assert token.account_id == test_account.id
    assert token.new_email == "newemail@example.com"
    assert token.token is not None  # auto-generated uuid
    assert token.expires_at is not None
    assert token.used is False


def test_email_verification_token_is_expired(session: Session, test_account: Account):
    """Test that is_expired() correctly identifies expired tokens."""
    expired_token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="expired@example.com",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    valid_token = EmailVerificationToken(
        account_id=test_account.id,
        new_email="valid@example.com",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    session.add(expired_token)
    session.add(valid_token)
    session.commit()

    assert expired_token.is_expired()
    assert not valid_token.is_expired()


# --- AccountRecoveryToken tests ---


def test_account_recovery_token_creation(session: Session, test_account: Account):
    """Test that AccountRecoveryToken can be created with correct fields."""
    token = AccountRecoveryToken(
        account_id=test_account.id,
        email="victim@example.com",
    )
    session.add(token)
    session.commit()
    session.refresh(token)

    assert token.id is not None
    assert token.account_id == test_account.id
    assert token.email == "victim@example.com"
    assert token.used is False
    assert token.token is not None
    # 7-day expiry
    assert token.expires_at.replace(tzinfo=UTC) > datetime.now(UTC) + timedelta(days=6)
    assert token.expires_at.replace(tzinfo=UTC) < datetime.now(UTC) + timedelta(days=8)


def test_account_recovery_token_is_expired(session: Session, test_account: Account):
    """Test is_expired() method on AccountRecoveryToken."""
    expired_token = AccountRecoveryToken(
        account_id=test_account.id,
        email="expired@example.com",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    valid_token = AccountRecoveryToken(
        account_id=test_account.id,
        email="valid@example.com",
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    session.add(expired_token)
    session.add(valid_token)
    session.commit()

    assert expired_token.is_expired()
    assert not valid_token.is_expired()
