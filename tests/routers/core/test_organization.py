from utils.core.models import Organization, Role, Permission, ValidPermissions, User
from utils.core.db import create_default_roles
from main import app
from sqlmodel import select
from tests.conftest import SetupError
from fastapi.testclient import TestClient
from sqlmodel import Session

def test_create_organization_success(auth_client, session, test_user):
    """Test successful organization creation"""
    response = auth_client.post(
        app.url_path_for("create_organization"),
        data={"name": "New Test Organization"},
        follow_redirects=False
    )

    # Check response
    assert response.status_code == 303  # Redirect status code
    assert "/organizations/" in response.headers["location"]

    # Verify database state
    org = session.exec(
        select(Organization)
        .where(Organization.name == "New Test Organization")
    ).first()
    
    assert org is not None
    assert org.name == "New Test Organization"

    # Verify default roles were created
    roles = session.exec(
        select(Role)
        .where(Role.organization_id == org.id)
    ).all()
    
    # Verify all default roles exist by name
    role_names = {role.name for role in roles}
    assert "Owner" in role_names
    assert "Administrator" in role_names
    assert "Member" in role_names
    assert len(roles) == 3 # Ensure only default roles were created

    # Verify test_user was assigned as owner
    owner_role = next((role for role in roles if role.name == "Owner"), None)
    assert owner_role is not None
    assert test_user in owner_role.users

    # Verify permissions for Owner role (should have all)
    all_permissions = session.exec(select(Permission)).all()
    all_permission_names = {p.name for p in all_permissions}
    owner_permission_names = {p.name for p in owner_role.permissions}
    assert owner_permission_names == all_permission_names

    # Verify permissions for Administrator role (should have all except DELETE_ORGANIZATION)
    admin_role = next((role for role in roles if role.name == "Administrator"), None)
    assert admin_role is not None
    admin_permission_names = {p.name for p in admin_role.permissions}
    expected_admin_permissions = {p.name for p in all_permissions if p.name != ValidPermissions.DELETE_ORGANIZATION}
    assert admin_permission_names == expected_admin_permissions

    # Verify permissions for Member role (should have none)
    member_role = next((role for role in roles if role.name == "Member"), None)
    assert member_role is not None
    assert len(member_role.permissions) == 0

def test_create_organization_empty_name(auth_client):
    """Test organization creation with empty name"""
    response = auth_client.post(
        app.url_path_for("create_organization"),
        data={"name": "   "},
        follow_redirects=True
    )
    
    # Should get a 422 Unprocessable Entity for validation error
    assert response.status_code == 422
    assert "this field cannot be empty or contain only whitespace" in response.text
    assert "name" in response.text

def test_create_organization_duplicate_name(auth_client, session, test_organization):
    """Test organization creation with duplicate name"""
    # Count organizations before the request
    org_count_before = len(session.exec(select(Organization)).all())
    
    response = auth_client.post(
        app.url_path_for("create_organization"),
        data={"name": test_organization.name},
        follow_redirects=False
    )
    
    # Verify the response is a 400 Bad Request
    assert response.status_code == 400
    assert "Organization name already taken" in response.text
    
    # Verify no new organization was created
    org_count_after = len(session.exec(select(Organization)).all())
    assert org_count_after == org_count_before
    
    # Verify there's still only one organization with this name
    orgs_with_name = session.exec(
        select(Organization)
        .where(Organization.name == test_organization.name)
    ).all()
    assert len(orgs_with_name) == 1

def test_create_organization_unauthenticated(unauth_client):
    """Test organization creation without authentication"""
    response = unauth_client.post(
        app.url_path_for("create_organization"),
        data={"name": "Unauthorized Org"},
        follow_redirects=False
    )
    
    assert response.status_code == 303  # Unauthorized

def test_update_organization_success(
        auth_client: TestClient, session: Session, test_organization: Organization, test_user: User
    ):
    """Test successful organization update"""
    # Ensure test_user has the EDIT_ORGANIZATION permission via the Owner role (already created by fixture)
    if test_organization.id is None:
        raise SetupError("Test organization ID is None")
        
    owner_role = session.exec(
        select(Role).where(
            Role.organization_id == test_organization.id,
            Role.name == "Owner"
        )
    ).first()
    
    if owner_role is None:
        raise SetupError("Owner role not found for test organization.")

    # Ensure the permission is present (it should be by default)
    edit_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.EDIT_ORGANIZATION)
    ).first()
    if edit_permission is None:
        raise SetupError("EDIT_ORGANIZATION permission not found.")
        
    if edit_permission not in owner_role.permissions:
        owner_role.permissions.append(edit_permission) # Add just in case
        
    # Ensure the user is assigned to the role (it should be by default for the creating user)
    if test_user not in owner_role.users:
        owner_role.users.append(test_user)
    
    session.commit()
    session.refresh(owner_role)
    session.refresh(test_user)

    new_name = "Updated Organization Name"
    response = auth_client.post(
        app.url_path_for("update_organization", org_id=test_organization.id),
        data={"id": str(test_organization.id), "name": new_name},
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect status code
    assert str(app.url_path_for("read_organization", org_id=test_organization.id)) in response.headers["location"]

    # Expire all objects in the session to force a refresh from the database
    session.expire_all()
    
    # Verify database update
    updated_org = session.get(Organization, test_organization.id)
    if updated_org is None:
        raise SetupError("Updated organization not found")
    assert updated_org.name == new_name

def test_update_organization_unauthorized(auth_client, session, test_organization, test_user):
    """Test organization update without proper permissions"""
    # Add user to organization but without edit permission
    basic_role = Role(name="Basic", organization_id=test_organization.id)
    basic_role.users.append(test_user)
    session.add(basic_role)
    session.commit()

    response = auth_client.post(
        app.url_path_for("update_organization", org_id=test_organization.id),
        data={
            "id": test_organization.id,
            "name": "Unauthorized Update"
        },
        follow_redirects=False
    )

    assert response.status_code == 403
    assert "permission" in response.text.lower()

def test_update_organization_duplicate_name(auth_client, session, test_organization, test_user):
    existing_org = Organization(name="Existing Org")
    session.add(existing_org)
    
    # Ensure test_user has EDIT_ORGANIZATION permission via the Owner role
    if test_organization.id is None:
        raise SetupError("Test organization ID is None")

    owner_role = session.exec(
        select(Role).where(
            Role.organization_id == test_organization.id,
            Role.name == "Owner"
        )
    ).first()

    if owner_role is None:
        raise SetupError("Owner role not found for test organization.")

    edit_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.EDIT_ORGANIZATION)
    ).first()
    if edit_permission is None:
        raise SetupError("EDIT_ORGANIZATION permission not found.")

    if edit_permission not in owner_role.permissions:
        owner_role.permissions.append(edit_permission)

    if test_user not in owner_role.users:
        owner_role.users.append(test_user)
        
    session.commit()
    session.refresh(owner_role)
    session.refresh(test_user)

    response = auth_client.post(
        app.url_path_for("update_organization", org_id=test_organization.id),
        data={
            "id": test_organization.id,
            "name": "Existing Org"
        },
        follow_redirects=False
    )

    assert response.status_code == 400
    assert "organization name already taken" in response.text.lower()

def test_update_organization_empty_name(auth_client, session, test_organization, test_user):
    """Test organization update with empty name"""
    # Ensure test_user has EDIT_ORGANIZATION permission via the Owner role
    if test_organization.id is None:
        raise SetupError("Test organization ID is None")

    owner_role = session.exec(
        select(Role).where(
            Role.organization_id == test_organization.id,
            Role.name == "Owner"
        )
    ).first()

    if owner_role is None:
        raise SetupError("Owner role not found for test organization.")

    edit_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.EDIT_ORGANIZATION)
    ).first()
    if edit_permission is None:
        raise SetupError("EDIT_ORGANIZATION permission not found.")

    if edit_permission not in owner_role.permissions:
        owner_role.permissions.append(edit_permission)

    if test_user not in owner_role.users:
        owner_role.users.append(test_user)
        
    session.commit()
    session.refresh(owner_role)
    session.refresh(test_user)

    response = auth_client.post(
        app.url_path_for("update_organization", org_id=test_organization.id),
        data={
            "id": test_organization.id,
            "name": "   "
        },
        follow_redirects=True
    )

    assert response.status_code == 422
    assert "this field cannot be empty or contain only whitespace" in response.text.lower()
    assert "name" in response.text.lower()

def test_update_organization_unauthenticated(unauth_client, test_organization):
    """Test organization update without authentication"""
    response = unauth_client.post(
        app.url_path_for("update_organization", org_id=test_organization.id),
        data={
            "id": test_organization.id,
            "name": "Unauthorized Update"
        },
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect to login

def test_delete_organization_success(auth_client, session, test_organization, test_user):
    """Test successful organization deletion"""
    # Store the organization ID for later verification
    org_id = test_organization.id
    if org_id is None: # Add check for None
        raise SetupError("Test organization ID is None")
    
    # Ensure test_user has DELETE_ORGANIZATION permission via the Owner role
    owner_role = session.exec(
        select(Role).where(
            Role.organization_id == org_id,
            Role.name == "Owner"
        )
    ).first()

    if owner_role is None:
        raise SetupError("Owner role not found for test organization.")

    delete_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.DELETE_ORGANIZATION)
    ).first()
    if delete_permission is None:
        raise SetupError("DELETE_ORGANIZATION permission not found.")

    if delete_permission not in owner_role.permissions:
        owner_role.permissions.append(delete_permission) 

    if test_user not in owner_role.users:
        owner_role.users.append(test_user)
        
    session.commit() # Commit permission/user assignment changes
    session.refresh(owner_role)
    session.refresh(test_user)

    response = auth_client.post(
        app.url_path_for("delete_organization", org_id=org_id),
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect status code
    assert app.url_path_for("read_profile") in response.headers["location"]

    # Expire all objects in the session to force a refresh from the database
    session.expire_all()
    
    # Verify organization was deleted by querying directly
    deleted_org = session.exec(
        select(Organization).where(Organization.id == org_id)
    ).first()
    assert deleted_org is None

def test_delete_organization_unauthorized(auth_client_member, session, test_organization):
    """Test organization deletion without proper permissions"""
    # Use auth_client_member, who belongs to the org but has no delete permission
    response = auth_client_member.post(
        app.url_path_for("delete_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 403
    assert "permission" in response.text.lower()

    # Verify organization still exists
    org = session.get(Organization, test_organization.id)
    assert org is not None

def test_delete_organization_not_member(auth_client_non_member, session, test_organization):
    """Test organization deletion by non-member"""
    response = auth_client_non_member.post(
        app.url_path_for("delete_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 403
    assert "permission" in response.text.lower()

    # Verify organization still exists
    org = session.get(Organization, test_organization.id)
    assert org is not None

def test_delete_organization_unauthenticated(unauth_client, test_organization):
    """Test organization deletion without authentication"""
    response = unauth_client.post(
        app.url_path_for("delete_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 303  # Redirect to login

def test_delete_organization_cascade(auth_client, session, test_organization, test_user):
    """Test that deleting organization cascades to roles"""
    # Store the organization ID for later verification
    org_id = test_organization.id
    if org_id is None: # Add check for None
        raise SetupError("Test organization ID is None")
    
    # Ensure test_user has DELETE_ORGANIZATION permission via the Owner role
    owner_role = session.exec(
        select(Role).where(
            Role.organization_id == org_id,
            Role.name == "Owner"
        )
    ).first()
    if owner_role is None:
        raise SetupError("Owner role not found for test organization.")

    delete_permission = session.exec(
        select(Permission).where(Permission.name == ValidPermissions.DELETE_ORGANIZATION)
    ).first()
    if delete_permission is None:
        raise SetupError("DELETE_ORGANIZATION permission not found.")

    if delete_permission not in owner_role.permissions:
        owner_role.permissions.append(delete_permission)

    if test_user not in owner_role.users:
        owner_role.users.append(test_user)
        
    # Verify the Member role exists (created by fixture)
    member_role = session.exec(
        select(Role).where(
            Role.organization_id == org_id,
            Role.name == "Member"
        )
    ).first()
    if member_role is None:
        raise SetupError("Member role not found for test organization. Fixture might have changed.")

    session.commit() # Commit permission/user assignment changes
    session.refresh(owner_role)
    session.refresh(test_user)

    response = auth_client.post(
        app.url_path_for("delete_organization", org_id=org_id),
        follow_redirects=False
    )

    assert response.status_code == 303

    # Expire all objects in the session to force a refresh from the database
    session.expire_all()
    
    # Verify roles were also deleted
    roles = session.exec(
        select(Role)
        .where(Role.organization_id == org_id)
    ).all()
    assert len(roles) == 0

# --- Organization View Tests ---

def test_read_organization_as_owner(auth_client_owner, test_organization):
    """Test accessing organization page as an owner"""
    response = auth_client_owner.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 200
    assert test_organization.name in response.text

    # Owner should have the permission to trigger the delete organization modal
    assert 'data-bs-target="#deleteOrganizationModal"' in response.text


def test_read_organization_as_admin(auth_client_admin, test_organization):
    """Test accessing organization page as an admin"""
    response = auth_client_admin.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 200
    assert test_organization.name in response.text
    
    # Admin shouldn't have the permission to trigger the delete organization modal
    assert 'data-bs-target="#deleteOrganizationModal"' not in response.text


def test_read_organization_as_member(auth_client_member, test_organization):
    """Test accessing organization page as a regular member"""
    response = auth_client_member.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 200
    assert test_organization.name in response.text

    # Member shouldn't have the permission to trigger the delete organization modal
    assert 'data-bs-target="#deleteOrganizationModal"' not in response.text


def test_read_organization_as_non_member(auth_client_non_member, test_organization):
    """Test accessing organization page as a non-member"""
    response = auth_client_non_member.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    # Non-members should get an error when accessing the organization
    assert response.status_code == 404
    assert "Organization not found" in response.text


def test_organization_page_displays_members_correctly(auth_client_owner, org_admin_user, org_member_user, test_organization):
    """Test that members and their roles are displayed correctly"""
    response = auth_client_owner.get(
        app.url_path_for("read_organization", org_id=test_organization.id),
        follow_redirects=False
    )

    assert response.status_code == 200

    # Check that members are displayed with their names and roles
    assert "Org Owner" in response.text
    assert "Admin User" in response.text
    assert "Member User" in response.text

    # Check roles appear next to users
    assert ">Owner<" in response.text
    assert ">Administrator<" in response.text
    assert ">Member<" in response.text


def test_empty_organization_displays_no_members_message(auth_client_owner, session):
    """Test that an organization with no members displays appropriate message"""
    # Create a new empty organization with just the owner
    empty_org = Organization(name="Empty Organization")
    session.add(empty_org)
    session.commit()

    if empty_org.id is None:
        raise SetupError("Empty organization ID is None")

    create_default_roles(session, empty_org.id, check_first=False)

    # Retrieve the owner role
    owner_role = session.exec(
        select(Role)
        .where(Role.name == "Owner")
        .where(Role.organization_id == empty_org.id)
    ).first()
    session.refresh(empty_org)

    if owner_role is None:
        raise SetupError("Could not find 'Owner' role after test setup.")

    # Get the owner user (created by the org_owner fixture)
    owner = session.exec(select(User).where(User.name == "Org Owner")).first()
    if owner is None:
        raise SetupError("Could not find 'Org Owner' user after test setup.")

    # Add the owner to the role to ensure we can access the organization
    # but keep it otherwise empty
    owner_role.users.append(owner)

    # No need to add again, just commit
    session.commit()

    response = auth_client_owner.get(
        app.url_path_for("read_organization", org_id=empty_org.id),
        follow_redirects=False
    )

    # This will fail before implementation but should pass after
    assert response.status_code == 200
    assert "No members found" in response.text


# --- Invite User Tests ---

def test_invite_user_success(auth_client_owner, session, test_organization, non_member_user):
    """Test successfully inviting a user to the organization"""
    # Count roles before invite
    roles_count_before = len(non_member_user.roles)

    # Send invite
    response = auth_client_owner.post(
        app.url_path_for("invite_member", org_id=test_organization.id),
        data={"email": non_member_user.account.email},
        follow_redirects=False
    )

    # Should redirect back to organization page
    assert response.status_code == 303
    assert app.url_path_for("read_organization", org_id=test_organization.id) in response.headers["location"]

    # Verify database state - user should now have the Member role
    session.refresh(non_member_user)
    assert len(non_member_user.roles) == roles_count_before + 1

    # Verify the user has been assigned the Member role
    member_role = session.exec(
        select(Role)
        .where(Role.name == "Member")
        .where(Role.organization_id == test_organization.id)
    ).first()

    assert member_role is not None
    assert non_member_user in member_role.users


def test_invite_nonexistent_user(auth_client_owner, test_organization):
    """Test inviting a user that doesn't exist in the system"""
    response = auth_client_owner.post(
        app.url_path_for("invite_member", org_id=test_organization.id),
        data={"email": "nonexistent@example.com"},
        follow_redirects=True
    )

    # Should return an error
    assert response.status_code in [404, 400, 500]  # Allow any reasonable error code
    assert "user not found" in response.text.lower() or "account not found" in response.text.lower() or "email not found" in response.text.lower()


def test_invite_existing_member(auth_client_owner, test_organization, org_member_user):
    """Test inviting a user who is already a member"""
    response = auth_client_owner.post(
        app.url_path_for("invite_member", org_id=test_organization.id),
        data={"email": org_member_user.account.email},
        follow_redirects=True
    )

    # Should return a 400 Bad Request
    assert response.status_code == 400
    assert "already a member" in response.text.lower()


def test_invite_without_permission(auth_client_member, test_organization, non_member_user):
    """Test inviting a user without having the INVITE_USER permission"""
    response = auth_client_member.post(
        app.url_path_for("invite_member", org_id=test_organization.id),
        data={"email": non_member_user.account.email},
        follow_redirects=True
    )

    # Should return a 403 Forbidden
    assert response.status_code == 403
    assert "permission" in response.text.lower()
