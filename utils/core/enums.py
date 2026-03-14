from enum import Enum


class ValidPermissions(Enum):
    """
    Core permissions - do not modify these:
    """
    DELETE_ORGANIZATION = "Delete Organization"
    EDIT_ORGANIZATION = "Edit Organization"
    INVITE_USER = "Invite User"
    REMOVE_USER = "Remove User"
    EDIT_USER_ROLE = "Edit User Role"
    CREATE_ROLE = "Create Role"
    DELETE_ROLE = "Delete Role"
    EDIT_ROLE = "Edit Role"

    # Add additional app-specific permissions below this line:
    READ_ORGANIZATION_RESOURCES = "Read Organization Resources"
    WRITE_ORGANIZATION_RESOURCES = "Write Organization Resources"
    DELETE_ORGANIZATION_RESOURCES = "Delete Organization Resources"