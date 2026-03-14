"""
Example app-specific permissions. Replace these with your own permissions
that correspond to your application's data models and access control needs.

These are automatically registered alongside the core ValidPermissions
during database setup, and can be used with User.has_permission() in the
same way as core permissions.
"""
from enum import StrEnum


class AppPermissions(StrEnum):
    READ_ORGANIZATION_RESOURCES = "Read Organization Resources"
    WRITE_ORGANIZATION_RESOURCES = "Write Organization Resources"
    DELETE_ORGANIZATION_RESOURCES = "Delete Organization Resources"
