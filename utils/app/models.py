"""
Example application data model.

Replace this module with your own application-specific SQLModel classes.
Any SQLModel table classes defined here will be automatically created in the
database on startup, as long as this module is imported in utils/core/db.py.
"""

from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field
from utils.core.models import utc_now


# --- Replace the example model below with your own application models ---


class OrganizationResource(SQLModel, table=True):
    """
    Example application data model representing a resource owned by an
    organization. Replace this with your own application-specific models.

    Each resource belongs to a single organization (via organization_id foreign
    key). Users with the READ_ORGANIZATION_RESOURCES permission can view these
    resources, users with WRITE_ORGANIZATION_RESOURCES can create/edit them, and
    users with DELETE_ORGANIZATION_RESOURCES can delete them.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(foreign_key="organization.id", index=True)
    title: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
