"""
Application data models.

SQLModel table classes defined here are automatically created in the
database on startup when this module is imported in utils/core/db.py.
"""

from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel

from utils.core.models import utc_now


class OrganizationResource(SQLModel, table=True):
    """
    Example application data model representing a resource owned by an
    organization. Replace or extend with your own application-specific models.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(
        foreign_key="organization.id", ondelete="CASCADE", index=True
    )
    title: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class OrganizationBilling(SQLModel, table=True):
    """Stripe subscription state for one organization (1:1 with Organization)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    organization_id: int = Field(
        foreign_key="organization.id",
        unique=True,
        ondelete="CASCADE",
        index=True,
    )
    stripe_customer_id: Optional[str] = Field(default=None, index=True)
    stripe_subscription_id: Optional[str] = Field(default=None, index=True)
    status: str = Field(default="none", index=True)
    price_id: Optional[str] = None
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    last_payment_at: Optional[datetime] = None
    cancel_at_period_end: bool = Field(default=False)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class StripeWebhookEvent(SQLModel, table=True):
    """Processed Stripe webhook event IDs for idempotent handling."""

    id: Optional[int] = Field(default=None, primary_key=True)
    stripe_event_id: str = Field(unique=True, index=True)
    processed_at: datetime = Field(default_factory=utc_now)
