"""
App-specific permissions. Replace or extend these for your application's
access control needs.

These are automatically registered alongside core ValidPermissions during
database setup and can be used with User.has_permission() the same way.
"""

from enum import StrEnum


class AppPermissions(StrEnum):
    READ_ORGANIZATION_RESOURCES = "Read Organization Resources"
    WRITE_ORGANIZATION_RESOURCES = "Write Organization Resources"
    DELETE_ORGANIZATION_RESOURCES = "Delete Organization Resources"
    MANAGE_BILLING = "Manage Billing"
    VIEW_BILLING = "View Billing"


class BillingStatus(StrEnum):
    """Stripe-aligned subscription states stored for each organization."""

    NONE = "none"
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"
    INCOMPLETE = "incomplete"


ACTIVE_BILLING_STATUSES = frozenset(
    {
        BillingStatus.TRIALING,
        BillingStatus.ACTIVE,
    }
)


CHECKOUT_ELIGIBLE_STATUSES = frozenset(
    {
        BillingStatus.NONE,
        BillingStatus.CANCELED,
        BillingStatus.INCOMPLETE,
        BillingStatus.UNPAID,
    }
)


PORTAL_ELIGIBLE_STATUSES = frozenset(
    {
        BillingStatus.TRIALING,
        BillingStatus.ACTIVE,
        BillingStatus.PAST_DUE,
        BillingStatus.UNPAID,
        BillingStatus.INCOMPLETE,
    }
)
