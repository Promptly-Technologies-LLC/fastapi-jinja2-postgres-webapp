"""Billing helpers for organization-scoped Stripe subscriptions."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Optional

from sqlmodel import Session, select

from utils.app.enums import (
    ACTIVE_BILLING_STATUSES,
    CHECKOUT_ELIGIBLE_STATUSES,
    PORTAL_ELIGIBLE_STATUSES,
    BillingStatus,
)
from utils.app.models import OrganizationBilling
from utils.core.models import utc_now

logger = logging.getLogger(__name__)


class _UnsetType:
    __slots__ = ()


_UNSET = _UnsetType()


def _as_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def get_org_billing(session: Session, org_id: int) -> OrganizationBilling | None:
    return session.exec(
        select(OrganizationBilling).where(OrganizationBilling.organization_id == org_id)
    ).first()


def get_or_create_org_billing(session: Session, org_id: int) -> OrganizationBilling:
    billing = get_org_billing(session, org_id)
    if billing is not None:
        return billing
    billing = OrganizationBilling(organization_id=org_id)
    session.add(billing)
    session.commit()
    session.refresh(billing)
    return billing


def billing_status(billing: OrganizationBilling | None) -> BillingStatus:
    if billing is None or not billing.status:
        return BillingStatus.NONE
    try:
        return BillingStatus(billing.status)
    except ValueError:
        return BillingStatus.NONE


def org_has_active_subscription(session: Session, org_id: int) -> bool:
    """Return True when the organization has a paid-up trialing or active subscription."""
    billing = get_org_billing(session, org_id)
    if billing is None:
        return False
    return billing_status(billing) in ACTIVE_BILLING_STATUSES


def org_may_start_checkout(session: Session, org_id: int) -> bool:
    billing = get_org_billing(session, org_id)
    status = billing_status(billing)
    if status in CHECKOUT_ELIGIBLE_STATUSES:
        return True
    return billing is None or not billing.stripe_customer_id


def sync_billing_from_subscription(
    session: Session,
    *,
    org_id: int,
    stripe_customer_id: str | None | _UnsetType = _UNSET,
    stripe_subscription_id: str | None | _UnsetType = _UNSET,
    status: str | None | _UnsetType = _UNSET,
    price_id: str | None | _UnsetType = _UNSET,
    current_period_start: datetime | None | _UnsetType = _UNSET,
    current_period_end: datetime | None | _UnsetType = _UNSET,
    cancel_at_period_end: bool | _UnsetType = _UNSET,
) -> OrganizationBilling:
    billing = get_or_create_org_billing(session, org_id)
    if not isinstance(stripe_customer_id, _UnsetType):
        billing.stripe_customer_id = stripe_customer_id
    if not isinstance(stripe_subscription_id, _UnsetType):
        billing.stripe_subscription_id = stripe_subscription_id
    if not isinstance(status, _UnsetType) and status is not None:
        billing.status = status
    if not isinstance(price_id, _UnsetType):
        billing.price_id = price_id
    if not isinstance(current_period_start, _UnsetType):
        period_start = current_period_start
        billing.current_period_start = (
            _as_utc_naive(period_start) if period_start is not None else None
        )
    if not isinstance(current_period_end, _UnsetType):
        period_end = current_period_end
        billing.current_period_end = (
            _as_utc_naive(period_end) if period_end is not None else None
        )
    if not isinstance(cancel_at_period_end, _UnsetType):
        billing.cancel_at_period_end = cancel_at_period_end
    billing.updated_at = utc_now()
    session.add(billing)
    session.commit()
    session.refresh(billing)
    return billing


def record_last_payment(session: Session, org_id: int, paid_at: datetime) -> None:
    billing = get_org_billing(session, org_id)
    if billing is None:
        return
    billing.last_payment_at = _as_utc_naive(paid_at)
    billing.updated_at = utc_now()
    session.add(billing)
    session.commit()


def cancel_org_stripe_subscription(session: Session, org_id: int) -> None:
    """Cancel the Stripe subscription before organization deletion."""
    from exceptions.http_exceptions import StripeSubscriptionCancelError
    from utils.app.credentials import billing_enabled

    if not billing_enabled():
        return

    billing = get_org_billing(session, org_id)
    if billing is None or not billing.stripe_subscription_id:
        return
    if billing_status(billing) not in ACTIVE_BILLING_STATUSES | {
        BillingStatus.PAST_DUE,
        BillingStatus.UNPAID,
    }:
        return

    from utils.app.stripe_billing import cancel_subscription

    try:
        cancel_subscription(billing.stripe_subscription_id)
    except Exception as exc:
        logger.exception(
            "Failed to cancel Stripe subscription for org_id=%s before delete",
            org_id,
        )
        raise StripeSubscriptionCancelError() from exc

    billing.status = BillingStatus.CANCELED.value
    billing.stripe_subscription_id = None
    billing.cancel_at_period_end = False
    billing.updated_at = utc_now()
    session.add(billing)
    session.commit()


def billing_status_label(status: BillingStatus) -> str:
    labels = {
        BillingStatus.NONE: "Free",
        BillingStatus.TRIALING: "Trialing",
        BillingStatus.ACTIVE: "Active",
        BillingStatus.PAST_DUE: "Past due",
        BillingStatus.CANCELED: "Canceled",
        BillingStatus.UNPAID: "Unpaid",
        BillingStatus.INCOMPLETE: "Incomplete",
    }
    return labels.get(status, status.value.replace("_", " ").title())


def can_subscribe_to_billing(
    *,
    can_manage: bool,
    status: BillingStatus,
    billing: OrganizationBilling | None,
) -> bool:
    if not can_manage:
        return False
    if status in CHECKOUT_ELIGIBLE_STATUSES:
        return True
    return billing is None or not billing.stripe_customer_id


def can_manage_billing_portal(
    *,
    can_manage: bool,
    billing: OrganizationBilling | None,
    status: BillingStatus,
) -> bool:
    if not can_manage or billing is None or not billing.stripe_customer_id:
        return False
    return status in PORTAL_ELIGIBLE_STATUSES


def billing_nav_href(request, user) -> str | None:
    """Return billing page URL for the nav menu when the user may view billing."""
    from utils.app.credentials import billing_enabled
    from utils.app.enums import AppPermissions

    if not billing_enabled() or not user or not user.organizations:
        return None

    selected_org = None
    selected_org_id_str = request.cookies.get("selected_organization_id")
    if selected_org_id_str:
        try:
            selected_org_id = int(selected_org_id_str)
            selected_org = next(
                (org for org in user.organizations if org.id == selected_org_id),
                None,
            )
        except ValueError:
            pass

    if selected_org is None:
        selected_org = user.organizations[0]

    if selected_org.id is None:
        return None

    if not user.has_permission(AppPermissions.VIEW_BILLING, selected_org):
        return None

    return str(request.url_for("read_billing", org_id=selected_org.id))


def organization_id_from_metadata(metadata: object) -> Optional[int]:
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get("organization_id")
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw)
        except ValueError:
            return None
    return None
