"""Tests for billing helper functions."""

from datetime import UTC, datetime

from sqlmodel import Session

from utils.app.billing import (
    billing_status,
    get_or_create_org_billing,
    org_has_active_subscription,
    org_may_start_checkout,
    sync_billing_from_subscription,
)
from utils.app.enums import BillingStatus
from utils.app.models import OrganizationBilling
from utils.core.models import Organization


def test_get_or_create_org_billing(session: Session) -> None:
    org = Organization(name="Billing org")
    session.add(org)
    session.commit()
    session.refresh(org)
    assert org.id is not None

    first = get_or_create_org_billing(session, org.id)
    second = get_or_create_org_billing(session, org.id)
    assert first.id is not None
    assert second.id == first.id


def test_org_has_active_subscription(session: Session) -> None:
    org = Organization(name="Paid org")
    session.add(org)
    session.commit()
    session.refresh(org)
    assert org.id is not None

    assert org_has_active_subscription(session, org.id) is False

    sync_billing_from_subscription(
        session,
        org_id=org.id,
        stripe_customer_id="cus_123",
        stripe_subscription_id="sub_123",
        status=BillingStatus.ACTIVE.value,
        price_id="price_123",
        current_period_start=datetime.now(UTC),
        current_period_end=datetime.now(UTC),
        cancel_at_period_end=False,
    )
    assert org_has_active_subscription(session, org.id) is True


def test_past_due_is_not_treated_as_active(session: Session) -> None:
    org = Organization(name="Past due org")
    session.add(org)
    session.commit()
    session.refresh(org)
    assert org.id is not None

    sync_billing_from_subscription(
        session,
        org_id=org.id,
        stripe_customer_id="cus_past_due",
        stripe_subscription_id="sub_past_due",
        status=BillingStatus.PAST_DUE.value,
        price_id="price_123",
        current_period_start=datetime.now(UTC),
        current_period_end=datetime.now(UTC),
        cancel_at_period_end=False,
    )
    assert org_has_active_subscription(session, org.id) is False


def test_sync_clears_subscription_id_when_explicitly_set_to_none(
    session: Session,
) -> None:
    org = Organization(name="Canceled org")
    session.add(org)
    session.commit()
    session.refresh(org)
    assert org.id is not None

    sync_billing_from_subscription(
        session,
        org_id=org.id,
        stripe_customer_id="cus_123",
        stripe_subscription_id="sub_123",
        status=BillingStatus.ACTIVE.value,
        price_id="price_123",
        current_period_start=datetime.now(UTC),
        current_period_end=datetime.now(UTC),
        cancel_at_period_end=False,
    )
    sync_billing_from_subscription(
        session,
        org_id=org.id,
        stripe_subscription_id=None,
        status=BillingStatus.CANCELED.value,
    )
    billing = get_or_create_org_billing(session, org.id)
    assert billing.stripe_subscription_id is None
    assert billing.status == BillingStatus.CANCELED.value


def test_incomplete_subscription_may_start_checkout(session: Session) -> None:
    org = Organization(name="Incomplete org")
    session.add(org)
    session.commit()
    session.refresh(org)
    assert org.id is not None

    sync_billing_from_subscription(
        session,
        org_id=org.id,
        stripe_customer_id="cus_incomplete",
        stripe_subscription_id="sub_incomplete",
        status=BillingStatus.INCOMPLETE.value,
        price_id="price_123",
        current_period_start=None,
        current_period_end=None,
        cancel_at_period_end=False,
    )
    assert org_may_start_checkout(session, org.id) is True


def test_active_subscription_may_not_start_checkout(session: Session) -> None:
    org = Organization(name="Active org")
    session.add(org)
    session.commit()
    session.refresh(org)
    assert org.id is not None

    sync_billing_from_subscription(
        session,
        org_id=org.id,
        stripe_customer_id="cus_active",
        stripe_subscription_id="sub_active",
        status=BillingStatus.ACTIVE.value,
        price_id="price_123",
        current_period_start=datetime.now(UTC),
        current_period_end=datetime.now(UTC),
        cancel_at_period_end=False,
    )
    assert org_may_start_checkout(session, org.id) is False


def test_billing_status_defaults_to_none() -> None:
    assert billing_status(None) == BillingStatus.NONE
    assert billing_status(OrganizationBilling(organization_id=1)) == BillingStatus.NONE
