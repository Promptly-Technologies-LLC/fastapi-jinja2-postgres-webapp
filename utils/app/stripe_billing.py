"""Thin Stripe integration for organization subscriptions."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import stripe
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from utils.app.billing import (
    organization_id_from_metadata,
    record_last_payment,
    sync_billing_from_subscription,
)
from utils.app.enums import BillingStatus
from utils.app.models import StripeWebhookEvent
from utils.core.models import utc_now

logger = logging.getLogger(__name__)


class WebhookHandleResult(StrEnum):
    HANDLED = "handled"
    IGNORED = "ignored"
    FAILED = "failed"


@dataclass(frozen=True)
class StripeSettings:
    secret_key: str
    webhook_secret: str
    price_id: str
    base_url: str
    plan_name: str
    tax_enabled: bool


def stripe_settings() -> StripeSettings:
    secret_key = os.getenv("STRIPE_SECRET_KEY", "")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    price_id = os.getenv("STRIPE_PRICE_ID", "")
    base_url = os.getenv("BASE_URL", "").rstrip("/")
    plan_name = os.getenv("STRIPE_PLAN_NAME", "Pro")
    tax_raw = os.getenv("STRIPE_TAX_ENABLED", "1").lower()
    tax_enabled = tax_raw not in {"0", "false", "no"}
    return StripeSettings(
        secret_key=secret_key,
        webhook_secret=webhook_secret,
        price_id=price_id,
        base_url=base_url,
        plan_name=plan_name,
        tax_enabled=tax_enabled,
    )


def _configure_stripe() -> StripeSettings:
    settings = stripe_settings()
    stripe.api_key = settings.secret_key
    return settings


def create_checkout_session(
    *,
    org_id: int,
    owner_email: str,
    customer_id: str | None,
    idempotency_key: str,
) -> stripe.checkout.Session:
    settings = _configure_stripe()
    success_url = (
        f"{settings.base_url}/organizations/{org_id}/billing/success"
        "?session_id={CHECKOUT_SESSION_ID}"
    )
    cancel_url = f"{settings.base_url}/organizations/{org_id}/billing/cancel"

    params: dict[str, Any] = {
        "mode": "subscription",
        "line_items": [{"price": settings.price_id, "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(org_id),
        "metadata": {"organization_id": str(org_id)},
        "subscription_data": {"metadata": {"organization_id": str(org_id)}},
        "billing_address_collection": "required",
    }
    if settings.tax_enabled:
        params["automatic_tax"] = {"enabled": True}
    if customer_id:
        params["customer"] = customer_id
    else:
        params["customer_email"] = owner_email

    return stripe.checkout.Session.create(
        **params,
        idempotency_key=idempotency_key,
    )


def create_portal_session(
    *, org_id: int, customer_id: str
) -> stripe.billing_portal.Session:
    settings = _configure_stripe()
    return_url = f"{settings.base_url}/organizations/{org_id}/billing"
    return stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )


def retrieve_checkout_session(session_id: str) -> stripe.checkout.Session:
    _configure_stripe()
    return stripe.checkout.Session.retrieve(
        session_id,
        expand=["subscription"],
    )


def cancel_subscription(subscription_id: str) -> stripe.Subscription:
    _configure_stripe()
    return stripe.Subscription.cancel(subscription_id)


def construct_webhook_event(payload: bytes, signature: str) -> stripe.Event:
    settings = _configure_stripe()
    return stripe.Webhook.construct_event(
        payload,
        signature,
        settings.webhook_secret,
    )


def _timestamp_to_datetime(value: int | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, tz=UTC)


def _subscription_price_id(subscription: Any) -> str | None:
    items = getattr(subscription, "items", None)
    data = getattr(items, "data", None) if items is not None else None
    if not data:
        return None
    first = data[0]
    price = getattr(first, "price", None)
    if price is None:
        return None
    return getattr(price, "id", None)


def _sync_from_stripe_subscription(
    session: Session, subscription: Any, org_id: int
) -> None:
    sync_billing_from_subscription(
        session,
        org_id=org_id,
        stripe_customer_id=getattr(subscription, "customer", None),
        stripe_subscription_id=getattr(subscription, "id", None),
        status=str(getattr(subscription, "status", "none")),
        price_id=_subscription_price_id(subscription),
        current_period_start=_timestamp_to_datetime(
            getattr(subscription, "current_period_start", None)
        ),
        current_period_end=_timestamp_to_datetime(
            getattr(subscription, "current_period_end", None)
        ),
        cancel_at_period_end=bool(getattr(subscription, "cancel_at_period_end", False)),
    )


def _org_id_from_subscription(subscription: Any) -> int | None:
    metadata = getattr(subscription, "metadata", None)
    return organization_id_from_metadata(metadata)


def _org_id_from_invoice(invoice: Any) -> int | None:
    metadata = getattr(invoice, "metadata", None)
    org_id = organization_id_from_metadata(metadata)
    if org_id is not None:
        return org_id
    subscription_details = getattr(invoice, "subscription_details", None)
    if subscription_details is not None:
        sub_metadata = getattr(subscription_details, "metadata", None)
        org_id = organization_id_from_metadata(sub_metadata)
        if org_id is not None:
            return org_id
    parent = getattr(invoice, "parent", None)
    if parent is not None:
        sub_details = getattr(parent, "subscription_details", None)
        if sub_details is not None:
            return organization_id_from_metadata(getattr(sub_details, "metadata", None))
    return None


def claim_webhook_event(session: Session, event_id: str) -> bool:
    """Atomically claim a Stripe event ID before processing."""
    try:
        session.add(
            StripeWebhookEvent(stripe_event_id=event_id, processed_at=utc_now())
        )
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        return False


def release_webhook_event_claim(session: Session, event_id: str) -> None:
    event = session.exec(
        select(StripeWebhookEvent).where(StripeWebhookEvent.stripe_event_id == event_id)
    ).first()
    if event is not None:
        session.delete(event)
        session.commit()


def _log_webhook_handled(
    event_id: str, event_type: str, org_id: int
) -> WebhookHandleResult:
    logger.info(
        "Handled Stripe webhook event %s (%s) for org_id=%s",
        event_id,
        event_type,
        org_id,
    )
    return WebhookHandleResult.HANDLED


def handle_stripe_webhook_event(
    session: Session, event: stripe.Event
) -> WebhookHandleResult:
    event_type = event.type
    data_object = event.data.object

    try:
        if event_type == "checkout.session.completed":
            org_id = organization_id_from_metadata(
                getattr(data_object, "metadata", None)
            )
            if org_id is None:
                org_id = organization_id_from_metadata(
                    {
                        "organization_id": getattr(
                            data_object, "client_reference_id", None
                        )
                    }
                )
            subscription_id = getattr(data_object, "subscription", None)
            if org_id is None:
                logger.warning(
                    "Ignoring Stripe event %s: missing organization_id metadata",
                    event.id,
                )
                return WebhookHandleResult.IGNORED
            if not subscription_id:
                logger.warning(
                    "Ignoring Stripe event %s: checkout session missing subscription",
                    event.id,
                )
                return WebhookHandleResult.IGNORED
            subscription = stripe.Subscription.retrieve(subscription_id)
            _sync_from_stripe_subscription(session, subscription, org_id)
            return _log_webhook_handled(event.id, event_type, org_id)

        if event_type in {
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        }:
            org_id = _org_id_from_subscription(data_object)
            if org_id is None:
                logger.warning(
                    "Ignoring Stripe event %s: subscription missing organization_id metadata",
                    event.id,
                )
                return WebhookHandleResult.IGNORED
            if event_type == "customer.subscription.deleted":
                sync_billing_from_subscription(
                    session,
                    org_id=org_id,
                    stripe_customer_id=getattr(data_object, "customer", None),
                    stripe_subscription_id=None,
                    status=BillingStatus.CANCELED.value,
                    price_id=_subscription_price_id(data_object),
                    current_period_start=_timestamp_to_datetime(
                        getattr(data_object, "current_period_start", None)
                    ),
                    current_period_end=_timestamp_to_datetime(
                        getattr(data_object, "current_period_end", None)
                    ),
                    cancel_at_period_end=False,
                )
                return _log_webhook_handled(event.id, event_type, org_id)
            _sync_from_stripe_subscription(session, data_object, org_id)
            return _log_webhook_handled(event.id, event_type, org_id)

        if event_type == "invoice.paid":
            org_id = _org_id_from_invoice(data_object)
            if org_id is None:
                logger.warning(
                    "Ignoring Stripe event %s: invoice missing organization_id metadata",
                    event.id,
                )
                return WebhookHandleResult.IGNORED
            transitions = getattr(data_object, "status_transitions", None)
            paid_at = None
            if transitions is not None:
                paid_at = _timestamp_to_datetime(getattr(transitions, "paid_at", None))
            record_last_payment(session, org_id, paid_at or utc_now())
            subscription_id = getattr(data_object, "subscription", None)
            if subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                _sync_from_stripe_subscription(session, subscription, org_id)
            return _log_webhook_handled(event.id, event_type, org_id)

        if event_type == "invoice.payment_failed":
            org_id = _org_id_from_invoice(data_object)
            subscription_id = getattr(data_object, "subscription", None)
            if org_id is None:
                logger.warning(
                    "Ignoring Stripe event %s: failed invoice missing organization_id metadata",
                    event.id,
                )
                return WebhookHandleResult.IGNORED
            if subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                _sync_from_stripe_subscription(session, subscription, org_id)
                return _log_webhook_handled(event.id, event_type, org_id)
            logger.warning(
                "Ignoring Stripe event %s: failed invoice missing subscription",
                event.id,
            )
            return WebhookHandleResult.IGNORED

        return WebhookHandleResult.IGNORED
    except Exception:
        logger.exception("Failed to process Stripe webhook event %s", event.id)
        return WebhookHandleResult.FAILED
