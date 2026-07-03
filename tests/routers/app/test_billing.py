"""Router tests for organization billing."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from main import app
from utils.app.billing import get_org_billing, sync_billing_from_subscription
from utils.app.enums import BillingStatus
from utils.app.models import StripeWebhookEvent
from utils.app.stripe_billing import WebhookHandleResult, handle_stripe_webhook_event
from utils.core.models import Organization, utc_now


@pytest.fixture
def auth_client_member(
    session: Session, test_organization: Organization, org_member_user
) -> TestClient:
    from utils.core.auth import create_access_token, create_tracked_refresh_token

    client = TestClient(app, follow_redirects=False)
    assert org_member_user.account is not None
    access_token = create_access_token({"sub": org_member_user.account.email})
    refresh_token = create_tracked_refresh_token(
        org_member_user.account_id, org_member_user.account.email, session
    )
    session.commit()
    client.cookies.set("access_token", access_token)
    client.cookies.set("refresh_token", refresh_token)
    return client


def test_billing_page_owner_can_view(
    auth_client_owner: TestClient, test_organization: Organization
) -> None:
    assert test_organization.id is not None
    response = auth_client_owner.get(
        app.url_path_for("read_billing", org_id=test_organization.id)
    )
    assert response.status_code == 200
    assert "Subscribe with Stripe" in response.text
    assert "Pro plan" in response.text


def test_billing_page_member_can_view(
    auth_client_member: TestClient,
    test_organization: Organization,
) -> None:
    assert test_organization.id is not None
    response = auth_client_member.get(
        app.url_path_for("read_billing", org_id=test_organization.id)
    )
    assert response.status_code == 200
    assert "Only the organization owner" in response.text


def test_checkout_owner_redirects_to_stripe(
    auth_client_owner: TestClient,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None

    class FakeCheckout:
        url = "https://checkout.stripe.test/session_123"

    monkeypatch.setattr(
        "routers.app.billing.create_checkout_session",
        lambda **kwargs: FakeCheckout(),
    )

    response = auth_client_owner.post(
        app.url_path_for("start_checkout", org_id=test_organization.id)
    )
    assert response.status_code == 303
    assert response.headers["location"] == FakeCheckout.url


def test_checkout_rejects_active_subscription(
    auth_client_owner: TestClient,
    session: Session,
    test_organization: Organization,
) -> None:
    assert test_organization.id is not None
    sync_billing_from_subscription(
        session,
        org_id=test_organization.id,
        stripe_customer_id="cus_active",
        stripe_subscription_id="sub_active",
        status=BillingStatus.ACTIVE.value,
        price_id="price_test_dummy",
        current_period_start=None,
        current_period_end=None,
        cancel_at_period_end=False,
    )

    response = auth_client_owner.post(
        app.url_path_for("start_checkout", org_id=test_organization.id)
    )
    assert response.status_code == 403


def test_checkout_member_forbidden(
    auth_client_member: TestClient,
    test_organization: Organization,
) -> None:
    assert test_organization.id is not None
    response = auth_client_member.post(
        app.url_path_for("start_checkout", org_id=test_organization.id)
    )
    assert response.status_code == 403


def test_portal_requires_customer(
    auth_client_owner: TestClient, test_organization: Organization
) -> None:
    assert test_organization.id is not None
    response = auth_client_owner.post(
        app.url_path_for("start_customer_portal", org_id=test_organization.id)
    )
    assert response.status_code == 403


def test_billing_success_requires_verified_checkout_session(
    auth_client_owner: TestClient,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None

    class FakeCheckoutSession:
        metadata = {"organization_id": str(test_organization.id)}
        client_reference_id = str(test_organization.id)
        payment_status = "paid"
        status = "complete"

    monkeypatch.setattr(
        "routers.app.billing.retrieve_checkout_session",
        lambda session_id: FakeCheckoutSession(),
    )

    response = auth_client_owner.get(
        app.url_path_for(
            "billing_checkout_success",
            org_id=test_organization.id,
        ),
        params={"session_id": "cs_test_verified"},
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith(
        f"/organizations/{test_organization.id}/billing"
    )


def test_billing_success_without_session_id_is_informational(
    auth_client_owner: TestClient,
    test_organization: Organization,
) -> None:
    assert test_organization.id is not None
    response = auth_client_owner.get(
        app.url_path_for("billing_checkout_success", org_id=test_organization.id)
    )
    assert response.status_code == 303


def test_webhook_rejects_missing_signature(unauth_client: TestClient) -> None:
    response = unauth_client.post(
        "/webhooks/stripe",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_webhook_checkout_completed_updates_billing(
    unauth_client: TestClient,
    session: Session,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None
    org_id = test_organization.id

    subscription = SimpleNamespace(
        id="sub_test",
        customer="cus_test",
        status="active",
        metadata={"organization_id": str(org_id)},
        current_period_start=1_700_000_000,
        current_period_end=1_700_086_400,
        cancel_at_period_end=False,
        items=SimpleNamespace(
            data=[SimpleNamespace(price=SimpleNamespace(id="price_test_dummy"))]
        ),
    )

    event = SimpleNamespace(
        id="evt_test_checkout",
        type="checkout.session.completed",
        data=SimpleNamespace(
            object=SimpleNamespace(
                metadata={"organization_id": str(org_id)},
                client_reference_id=str(org_id),
                subscription="sub_test",
                customer="cus_test",
            )
        ),
    )

    monkeypatch.setattr(
        "routers.app.billing.construct_webhook_event",
        lambda payload, signature: event,
    )
    monkeypatch.setattr(
        "utils.app.stripe_billing.stripe.Subscription.retrieve",
        lambda subscription_id: subscription,
    )

    response = unauth_client.post(
        "/webhooks/stripe",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Stripe-Signature": "test",
        },
    )
    assert response.status_code == 200

    billing = get_org_billing(session, org_id)
    assert billing is not None
    assert billing.stripe_customer_id == "cus_test"
    assert billing.stripe_subscription_id == "sub_test"
    assert billing.status == BillingStatus.ACTIVE.value

    stored_event = session.exec(
        select(StripeWebhookEvent).where(
            StripeWebhookEvent.stripe_event_id == "evt_test_checkout"
        )
    ).one()
    assert stored_event.id is not None


def test_webhook_is_idempotent(
    unauth_client: TestClient,
    session: Session,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None
    session.add(
        StripeWebhookEvent(
            stripe_event_id="evt_duplicate",
            processed_at=utc_now(),
        )
    )
    session.commit()

    event = SimpleNamespace(
        id="evt_duplicate",
        type="checkout.session.completed",
        data=SimpleNamespace(object=SimpleNamespace()),
    )
    monkeypatch.setattr(
        "routers.app.billing.construct_webhook_event",
        lambda payload, signature: event,
    )
    called = {"count": 0}

    def _fail_handler(db_session: Session, stripe_event: Any) -> WebhookHandleResult:
        called["count"] += 1
        return WebhookHandleResult.HANDLED

    monkeypatch.setattr(
        "routers.app.billing.handle_stripe_webhook_event", _fail_handler
    )

    response = unauth_client.post(
        "/webhooks/stripe",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Stripe-Signature": "test",
        },
    )
    assert response.status_code == 200
    assert called["count"] == 0


def test_webhook_subscription_deleted_clears_subscription_id(
    session: Session,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None
    sync_billing_from_subscription(
        session,
        org_id=test_organization.id,
        stripe_customer_id="cus_delete_event",
        stripe_subscription_id="sub_delete_event",
        status=BillingStatus.ACTIVE.value,
        price_id="price_test_dummy",
        current_period_start=None,
        current_period_end=None,
        cancel_at_period_end=False,
    )

    event = SimpleNamespace(
        id="evt_subscription_deleted",
        type="customer.subscription.deleted",
        data=SimpleNamespace(
            object=SimpleNamespace(
                customer="cus_delete_event",
                metadata={"organization_id": str(test_organization.id)},
                current_period_start=1_700_000_000,
                current_period_end=1_700_086_400,
                items=SimpleNamespace(
                    data=[SimpleNamespace(price=SimpleNamespace(id="price_test_dummy"))]
                ),
            )
        ),
    )

    result = handle_stripe_webhook_event(session, event)
    assert result is WebhookHandleResult.HANDLED

    billing = get_org_billing(session, test_organization.id)
    assert billing is not None
    assert billing.status == BillingStatus.CANCELED.value
    assert billing.stripe_subscription_id is None


def test_webhook_payment_failed_syncs_past_due_status(
    session: Session,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None
    subscription = SimpleNamespace(
        id="sub_past_due",
        customer="cus_past_due",
        status="past_due",
        metadata={"organization_id": str(test_organization.id)},
        current_period_start=1_700_000_000,
        current_period_end=1_700_086_400,
        cancel_at_period_end=False,
        items=SimpleNamespace(
            data=[SimpleNamespace(price=SimpleNamespace(id="price_test_dummy"))]
        ),
    )
    event = SimpleNamespace(
        id="evt_payment_failed",
        type="invoice.payment_failed",
        data=SimpleNamespace(
            object=SimpleNamespace(
                subscription="sub_past_due",
                metadata={"organization_id": str(test_organization.id)},
            )
        ),
    )
    monkeypatch.setattr(
        "utils.app.stripe_billing.stripe.Subscription.retrieve",
        lambda subscription_id: subscription,
    )

    result = handle_stripe_webhook_event(session, event)
    assert result is WebhookHandleResult.HANDLED

    billing = get_org_billing(session, test_organization.id)
    assert billing is not None
    assert billing.status == BillingStatus.PAST_DUE.value


def test_webhook_missing_metadata_is_ignored_without_failure(
    session: Session,
) -> None:
    event = SimpleNamespace(
        id="evt_missing_metadata",
        type="checkout.session.completed",
        data=SimpleNamespace(
            object=SimpleNamespace(
                metadata={}, client_reference_id=None, subscription=None
            )
        ),
    )
    result = handle_stripe_webhook_event(session, event)
    assert result is WebhookHandleResult.IGNORED


def test_org_delete_cancels_subscription(
    auth_client_owner: TestClient,
    session: Session,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None
    sync_billing_from_subscription(
        session,
        org_id=test_organization.id,
        stripe_customer_id="cus_delete",
        stripe_subscription_id="sub_delete",
        status=BillingStatus.ACTIVE.value,
        price_id="price_test_dummy",
        current_period_start=None,
        current_period_end=None,
        cancel_at_period_end=False,
    )
    canceled: list[str] = []

    monkeypatch.setattr(
        "utils.app.stripe_billing.cancel_subscription",
        lambda subscription_id: canceled.append(subscription_id) or SimpleNamespace(),
    )

    response = auth_client_owner.post(
        app.url_path_for("delete_organization", org_id=test_organization.id)
    )
    assert response.status_code in {303, 200}
    assert canceled == ["sub_delete"]

    remaining = session.exec(
        select(Organization).where(Organization.id == test_organization.id)
    ).first()
    assert remaining is None


def test_org_delete_blocked_when_stripe_cancel_fails(
    auth_client_owner: TestClient,
    session: Session,
    test_organization: Organization,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert test_organization.id is not None
    sync_billing_from_subscription(
        session,
        org_id=test_organization.id,
        stripe_customer_id="cus_delete_fail",
        stripe_subscription_id="sub_delete_fail",
        status=BillingStatus.ACTIVE.value,
        price_id="price_test_dummy",
        current_period_start=None,
        current_period_end=None,
        cancel_at_period_end=False,
    )

    def _raise_cancel(subscription_id: str) -> None:
        raise RuntimeError("stripe unavailable")

    monkeypatch.setattr("utils.app.stripe_billing.cancel_subscription", _raise_cancel)

    response = auth_client_owner.post(
        app.url_path_for("delete_organization", org_id=test_organization.id)
    )
    assert response.status_code == 409

    remaining = session.exec(
        select(Organization).where(Organization.id == test_organization.id)
    ).first()
    assert remaining is not None
