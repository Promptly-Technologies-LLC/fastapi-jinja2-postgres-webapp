"""Organization billing routes (Stripe Checkout, Customer Portal, webhooks)."""

from __future__ import annotations

import logging
import uuid

import stripe
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from exceptions.http_exceptions import (
    ActiveSubscriptionError,
    InsufficientPermissionsError,
    OrganizationNotFoundError,
    StripeServiceUnavailableError,
    StripeSessionError,
)
from utils.app.billing import (
    billing_status,
    billing_status_label,
    can_manage_billing_portal,
    can_subscribe_to_billing,
    get_org_billing,
    org_may_start_checkout,
    organization_id_from_metadata,
)
from utils.app.enums import AppPermissions
from utils.app.stripe_billing import (
    WebhookHandleResult,
    claim_webhook_event,
    construct_webhook_event,
    create_checkout_session,
    create_portal_session,
    handle_stripe_webhook_event,
    release_webhook_event_claim,
    retrieve_checkout_session,
    stripe_settings,
)
from utils.core.dependencies import get_session, get_user_with_relations
from utils.core.htmx import htmx_redirect, is_htmx_request, set_flash_cookie
from utils.core.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["billing"])
webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])
templates = Jinja2Templates(directory="templates")


def _require_org_member(user: User, org_id: int):
    org = next((item for item in user.organizations if item.id == org_id), None)
    if org is None:
        raise OrganizationNotFoundError()
    return org


@router.get("/{org_id}/billing")
async def read_billing(
    org_id: int,
    request: Request,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session),
):
    org = _require_org_member(user, org_id)
    if not user.has_permission(AppPermissions.VIEW_BILLING, org_id):
        raise InsufficientPermissionsError()

    billing = get_org_billing(session, org_id)
    status = billing_status(billing)
    settings = stripe_settings()
    can_manage = user.has_permission(AppPermissions.MANAGE_BILLING, org_id)

    return templates.TemplateResponse(
        request,
        "billing/billing.html",
        {
            "user": user,
            "organization": org,
            "billing": billing,
            "billing_status": status,
            "billing_status_label": billing_status_label(status),
            "plan_name": settings.plan_name,
            "can_manage_billing": can_manage,
            "can_subscribe": can_subscribe_to_billing(
                can_manage=can_manage,
                status=status,
                billing=billing,
            ),
            "can_manage_portal": can_manage_billing_portal(
                can_manage=can_manage,
                billing=billing,
                status=status,
            ),
        },
    )


def _redirect_to_billing(
    request: Request, org_id: int, *, message: str, level: str = "success"
) -> Response:
    response = RedirectResponse(
        url=router.url_path_for("read_billing", org_id=org_id),
        status_code=303,
    )
    set_flash_cookie(response, message, level=level)
    return response


def _redirect_to_stripe(request: Request, url: str) -> Response:
    if is_htmx_request(request):
        response = Response(status_code=200)
        htmx_redirect(response, url)
        return response
    return RedirectResponse(url=url, status_code=303)


@router.post("/{org_id}/billing/checkout")
async def start_checkout(
    org_id: int,
    request: Request,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session),
):
    _require_org_member(user, org_id)
    if not user.has_permission(AppPermissions.MANAGE_BILLING, org_id):
        raise InsufficientPermissionsError()

    if not org_may_start_checkout(session, org_id):
        logger.warning(
            "Checkout blocked for org_id=%s: organization already has an active subscription",
            org_id,
        )
        raise ActiveSubscriptionError()

    assert user.account is not None
    billing = get_org_billing(session, org_id)
    idempotency_key = f"checkout-org-{org_id}-{uuid.uuid4().hex}"
    try:
        checkout = create_checkout_session(
            org_id=org_id,
            owner_email=user.account.email,
            customer_id=billing.stripe_customer_id if billing else None,
            idempotency_key=idempotency_key,
        )
    except stripe.StripeError:
        logger.exception(
            "Stripe Checkout session creation failed for org_id=%s", org_id
        )
        raise StripeServiceUnavailableError("start checkout") from None

    checkout_url = checkout.url
    if not checkout_url:
        raise StripeSessionError("checkout")
    return _redirect_to_stripe(request, checkout_url)


@router.post("/{org_id}/billing/portal")
async def start_customer_portal(
    org_id: int,
    request: Request,
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session),
):
    _require_org_member(user, org_id)
    if not user.has_permission(AppPermissions.MANAGE_BILLING, org_id):
        raise InsufficientPermissionsError()

    billing = get_org_billing(session, org_id)
    if billing is None or not billing.stripe_customer_id:
        raise InsufficientPermissionsError(
            "Subscribe first before managing billing details."
        )

    try:
        portal = create_portal_session(
            org_id=org_id,
            customer_id=billing.stripe_customer_id,
        )
    except stripe.StripeError:
        logger.exception("Stripe Customer Portal session failed for org_id=%s", org_id)
        raise StripeServiceUnavailableError("open billing portal") from None

    portal_url = portal.url
    if not portal_url:
        raise StripeSessionError("portal")
    return _redirect_to_stripe(request, portal_url)


@router.get("/{org_id}/billing/success")
async def billing_checkout_success(
    org_id: int,
    request: Request,
    session_id: str | None = Query(default=None),
    user: User = Depends(get_user_with_relations),
    session: Session = Depends(get_session),
):
    _require_org_member(user, org_id)
    if not session_id:
        return _redirect_to_billing(
            request,
            org_id,
            message="Checkout could not be verified. Check billing status shortly.",
            level="info",
        )

    try:
        checkout_session = retrieve_checkout_session(session_id)
    except stripe.StripeError:
        logger.exception(
            "Failed to verify Stripe checkout session %s for org_id=%s",
            session_id,
            org_id,
        )
        return _redirect_to_billing(
            request,
            org_id,
            message="Checkout could not be verified. Check billing status shortly.",
            level="info",
        )

    checkout_org_id = organization_id_from_metadata(
        getattr(checkout_session, "metadata", None)
    )
    if checkout_org_id is None:
        checkout_org_id = organization_id_from_metadata(
            {"organization_id": getattr(checkout_session, "client_reference_id", None)}
        )
    if checkout_org_id != org_id:
        raise InsufficientPermissionsError(
            "Checkout session does not match organization."
        )

    payment_status = getattr(checkout_session, "payment_status", None)
    checkout_status = getattr(checkout_session, "status", None)
    if payment_status != "paid" and checkout_status != "complete":
        return _redirect_to_billing(
            request,
            org_id,
            message="Checkout is not complete yet. Billing status will update shortly.",
            level="info",
        )

    response = RedirectResponse(
        url=router.url_path_for("read_billing", org_id=org_id),
        status_code=303,
    )
    set_flash_cookie(
        response,
        "Subscription checkout completed. Billing status will update shortly.",
    )
    return response


@router.get("/{org_id}/billing/cancel")
async def billing_checkout_cancel(
    org_id: int,
    request: Request,
    user: User = Depends(get_user_with_relations),
):
    _require_org_member(user, org_id)
    response = RedirectResponse(
        url=router.url_path_for("read_billing", org_id=org_id),
        status_code=303,
    )
    set_flash_cookie(response, "Checkout canceled.", level="info")
    return response


@webhook_router.post("/stripe")
async def stripe_webhook(
    request: Request,
    session: Session = Depends(get_session),
):
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    if not signature:
        logger.warning("Stripe webhook rejected: missing Stripe-Signature header")
        return Response(status_code=400, content="Missing Stripe-Signature header")

    try:
        event = construct_webhook_event(payload, signature)
    except ValueError:
        logger.warning("Stripe webhook rejected: invalid payload")
        return Response(status_code=400, content="Invalid payload")
    except stripe.SignatureVerificationError:
        logger.warning("Stripe webhook rejected: invalid signature")
        return Response(status_code=400, content="Invalid signature")

    if not claim_webhook_event(session, event.id):
        logger.info(
            "Skipping duplicate Stripe webhook event %s (%s)",
            event.id,
            event.type,
        )
        return Response(status_code=200, content='{"ok": true}')

    result = handle_stripe_webhook_event(session, event)
    if result in {WebhookHandleResult.FAILED, WebhookHandleResult.RETRYABLE}:
        release_webhook_event_claim(session, event.id)
        return Response(status_code=500, content="Webhook handler failed")

    return Response(status_code=200, content='{"ok": true}')
