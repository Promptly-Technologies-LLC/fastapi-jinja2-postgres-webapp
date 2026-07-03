"""Environment validation for application-specific services."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def billing_enabled() -> bool:
    """Return True unless billing is explicitly disabled via BILLING_ENABLED=0."""
    raw = os.getenv("BILLING_ENABLED", "1").lower()
    return raw not in {"0", "false", "no"}


def validate_billing_environment() -> None:
    """Ensure Stripe billing env vars are present when billing is enabled."""
    if not billing_enabled():
        return
    required = (
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_ID",
        "BASE_URL",
    )
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise ValueError("Missing billing environment variables: " + ", ".join(missing))
