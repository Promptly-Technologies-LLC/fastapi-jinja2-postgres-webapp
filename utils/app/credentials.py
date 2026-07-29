"""Environment validation for application-specific services."""

from __future__ import annotations

import os


def validate_billing_environment() -> None:
    """Ensure required Stripe billing environment variables are set."""
    required = (
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_ID",
        "BASE_URL",
    )
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise ValueError("Missing billing environment variables: " + ", ".join(missing))
