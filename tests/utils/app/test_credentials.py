"""Tests for application credential helpers."""

from __future__ import annotations

import pytest

from utils.app.credentials import validate_billing_environment


def test_validate_billing_raises_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_ID", raising=False)
    monkeypatch.delenv("BASE_URL", raising=False)
    with pytest.raises(ValueError, match="Missing billing environment variables"):
        validate_billing_environment()


def test_validate_billing_passes_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_dummy")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_dummy")
    monkeypatch.setenv("STRIPE_PRICE_ID", "price_test_dummy")
    monkeypatch.setenv("BASE_URL", "http://localhost:8000")
    validate_billing_environment()
