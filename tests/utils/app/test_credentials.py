"""Tests for application credential helpers."""

from __future__ import annotations

import pytest

from utils.app.credentials import billing_enabled, validate_billing_environment


def test_billing_enabled_defaults_to_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BILLING_ENABLED", raising=False)
    assert billing_enabled() is True


def test_billing_enabled_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BILLING_ENABLED", "0")
    assert billing_enabled() is False


def test_validate_billing_skipped_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BILLING_ENABLED", "0")
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    validate_billing_environment()


def test_validate_billing_raises_when_enabled_and_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BILLING_ENABLED", "1")
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_ID", raising=False)
    monkeypatch.delenv("BASE_URL", raising=False)
    with pytest.raises(ValueError, match="Missing billing environment variables"):
        validate_billing_environment()
