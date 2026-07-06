"""Fixtures shared by frontend GET and redirect integration tests."""

from __future__ import annotations

import pytest
from datetime import UTC, datetime, timedelta

from utils.core.models import AccountRecoveryToken, PasswordResetToken


@pytest.fixture
def password_reset_credentials(session, test_account):
    """Valid email/token pair for GET /account/reset_password."""
    reset_token = PasswordResetToken(account_id=test_account.id)
    session.add(reset_token)
    session.commit()
    session.refresh(reset_token)
    return test_account.email, reset_token.token


@pytest.fixture
def account_recovery_token(session, test_account):
    """Valid recovery token for GET /account/recover."""
    token = AccountRecoveryToken(
        account_id=test_account.id,
        email=test_account.email,
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=7),
    )
    session.add(token)
    session.commit()
    session.refresh(token)
    return token.token
