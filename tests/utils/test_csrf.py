from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from main import app
from utils.core.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    generate_csrf_token,
    validate_csrf_token,
)


def test_validate_csrf_token_accepts_matching_values():
    request = MagicMock()
    token = generate_csrf_token()
    request.state.csrf_token = token
    assert validate_csrf_token(request, token) is True


def test_validate_csrf_token_rejects_mismatch():
    request = MagicMock()
    request.state.csrf_token = generate_csrf_token()
    assert validate_csrf_token(request, generate_csrf_token()) is False


def test_post_without_csrf_rejected_when_enabled(
    unauth_client: TestClient, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = generate_csrf_token()
    unauth_client.cookies.set(CSRF_COOKIE_NAME, token)

    response = unauth_client.post(
        app.url_path_for("login"),
        data={"email": "test@example.com", "password": "Password123!@#"},
    )

    assert response.status_code == 403


def test_post_with_form_csrf_accepted_when_enabled(
    unauth_client: TestClient, test_account, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = generate_csrf_token()
    unauth_client.cookies.set(CSRF_COOKIE_NAME, token)

    response = unauth_client.post(
        app.url_path_for("login"),
        data={
            CSRF_FORM_FIELD: token,
            "email": test_account.email,
            "password": "Test123!@#",
        },
        follow_redirects=False,
    )

    assert response.status_code != 403


def test_post_with_header_csrf_accepted_when_enabled(
    unauth_client: TestClient, monkeypatch
):
    monkeypatch.setenv("CSRF_ENABLED", "1")
    token = generate_csrf_token()
    unauth_client.cookies.set(CSRF_COOKIE_NAME, token)

    response = unauth_client.post(
        app.url_path_for("forgot_password"),
        data={"email": "missing@example.com"},
        headers={CSRF_HEADER_NAME: token},
    )

    assert response.status_code != 403
