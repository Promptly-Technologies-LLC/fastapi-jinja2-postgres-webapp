"""Tests for public website lead forms."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from main import app
from utils.core.csrf import CSRF_COOKIE_NAME, generate_csrf_token


def _url(name: str, **path_params) -> str:
    return str(app.url_path_for(name, **path_params))


def _csrf_client(client):
    token = generate_csrf_token()
    client.cookies.set(CSRF_COOKIE_NAME, token)
    return token


@pytest.fixture
def demo_form_data() -> dict[str, str]:
    return {
        "work_email": "jordan@summitair.com",
        "first_name": "Jordan",
        "last_name": "Diaz",
        "company": "Summit Air & Heating",
        "trade": "HVAC",
        "phone": "(518) 555-0142",
        "technicians": "2-5",
        "phone_answerer": "office_voicemail",
    }


@pytest.fixture
def call_me_form_data() -> dict[str, str]:
    return {
        "name": "Jordan Diaz",
        "business": "Summit Air & Heating",
        "email": "jordan@summitair.com",
        "phone": "(518) 555-0142",
        "industry": "HVAC",
        "crm": "",
    }


def test_read_demo_page_renders(unauth_client):
    response = unauth_client.get(_url("read_demo"))
    assert response.status_code == 200
    assert "Book a demo" in response.text
    assert "Calli picks up." in response.text
    assert 'name="work_email"' in response.text


@patch("resend.Emails.send")
def test_submit_book_demo_success_redirects(
    mock_send,
    unauth_client,
    demo_form_data,
    mock_email_response,
):
    mock_send.return_value = mock_email_response
    token = _csrf_client(unauth_client)
    response = unauth_client.post(
        _url("submit_book_demo"),
        data={**demo_form_data, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("/demo")
    mock_send.assert_called_once()


@patch("resend.Emails.send")
def test_submit_book_demo_validation_error_rerenders_form(
    mock_send,
    unauth_client,
    demo_form_data,
):
    token = _csrf_client(unauth_client)
    invalid = {**demo_form_data, "work_email": "not-an-email"}
    response = unauth_client.post(
        _url("submit_book_demo"),
        data={**invalid, "csrf_token": token},
    )
    assert response.status_code == 422
    assert 'name="work_email"' in response.text
    mock_send.assert_not_called()


@patch("resend.Emails.send")
def test_submit_call_me_success_redirects_home(
    mock_send,
    unauth_client,
    call_me_form_data,
    mock_email_response,
):
    mock_send.return_value = mock_email_response
    token = _csrf_client(unauth_client)
    response = unauth_client.post(
        _url("submit_call_me"),
        data={**call_me_form_data, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("/#call-me")
    mock_send.assert_called_once()


@patch("resend.Emails.send")
def test_submit_call_me_validation_error_redirects_with_flash(
    mock_send,
    unauth_client,
    call_me_form_data,
):
    token = _csrf_client(unauth_client)
    invalid = {**call_me_form_data, "phone": "bad"}
    response = unauth_client.post(
        _url("submit_call_me"),
        data={**invalid, "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "flash_message=" in response.headers.get("set-cookie", "")
    mock_send.assert_not_called()
