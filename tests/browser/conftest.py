import os
import socket
import subprocess
import time
from contextlib import contextmanager

import pytest
from playwright.sync_api import Browser, Page
from tests.browser.db_helpers import browser_db_env
from utils.core.db import (
    ensure_database_exists,
    get_connection_url,
    set_up_db,
    tear_down_db,
)


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


@contextmanager
def _temporary_env(env: dict[str, str]):
    """Apply env vars for DB helpers without leaking into the pytest process."""
    saved = {key: os.environ.get(key) for key in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def register_user(
    browser: Browser,
    live_server: str,
    *,
    name: str,
    email: str,
    password: str,
) -> None:
    """Register a user through the live server UI (session-scoped helper)."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server}/account/register")
    page.fill("#name", name)
    page.fill("#email", email)
    page.fill("#password", password)
    page.fill("#confirm_password", password)
    page.click('button[type="submit"]')
    page.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    context.close()


def login_user(
    browser: Browser,
    live_server: str,
    *,
    email: str,
    password: str,
) -> Page:
    """Log in via the live server and return a page on the dashboard."""
    context = browser.new_context(viewport={"width": 1280, "height": 720})
    page = context.new_page()
    page.goto(f"{live_server}/account/login")
    page.fill("#email", email)
    page.fill("#password", password)
    page.click('button[type="submit"]')
    page.wait_for_function(
        "window.location.pathname.startsWith('/dashboard')", timeout=10_000
    )
    return page


def _apply_rate_limit_env(env: dict[str, str]) -> dict[str, str]:
    env["LOGIN_IP_LIMIT"] = "500"
    env["LOGIN_EMAIL_LIMIT"] = "500"
    env["REGISTER_IP_LIMIT"] = "500"
    env["FORGOT_PASSWORD_IP_LIMIT"] = "500"
    env["FORGOT_PASSWORD_EMAIL_LIMIT"] = "500"
    return env


def _start_live_server(env: dict[str, str], port: int) -> subprocess.Popen:
    assert _port_free(port), f"Port {port} already in use"
    with _temporary_env(env):
        ensure_database_exists(get_connection_url())
        set_up_db(drop=True)

    proc = subprocess.Popen(
        [
            "uv",
            "run",
            "uvicorn",
            "main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    for _ in range(30):
        if not _port_free(port):
            break
        time.sleep(0.5)
    else:
        proc.terminate()
        raise RuntimeError(f"Server did not start on port {port} within 15 seconds")
    return proc


_STRIPE_BROWSER_ENV = {
    "STRIPE_SECRET_KEY": "sk_test_dummy",
    "STRIPE_WEBHOOK_SECRET": "whsec_test_dummy",
    "STRIPE_PRICE_ID": "price_test_dummy",
    "STRIPE_PLAN_NAME": "Pro",
    "STRIPE_TAX_ENABLED": "0",
}


@pytest.fixture(scope="session")
def browser_env():
    """Build an environment dict for the live server subprocess."""
    env = _apply_rate_limit_env(browser_db_env())
    env["BASE_URL"] = "http://127.0.0.1:8113"
    env.update(_STRIPE_BROWSER_ENV)
    env["CSRF_ENABLED"] = "0"
    return env


@pytest.fixture(scope="session")
def browser_csrf_env():
    """Live-server env with CSRF protection enabled (separate port/DB)."""
    env = _apply_rate_limit_env(browser_db_env())
    env["DB_NAME"] = "webapp-browser-csrf-test-db"
    env["BASE_URL"] = "http://127.0.0.1:8114"
    env.update(_STRIPE_BROWSER_ENV)
    env["CSRF_ENABLED"] = "1"
    return env


@pytest.fixture(scope="session")
def live_server(browser_env):
    """Start a uvicorn server for Playwright tests and return the base URL."""
    proc = _start_live_server(browser_env, 8113)
    try:
        yield "http://127.0.0.1:8113"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        with _temporary_env(browser_env):
            tear_down_db()


@pytest.fixture(scope="session")
def live_server_csrf(browser_csrf_env):
    """Live server with CSRF_ENABLED=1 for CSRF browser tests."""
    proc = _start_live_server(browser_csrf_env, 8114)
    try:
        yield "http://127.0.0.1:8114"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        with _temporary_env(browser_csrf_env):
            tear_down_db()
