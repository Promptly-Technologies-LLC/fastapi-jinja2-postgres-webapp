import pytest
import subprocess
import time
import os
import socket
from dotenv import load_dotenv
from utils.core.db import get_connection_url, set_up_db, tear_down_db, ensure_database_exists


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


@pytest.fixture(scope="session")
def browser_env():
    """Build an environment dict for the live server subprocess."""
    load_dotenv()
    env = os.environ.copy()
    env["DB_NAME"] = "webapp-browser-test-db"
    env["SECRET_KEY"] = "testsecretkey-that-is-at-least-32-bytes-long"
    env["HOST_NAME"] = "Test Organization"
    env["RESEND_API_KEY"] = "test"
    env["EMAIL_FROM"] = "test@example.com"
    env["BASE_URL"] = "http://127.0.0.1:8113"
    return env


@pytest.fixture(scope="session")
def live_server(browser_env):
    """Start a uvicorn server for Playwright tests and return the base URL."""
    # Apply env so our DB helpers use the right database
    os.environ.update(browser_env)

    ensure_database_exists(get_connection_url())
    set_up_db(drop=True)

    assert _port_free(8113), "Port 8113 already in use"

    proc = subprocess.Popen(
        ["uv", "run", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8113"],
        env=browser_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready
    for _ in range(30):
        if not _port_free(8113):
            break
        time.sleep(0.5)
    else:
        proc.terminate()
        raise RuntimeError("Server did not start within 15 seconds")

    yield "http://127.0.0.1:8113"

    proc.terminate()
    proc.wait(timeout=5)
    tear_down_db()
