import importlib
import time
from unittest.mock import MagicMock, patch

import utils.core.rate_limit as rate_limit_module
from utils.core.rate_limit import PostgresRateLimitWindow, RateLimitWindow, get_client_ip


# ---------------------------------------------------------------------------
# RateLimitWindow — core behaviour
# ---------------------------------------------------------------------------


def test_allows_requests_under_limit():
    limiter = RateLimitWindow(max_attempts=3, window_seconds=60)
    for _ in range(3):
        is_limited, _ = limiter.check("key")
        assert not is_limited
        limiter.record("key")


def test_blocks_once_limit_exceeded():
    limiter = RateLimitWindow(max_attempts=3, window_seconds=60)
    for _ in range(3):
        limiter.record("key")
    is_limited, retry_after = limiter.check("key")
    assert is_limited
    assert retry_after >= 1


def test_different_keys_are_independent():
    limiter = RateLimitWindow(max_attempts=2, window_seconds=60)
    limiter.record("a")
    limiter.record("a")
    assert limiter.check("a")[0] is True
    assert limiter.check("b")[0] is False


def test_remaining_decreases():
    limiter = RateLimitWindow(max_attempts=5, window_seconds=60)
    assert limiter.remaining("key") == 5
    limiter.record("key")
    assert limiter.remaining("key") == 4
    limiter.record("key")
    assert limiter.remaining("key") == 3


def test_reset_clears_key():
    limiter = RateLimitWindow(max_attempts=2, window_seconds=60)
    limiter.record("key")
    limiter.record("key")
    assert limiter.check("key")[0] is True
    limiter.reset("key")
    assert limiter.check("key")[0] is False
    assert limiter.remaining("key") == 2


def test_reset_nonexistent_key_is_noop():
    limiter = RateLimitWindow(max_attempts=2, window_seconds=60)
    limiter.reset("nonexistent")  # should not raise


# ---------------------------------------------------------------------------
# Window expiry
# ---------------------------------------------------------------------------


def test_unblocks_after_window_expiry():
    """Simulate time passing so that old attempts fall outside the window."""
    limiter = RateLimitWindow(max_attempts=2, window_seconds=10)

    base_time = time.monotonic()

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time):
        limiter.record("key")
        limiter.record("key")

    # Still within window
    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time + 5):
        assert limiter.check("key")[0] is True

    # After the window expires
    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time + 11):
        assert limiter.check("key")[0] is False
        assert limiter.remaining("key") == 2


def test_retry_after_is_positive_and_decreases():
    limiter = RateLimitWindow(max_attempts=1, window_seconds=30)

    base_time = 1_000_000.0

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time):
        limiter.record("key")

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time + 5):
        is_limited, retry_after = limiter.check("key")
        assert is_limited
        assert retry_after == 25

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time + 20):
        is_limited, retry_after = limiter.check("key")
        assert is_limited
        assert retry_after == 10


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------


def test_prune_removes_stale_keys():
    limiter = RateLimitWindow(max_attempts=2, window_seconds=10)

    base_time = time.monotonic()

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time):
        limiter.record("stale_key")
        limiter.record("fresh_key")

    # Advance past window for stale_key
    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time + 11):
        # Record fresh_key again so it still has in-window attempts
        limiter.record("fresh_key")
        limiter.prune()

    assert "stale_key" not in limiter._attempts
    assert "fresh_key" in limiter._attempts


def test_prune_on_empty_store():
    limiter = RateLimitWindow(max_attempts=2, window_seconds=10)
    limiter.prune()  # should not raise


def test_access_triggers_periodic_global_prune():
    limiter = RateLimitWindow(
        max_attempts=2,
        window_seconds=10,
        prune_interval_seconds=5,
    )

    base_time = time.monotonic()

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time):
        limiter.record("stale_key")

    with patch("utils.core.rate_limit.time.monotonic", return_value=base_time + 11):
        limiter.record("fresh_key")

    assert "stale_key" not in limiter._attempts
    assert "fresh_key" in limiter._attempts


def test_module_limiters_honor_env_configuration(monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("LOGIN_IP_LIMIT", "17")
        m.setenv("FORGOT_PASSWORD_EMAIL_WINDOW_SECONDS", "91")
        importlib.reload(rate_limit_module)

        assert rate_limit_module.login_ip_limiter.max_attempts == 17
        assert rate_limit_module.forgot_password_email_limiter.window_seconds == 91

    importlib.reload(rate_limit_module)


def test_postgres_rate_limit_window_enforces_limit(engine, env_vars, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "postgres")
    importlib.reload(rate_limit_module)

    limiter = PostgresRateLimitWindow("test_scope", max_attempts=2, window_seconds=60)
    limiter.clear()
    limiter.record("shared-key")
    limiter.record("shared-key")
    assert limiter.check("shared-key")[0] is True

    second = PostgresRateLimitWindow("test_scope", max_attempts=2, window_seconds=60)
    assert second.check("shared-key")[0] is True

    limiter.clear()
    monkeypatch.delenv("RATE_LIMIT_BACKEND", raising=False)
    importlib.reload(rate_limit_module)


# ---------------------------------------------------------------------------
# Client IP behind trusted proxies
# ---------------------------------------------------------------------------


def _make_request(
    peer_host: str | None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    request = MagicMock()
    if peer_host is None:
        request.client = None
    else:
        request.client = MagicMock(host=peer_host)
    request.headers = headers or {}
    return request


def test_get_client_ip_ignores_x_forwarded_for_without_trusted_proxy(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)
    request = _make_request(
        "203.0.113.10",
        headers={"x-forwarded-for": "198.51.100.7"},
    )
    assert get_client_ip(request) == "203.0.113.10"


def test_get_client_ip_uses_x_forwarded_for_from_trusted_proxy(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "127.0.0.1")
    request = _make_request(
        "127.0.0.1",
        headers={"x-forwarded-for": "198.51.100.7, 127.0.0.1"},
    )
    assert get_client_ip(request) == "198.51.100.7"


def test_get_client_ip_falls_back_to_peer_when_x_forwarded_for_missing(
    monkeypatch,
):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "127.0.0.1")
    request = _make_request("127.0.0.1")
    assert get_client_ip(request) == "127.0.0.1"


def test_get_client_ip_unknown_when_peer_missing(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)
    request = _make_request(None)
    assert get_client_ip(request) == "unknown"
