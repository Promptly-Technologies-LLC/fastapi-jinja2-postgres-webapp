import os
import time
import threading
import math
from logging import getLogger
from typing import Tuple

from fastapi import Request, Form
from pydantic import EmailStr
from dotenv import load_dotenv

logger = getLogger("uvicorn.error")
load_dotenv()


class RateLimitWindow:
    """
    Thread-safe sliding window rate limiter with bounded in-memory state.

    Tracks timestamps of attempts per key. Rejects requests that exceed
    `max_attempts` within `window_seconds`. Stale keys are pruned on
    every access and via an explicit `prune()` method.
    """

    def __init__(
        self,
        max_attempts: int,
        window_seconds: int,
        prune_interval_seconds: int = 30,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.prune_interval_seconds = prune_interval_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._next_prune_at = time.monotonic() + prune_interval_seconds

    def _cleanup_key(self, key: str, now: float) -> None:
        """Remove expired timestamps for a single key. Delete the key if empty."""
        cutoff = now - self.window_seconds
        if key in self._attempts:
            self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
            if not self._attempts[key]:
                del self._attempts[key]

    def _prune_stale_keys(self, now: float) -> None:
        """Remove stale keys across the whole store."""
        cutoff = now - self.window_seconds
        stale_keys = [
            key for key, timestamps in self._attempts.items()
            if all(timestamp <= cutoff for timestamp in timestamps)
        ]
        for key in stale_keys:
            del self._attempts[key]

    def _maybe_prune(self, now: float) -> None:
        """
        Opportunistically prune stale one-off keys during normal access.

        This prevents memory from growing without bound when many keys are
        never touched again after their window expires.
        """
        if now < self._next_prune_at:
            return
        self._prune_stale_keys(now)
        self._next_prune_at = now + self.prune_interval_seconds

    def check(self, key: str) -> Tuple[bool, int]:
        """
        Check whether a key is currently rate-limited.

        Returns:
            (is_limited, retry_after_seconds)
            retry_after_seconds is 0 when not limited.
        """
        now = time.monotonic()
        with self._lock:
            self._maybe_prune(now)
            self._cleanup_key(key, now)
            attempts = self._attempts.get(key, [])
            if len(attempts) >= self.max_attempts:
                oldest_relevant = attempts[0]
                retry_after = math.ceil((oldest_relevant + self.window_seconds) - now)
                return True, max(retry_after, 1)
            return False, 0

    def record(self, key: str) -> None:
        """Record an attempt for a key."""
        now = time.monotonic()
        with self._lock:
            self._maybe_prune(now)
            self._cleanup_key(key, now)
            if key not in self._attempts:
                self._attempts[key] = []
            self._attempts[key].append(now)

    def remaining(self, key: str) -> int:
        """Return the number of attempts remaining before the key is limited."""
        now = time.monotonic()
        with self._lock:
            self._maybe_prune(now)
            self._cleanup_key(key, now)
            return max(0, self.max_attempts - len(self._attempts.get(key, [])))

    def reset(self, key: str) -> None:
        """Clear all recorded attempts for a key."""
        with self._lock:
            self._attempts.pop(key, None)

    def prune(self) -> None:
        """Remove all stale keys. Call periodically to bound memory growth."""
        now = time.monotonic()
        with self._lock:
            self._prune_stale_keys(now)
            self._next_prune_at = now + self.prune_interval_seconds


# --- Configuration helpers ---

def _int_env(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            logger.warning(f"Invalid integer for {name}={val!r}, using default {default}")
    return default


# --- Shared limiter instances ---

login_ip_limiter = RateLimitWindow(
    max_attempts=_int_env("LOGIN_IP_LIMIT", 10),
    window_seconds=_int_env("LOGIN_IP_WINDOW_SECONDS", 60),
)
login_email_limiter = RateLimitWindow(
    max_attempts=_int_env("LOGIN_EMAIL_LIMIT", 5),
    window_seconds=_int_env("LOGIN_EMAIL_WINDOW_SECONDS", 60),
)
register_ip_limiter = RateLimitWindow(
    max_attempts=_int_env("REGISTER_IP_LIMIT", 5),
    window_seconds=_int_env("REGISTER_IP_WINDOW_SECONDS", 60),
)
forgot_password_ip_limiter = RateLimitWindow(
    max_attempts=_int_env("FORGOT_PASSWORD_IP_LIMIT", 5),
    window_seconds=_int_env("FORGOT_PASSWORD_IP_WINDOW_SECONDS", 60),
)
forgot_password_email_limiter = RateLimitWindow(
    max_attempts=_int_env("FORGOT_PASSWORD_EMAIL_LIMIT", 3),
    window_seconds=_int_env("FORGOT_PASSWORD_EMAIL_WINDOW_SECONDS", 60),
)


# --- Dependency helpers ---

def get_client_ip(request: Request) -> str:
    """
    Extract client IP from the request.

    Uses request.client.host only. Does NOT trust X-Forwarded-For
    because this app has no trusted-proxy middleware.
    """
    if request.client:
        return request.client.host
    return "unknown"


def _enforce_rate_limit(limiter: RateLimitWindow, key: str, scope: str) -> int:
    """
    Check the limiter for the given key. If limited, raise RateLimitError.
    Otherwise, record the attempt and return.

    Returns the retry_after value (0 when not limited).
    """
    from exceptions.http_exceptions import RateLimitError

    is_limited, retry_after = limiter.check(key)
    if is_limited:
        logger.warning(f"Rate limit exceeded: scope={scope} key={key}")
        raise RateLimitError(retry_after=retry_after)
    limiter.record(key)
    return 0


# --- Per-endpoint FastAPI dependencies ---

def check_login_ip_rate_limit(request: Request) -> None:
    ip = get_client_ip(request)
    _enforce_rate_limit(login_ip_limiter, f"ip:{ip}", "login_ip")


def check_login_email_rate_limit(email: EmailStr = Form(...)) -> EmailStr:
    normalized = email.lower().strip()
    _enforce_rate_limit(login_email_limiter, f"email:{normalized}", "login_email")
    return email


def check_register_ip_rate_limit(request: Request) -> None:
    ip = get_client_ip(request)
    _enforce_rate_limit(register_ip_limiter, f"ip:{ip}", "register_ip")


def check_forgot_password_ip_rate_limit(request: Request) -> None:
    ip = get_client_ip(request)
    _enforce_rate_limit(forgot_password_ip_limiter, f"ip:{ip}", "forgot_password_ip")


def check_forgot_password_email_rate_limit(email: EmailStr = Form(...)) -> EmailStr:
    normalized = email.lower().strip()
    _enforce_rate_limit(
        forgot_password_email_limiter, f"email:{normalized}", "forgot_password_email"
    )
    return email
