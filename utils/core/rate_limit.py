import os
import time
import threading
import math
from datetime import UTC, datetime, timedelta
import ipaddress
from logging import getLogger
from typing import Protocol, Tuple, runtime_checkable

from fastapi import Request, Form
from pydantic import EmailStr
from dotenv import load_dotenv
from sqlmodel import Session, col, create_engine, delete, select

from utils.core.db import get_connection_url
from utils.core.models import RateLimitAttempt

logger = getLogger("uvicorn.error")
load_dotenv()

_rate_limit_engine = None


def _get_rate_limit_engine():
    global _rate_limit_engine
    if _rate_limit_engine is None:
        _rate_limit_engine = create_engine(get_connection_url())
    return _rate_limit_engine


@runtime_checkable
class RateLimiter(Protocol):
    max_attempts: int
    window_seconds: int

    def check(self, key: str) -> Tuple[bool, int]: ...

    def record(self, key: str) -> None: ...

    def remaining(self, key: str) -> int: ...

    def reset(self, key: str) -> None: ...

    def prune(self) -> None: ...

    def clear(self) -> None: ...


def get_trusted_proxy_hosts() -> tuple[str, ...]:
    """
    Return trusted reverse-proxy peer addresses from TRUSTED_PROXY_IPS.

    Comma-separated list, e.g. ``127.0.0.1,::1,172.18.0.2``.
    """
    raw = os.environ.get("TRUSTED_PROXY_IPS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _peer_host(request: Request) -> str | None:
    if request.client is None:
        return None
    return request.client.host


def _parse_forwarded_client_ip(forwarded_for: str) -> str | None:
    for candidate in forwarded_for.split(","):
        value = candidate.strip()
        if not value:
            continue
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            continue
    return None


def get_client_ip(request: Request) -> str:
    """
    Extract the client IP for rate limiting.

    When the immediate peer is listed in TRUSTED_PROXY_IPS, the left-most
    valid address in X-Forwarded-For is treated as the client. Otherwise only
    request.client.host is used so clients cannot spoof their IP.
    """
    peer = _peer_host(request)
    if peer is None:
        return "unknown"

    trusted_hosts = get_trusted_proxy_hosts()
    if peer not in trusted_hosts:
        return peer

    forwarded_for = request.headers.get("x-forwarded-for")
    if not forwarded_for:
        return peer

    client_ip = _parse_forwarded_client_ip(forwarded_for)
    return client_ip or peer


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
            key
            for key, timestamps in self._attempts.items()
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

    def clear(self) -> None:
        """Clear all recorded attempts."""
        with self._lock:
            self._attempts.clear()


class PostgresRateLimitWindow:
    """
    Sliding-window rate limiter backed by PostgreSQL.

    Use when running multiple workers or replicas so configured limits apply
    cluster-wide instead of per process.
    """

    def __init__(self, scope: str, max_attempts: int, window_seconds: int):
        self.scope = scope
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    def _cutoff(self, now: datetime) -> datetime:
        return now - timedelta(seconds=self.window_seconds)

    def _recent_attempts(self, session: Session, key: str, now: datetime):
        return session.exec(
            select(RateLimitAttempt)
            .where(
                col(RateLimitAttempt.scope) == self.scope,
                col(RateLimitAttempt.key) == key,
                col(RateLimitAttempt.attempted_at) > self._cutoff(now),
            )
            .order_by(col(RateLimitAttempt.attempted_at))
        ).all()

    def check(self, key: str) -> Tuple[bool, int]:
        now = datetime.now(UTC)
        with Session(_get_rate_limit_engine()) as session:
            attempts = self._recent_attempts(session, key, now)
            if len(attempts) >= self.max_attempts:
                oldest = attempts[0].attempted_at
                if oldest.tzinfo is None:
                    oldest = oldest.replace(tzinfo=UTC)
                retry_after = math.ceil(
                    (
                        oldest + timedelta(seconds=self.window_seconds) - now
                    ).total_seconds()
                )
                return True, max(retry_after, 1)
            return False, 0

    def record(self, key: str) -> None:
        with Session(_get_rate_limit_engine()) as session:
            session.add(
                RateLimitAttempt(
                    scope=self.scope, key=key, attempted_at=datetime.now(UTC)
                )
            )
            session.commit()

    def remaining(self, key: str) -> int:
        now = datetime.now(UTC)
        with Session(_get_rate_limit_engine()) as session:
            attempts = self._recent_attempts(session, key, now)
            return max(0, self.max_attempts - len(attempts))

    def reset(self, key: str) -> None:
        with Session(_get_rate_limit_engine()) as session:
            session.exec(
                delete(RateLimitAttempt).where(
                    col(RateLimitAttempt.scope) == self.scope,
                    col(RateLimitAttempt.key) == key,
                )
            )
            session.commit()

    def prune(self) -> None:
        cutoff = self._cutoff(datetime.now(UTC))
        with Session(_get_rate_limit_engine()) as session:
            session.exec(
                delete(RateLimitAttempt).where(
                    col(RateLimitAttempt.scope) == self.scope,
                    col(RateLimitAttempt.attempted_at) <= cutoff,
                )
            )
            session.commit()

    def clear(self) -> None:
        with Session(_get_rate_limit_engine()) as session:
            session.exec(
                delete(RateLimitAttempt).where(
                    col(RateLimitAttempt.scope) == self.scope
                )
            )
            session.commit()


# --- Configuration helpers ---


def _int_env(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is not None:
        try:
            return int(val)
        except ValueError:
            logger.warning(
                f"Invalid integer for {name}={val!r}, using default {default}"
            )
    return default


def _rate_limit_backend() -> str:
    return os.environ.get("RATE_LIMIT_BACKEND", "memory").lower()


def _make_rate_limiter(
    scope: str, max_attempts: int, window_seconds: int
) -> RateLimiter:
    if _rate_limit_backend() == "postgres":
        return PostgresRateLimitWindow(scope, max_attempts, window_seconds)
    return RateLimitWindow(max_attempts=max_attempts, window_seconds=window_seconds)


# --- Shared limiter instances ---

login_ip_limiter = _make_rate_limiter(
    "login_ip",
    max_attempts=_int_env("LOGIN_IP_LIMIT", 10),
    window_seconds=_int_env("LOGIN_IP_WINDOW_SECONDS", 60),
)
login_email_limiter = _make_rate_limiter(
    "login_email",
    max_attempts=_int_env("LOGIN_EMAIL_LIMIT", 5),
    window_seconds=_int_env("LOGIN_EMAIL_WINDOW_SECONDS", 60),
)
register_ip_limiter = _make_rate_limiter(
    "register_ip",
    max_attempts=_int_env("REGISTER_IP_LIMIT", 5),
    window_seconds=_int_env("REGISTER_IP_WINDOW_SECONDS", 60),
)
forgot_password_ip_limiter = _make_rate_limiter(
    "forgot_password_ip",
    max_attempts=_int_env("FORGOT_PASSWORD_IP_LIMIT", 5),
    window_seconds=_int_env("FORGOT_PASSWORD_IP_WINDOW_SECONDS", 60),
)
forgot_password_email_limiter = _make_rate_limiter(
    "forgot_password_email",
    max_attempts=_int_env("FORGOT_PASSWORD_EMAIL_LIMIT", 3),
    window_seconds=_int_env("FORGOT_PASSWORD_EMAIL_WINDOW_SECONDS", 60),
)

_ALL_LIMITERS = (
    login_ip_limiter,
    login_email_limiter,
    register_ip_limiter,
    forgot_password_ip_limiter,
    forgot_password_email_limiter,
)


def clear_all_rate_limiters() -> None:
    """Clear all rate limiter state for the active backend."""
    for limiter in _ALL_LIMITERS:
        limiter.clear()


# --- Dependency helpers ---


def _enforce_rate_limit(limiter: RateLimiter, key: str, scope: str) -> int:
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
