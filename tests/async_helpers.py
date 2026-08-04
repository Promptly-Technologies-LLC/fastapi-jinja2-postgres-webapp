"""Shared helpers for driving async code from sync tests."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Coroutine, TypeVar

T = TypeVar("T")


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """Drive an async helper from sync tests.

    The full suite may already have an event loop (e.g. after Playwright), so
    asyncio.run() on the main thread can fail. Always run in a fresh thread.
    """

    def _runner() -> T:
        return asyncio.run(coro)

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_runner).result()
