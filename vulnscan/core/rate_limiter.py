from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token-bucket rate limiter."""

    def __init__(self, rps: float = 10.0) -> None:
        self._rps = max(rps, 0.1)
        self._tokens: float = self._rps
        self._last_refill: float = time.monotonic()
        self._lock: asyncio.Lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rps, self._tokens + elapsed * self._rps)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            wait_time = (1.0 - self._tokens) / self._rps

        await asyncio.sleep(wait_time)

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._rps, self._tokens + elapsed * self._rps)
            self._last_refill = now
            self._tokens = max(0.0, self._tokens - 1.0)
