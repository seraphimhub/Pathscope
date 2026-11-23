"""Client-side pacing for polite crawling.

``RateLimiter`` reserves request slots rather than sleeping after the fact, so
concurrent workers queue behind one shared schedule instead of each applying
its own delay (which would multiply the effective request rate).
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from typing import Any


class RateLimiter:
    """Serialize request starts according to ``rps``, ``delay``, and jitter."""

    def __init__(
        self,
        *,
        rps: float = 0.0,
        delay: float = 0.0,
        jitter: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Any] = asyncio.sleep,
        random_source: random.Random | None = None,
    ) -> None:
        self.rps = max(0.0, rps)
        self.delay = max(0.0, delay)
        self.jitter = max(0.0, jitter)
        self._clock = clock
        self._sleep = sleep
        # Jitter only spreads requests in time; unpredictability has no security
        # role here, unlike tokens or IDs.
        self._random = random_source or random.Random()  # nosec B311
        rps_interval = 1.0 / self.rps if self.rps > 0 else 0.0
        self._interval = max(self.delay, rps_interval)
        self._next_slot = 0.0

    @property
    def enabled(self) -> bool:
        """True when the limiter would ever make a caller wait."""
        return self._interval > 0 or self.jitter > 0

    async def wait(self) -> None:
        """Wait until this caller may start its request."""
        if not self.enabled:
            return
        now = self._clock()
        slot = max(now, self._next_slot)
        gap = self._interval + (self._random.uniform(0.0, self.jitter) if self.jitter else 0.0)
        self._next_slot = slot + gap
        pause = slot - now
        if pause > 0:
            await self._sleep(pause)
