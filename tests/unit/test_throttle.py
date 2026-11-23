"""Deterministic pacing tests: the limiter reserves slots, not sleeps after."""

from __future__ import annotations

import random

import pytest

from core.throttle import RateLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        self.now += seconds


def make_limiter(fake: FakeClock, **kwargs: object) -> RateLimiter:
    return RateLimiter(clock=fake.clock, sleep=fake.sleep, **kwargs)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_disabled_limiter_never_sleeps() -> None:
    fake = FakeClock()
    limiter = make_limiter(fake)
    for _ in range(5):
        await limiter.wait()
    assert fake.sleeps == []
    assert limiter.enabled is False


@pytest.mark.asyncio
async def test_rps_sets_a_shared_schedule() -> None:
    fake = FakeClock()
    limiter = make_limiter(fake, rps=10.0)  # 0.1 s between request starts
    await limiter.wait()  # first slot is free
    await limiter.wait()
    await limiter.wait()
    assert fake.sleeps == [0.1, 0.1]
    assert fake.now == pytest.approx(0.2)


@pytest.mark.asyncio
async def test_explicit_delay_wins_when_larger_than_rps_interval() -> None:
    fake = FakeClock()
    limiter = make_limiter(fake, rps=100.0, delay=0.5)
    await limiter.wait()
    await limiter.wait()
    assert fake.sleeps == [0.5]


@pytest.mark.asyncio
async def test_jitter_is_bounded_and_deterministic_with_seeded_rng() -> None:
    fake = FakeClock()
    limiter = make_limiter(
        fake,
        delay=0.1,
        jitter=0.2,
        random_source=random.Random(1234),
    )
    await limiter.wait()
    await limiter.wait()
    await limiter.wait()
    assert fake.sleeps
    for observed in fake.sleeps:
        assert 0.1 <= observed <= 0.3
    # Gaps include interval + uniform jitter, so they differ across calls.
    assert len(set(fake.sleeps)) > 1
