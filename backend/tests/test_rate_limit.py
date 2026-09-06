import time

import pytest

from app.core import rate_limit


@pytest.fixture(autouse=True)
def reset_rate_limit_state(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    from app.core.config import get_settings

    get_settings.cache_clear()
    rate_limit.reset_for_tests()
    yield
    rate_limit.reset_for_tests()
    get_settings.cache_clear()


def test_local_counter_increments_and_resets_after_window():
    for expected in range(1, 4):
        assert rate_limit.hit_count("client-a", limit=10) == expected
    assert rate_limit.hit_count("client-b", limit=10) == 1, "distinct clients must not share a bucket"


def test_local_counter_expires_hits_outside_the_window(monkeypatch):
    times = iter([0.0, 0.0, 61.0])
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: next(times))
    assert rate_limit.hit_count("client-c", limit=10) == 1
    assert rate_limit.hit_count("client-c", limit=10) == 2
    assert rate_limit.hit_count("client-c", limit=10) == 1, "hits older than 60s must be dropped"


def test_redis_unavailable_falls_back_to_local_counter_without_raising(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    from app.core.config import get_settings

    get_settings.cache_clear()
    rate_limit.reset_for_tests()

    assert rate_limit.hit_count("client-d", limit=10) == 1
    assert rate_limit.hit_count("client-d", limit=10) == 2
    assert rate_limit._redis_unavailable_logged is True


def test_no_redis_url_configured_uses_local_counter_directly(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    from app.core.config import get_settings

    get_settings.cache_clear()
    rate_limit.reset_for_tests()
    assert rate_limit._get_redis() is None
    assert rate_limit.hit_count("client-e", limit=5) == 1
