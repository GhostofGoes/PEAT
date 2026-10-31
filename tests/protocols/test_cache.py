import json
import random
import threading
import time

import pytest

from peat import config, state
from peat.protocols.cache import CacheKey, DataCache, data_cache


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def key(resource="a", namespace="http", host="192.0.2.1", port=80, variant="") -> CacheKey:
    return CacheKey(namespace, host, port, resource, variant)


def make_cache(**kwargs) -> DataCache:
    options = {"enabled": True, "ttl": 10.0, "max_entries": 100, "max_bytes": 8 * 10000}
    options.update(kwargs)
    return DataCache(**options)


def wait_for_followers(cache: DataCache, k: CacheKey, count: int = 1) -> None:
    """Wait until ``count`` threads are waiting for the in-flight fetch of ``k``."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with cache._lock:
            flight = cache._inflight.get(k)
        if flight is not None and len(flight.done._cond._waiters) >= count:
            return
        time.sleep(0.001)
    raise AssertionError("followers did not start waiting")


def start_leader(cache: DataCache, k: CacheKey, fetch_result, results: list, errors: list):
    """Start a thread that fetches ``k`` and blocks until the returned gate is set."""
    gate = threading.Event()
    started = threading.Event()
    calls = []

    def _fetch():
        calls.append(1)
        started.set()
        assert gate.wait(5)
        if isinstance(fetch_result, Exception):
            raise fetch_result
        return fetch_result

    def _run():
        try:
            results.append(cache.get_or_fetch(k, _fetch))
        except Exception as ex:
            errors.append(ex)

    thread = threading.Thread(target=_run)
    thread.start()
    assert started.wait(5)
    return thread, gate, calls


def test_cache_key_label_excludes_variant():
    k = key(variant="secret-digest")
    assert k.label == "http://192.0.2.1:80 a"
    assert "secret" not in k.label


def test_hit_miss_and_ttl_expiry():
    clock = FakeClock()
    cache = make_cache(clock=clock)
    calls = []

    def fetch():
        calls.append(1)
        return "value"

    first = cache.get_or_fetch(key(), fetch)
    assert first.status == "miss"
    assert not first.from_cache
    second = cache.get_or_fetch(key(), fetch)
    assert second.status == "hit"
    assert second.from_cache
    assert second.value == "value"
    assert second.age == 0.0

    clock.now += 9.9
    assert cache.get_or_fetch(key(), fetch).age == pytest.approx(9.9)
    assert key() in cache

    clock.now += 0.1  # exactly the TTL: expired
    assert key() not in cache
    assert cache.get_or_fetch(key(), fetch).status == "miss"
    assert len(calls) == 2
    assert cache.stats()["by_namespace"]["http"]["expired"] == 1


def test_per_call_ttl():
    clock = FakeClock()
    cache = make_cache(clock=clock)
    cache.get_or_fetch(key(), lambda: "v", ttl=1.0)
    clock.now += 1.0
    assert cache.get(key()) is None
    # ttl of 0 means "don't use the cache"
    assert cache.get_or_fetch(key("b"), lambda: "v", ttl=0).status == "bypass"
    assert key("b") not in cache


def test_variant_isolation():
    cache = make_cache()
    assert cache.get_or_fetch(key(variant="user1"), lambda: "A").value == "A"
    assert cache.get_or_fetch(key(variant="user2"), lambda: "B").value == "B"
    assert cache.get_or_fetch(key(variant="user1"), lambda: "X").value == "A"
    assert cache.get_or_fetch(key(variant="user2"), lambda: "X").value == "B"
    assert cache.get_or_fetch(key(port=8080, variant="user1"), lambda: "C").value == "C"


def test_none_and_store_if_false_not_stored():
    cache = make_cache()
    assert cache.get_or_fetch(key("n"), lambda: None).status == "miss"
    assert key("n") not in cache
    r = cache.get_or_fetch(key("e"), lambda: b"", store_if=bool)
    assert r.status == "miss"
    assert key("e") not in cache
    assert cache.put(key("p"), None) is False
    assert cache.stats()["by_namespace"]["http"]["not_stored"] == 2


def test_store_if_and_size_of_errors_do_not_break_fetch():
    cache = make_cache()

    def bad(_value):
        raise ValueError("bad")

    assert cache.get_or_fetch(key("a"), lambda: "v", store_if=bad).value == "v"
    assert cache.get_or_fetch(key("b"), lambda: "v", size_of=bad).value == "v"
    assert len(cache) == 0


def test_copier_isolation():
    cache = make_cache()
    original = {"x": 1}
    first = cache.get_or_fetch(key(), lambda: original, copier=dict)
    assert first.value is original  # the caller that fetched gets the original
    original["x"] = 99  # doesn't affect the stored copy
    got = cache.get_or_fetch(key(), lambda: None, copier=dict).value
    got["x"] = 2
    assert cache.get_or_fetch(key(), lambda: None, copier=dict).value == {"x": 1}
    assert cache.get(key(), copier=dict) == {"x": 1}


def test_copier_failure_on_hit_refetches():
    cache = make_cache()
    fail = []

    def copier(value):
        if fail:
            raise RuntimeError("copy failed")
        return value

    cache.get_or_fetch(key(), lambda: "old", copier=copier)
    fail.append(1)
    result = cache.get_or_fetch(key(), lambda: "new", copier=copier)
    assert result.value == "new"
    assert not result.from_cache


def test_single_flight_one_fetch():
    cache = make_cache()
    results, errors = [], []
    thread, gate, calls = start_leader(cache, key(), "page", results, errors)

    follower_results = []
    follower = threading.Thread(
        target=lambda: follower_results.append(cache.get_or_fetch(key(), lambda: "other"))
    )
    follower.start()
    wait_for_followers(cache, key())
    gate.set()
    thread.join(5)
    follower.join(5)

    assert not errors
    assert len(calls) == 1
    assert results[0].status == "miss"
    assert follower_results[0].status == "shared"
    assert follower_results[0].value == "page"
    assert cache.stats()["by_namespace"]["http"]["shared"] == 1


def test_follower_refetches_when_leader_raises():
    cache = make_cache()
    results, errors = [], []
    thread, gate, _ = start_leader(cache, key(), OSError("timed out"), results, errors)

    follower_results = []
    follower = threading.Thread(
        target=lambda: follower_results.append(cache.get_or_fetch(key(), lambda: "ok"))
    )
    follower.start()
    wait_for_followers(cache, key())
    gate.set()
    thread.join(5)
    follower.join(5)

    assert len(errors) == 1
    assert isinstance(errors[0], OSError)
    assert follower_results[0].status == "bypass"
    assert follower_results[0].value == "ok"
    assert key() not in cache
    assert not cache._inflight


def test_follower_refetches_when_leader_result_unstorable():
    cache = make_cache()
    results, errors = [], []
    thread, gate, _ = start_leader(cache, key(), None, results, errors)

    follower_results = []
    follower = threading.Thread(
        target=lambda: follower_results.append(cache.get_or_fetch(key(), lambda: "mine"))
    )
    follower.start()
    wait_for_followers(cache, key())
    gate.set()
    thread.join(5)
    follower.join(5)

    assert results[0].value is None
    assert follower_results[0].status == "bypass"
    assert follower_results[0].value == "mine"
    assert key() not in cache


def test_follower_wait_timeout():
    cache = make_cache()
    results, errors = [], []
    thread, gate, _ = start_leader(cache, key(), "late", results, errors)
    try:
        result = cache.get_or_fetch(key(), lambda: "mine", wait_timeout=0.01)
    finally:
        gate.set()
        thread.join(5)
    assert result.status == "bypass"
    assert result.value == "mine"
    assert results[0].value == "late"


def test_reentrant_same_key_same_thread_no_deadlock():
    cache = make_cache()
    inner = []

    def outer():
        inner.append(cache.get_or_fetch(key(), lambda: "inner"))
        return "outer"

    assert cache.get_or_fetch(key(), outer).value == "outer"
    assert inner[0].status == "bypass"
    assert cache.get(key()) == "outer"


def test_lru_eviction_by_count():
    cache = make_cache(max_entries=3)
    for i in range(5):
        cache.put(key(str(i)), i)
    assert len(cache) == 3
    assert key("0") not in cache
    assert key("1") not in cache
    assert cache.get(key("2")) == 2  # mark as recently used
    cache.put(key("5"), 5)
    assert key("2") in cache
    assert key("3") not in cache
    assert cache.stats()["by_namespace"]["http"]["evicted"] == 3


def test_eviction_by_bytes_and_expired_first():
    clock = FakeClock()
    cache = make_cache(max_bytes=8 * 100, clock=clock)  # 800 bytes total, 100 per entry
    cache.put(key("old"), "x", size=100, ttl=1.0)
    for i in range(7):
        cache.put(key(str(i)), "x", size=100)
    assert cache.stats()["bytes"] == 800
    clock.now += 1.0  # "old" expires
    cache.put(key("new"), "x", size=100)
    assert key("old") not in cache
    assert all(key(str(i)) in cache for i in range(7))
    cache.put(key("newer"), "x", size=100)
    assert key("0") not in cache  # least recently used
    assert cache.stats()["bytes"] <= 800


def test_too_large_entry_never_stored():
    cache = make_cache(max_bytes=8 * 100)
    assert cache.max_entry_bytes == 100
    result = cache.get_or_fetch(key("big"), lambda: "x", size_of=lambda _: 101)
    assert result.status == "miss"
    assert key("big") not in cache
    assert cache.put(key("big2"), "x", size=101) is False
    assert cache.put(key("ok"), "x", size=100) is True
    assert cache.stats()["by_namespace"]["http"]["too_large"] == 2


def test_disabled_ttl_zero_and_bypass_do_not_read_or_write():
    calls = []

    def fetch():
        calls.append(1)
        return "v"

    for cache in [
        make_cache(enabled=False),
        make_cache(ttl=0),
        make_cache(ttl=-5),
        make_cache(max_entries=0),
    ]:
        assert not cache.active
        assert cache.get_or_fetch(key(), fetch).status == "disabled"
        assert cache.get_or_fetch(key(), fetch).status == "disabled"
        assert cache.put(key(), "v") is False
        assert cache.get(key(), default="d") == "d"
        assert len(cache) == 0
    assert len(calls) == 8

    cache = make_cache()
    cache.put(key("seeded"), "cached")
    with cache.bypass():
        with cache.bypass():  # re-entrant
            assert not cache.active
        assert not cache.active
        assert cache.get(key("seeded")) is None
        assert cache.get_or_fetch(key("seeded"), lambda: "fresh").value == "fresh"
        assert cache.get_or_fetch(key("new"), fetch).status == "disabled"

        # Bypass in one thread doesn't affect other threads
        other = []
        t = threading.Thread(target=lambda: other.append(cache.active))
        t.start()
        t.join(5)
        assert other == [True]
    assert cache.active
    assert key("new") not in cache
    assert cache.get(key("seeded")) == "cached"


def test_invalidate_filters():
    cache = make_cache()
    cache.put(key("a"), 1)
    cache.put(key("b"), 2)
    cache.put(key("a", port=443), 3)
    cache.put(key("a", host="192.0.2.2"), 4)
    cache.put(key("f", namespace="ftp-file", port=21), 5)
    assert cache.invalidate(namespace="http", host="192.0.2.1", port=80, resource="a") == 1
    assert key("b") in cache
    assert cache.invalidate(namespace="http", host="192.0.2.1") == 2
    assert cache.invalidate(port=21) == 1
    assert len(cache) == 1
    assert cache.invalidate() == 1
    assert cache.stats()["by_namespace"]["http"]["invalidated"] == 4


def test_discard_clear_and_reset_stats():
    cache = make_cache()
    cache.put(key("a"), 1)
    cache.put(key("b"), 2)
    assert cache.discard(key("a")) is True
    assert cache.discard(key("a")) is False
    assert cache.get(key("b")) == 2
    cache.clear()
    assert len(cache) == 0
    assert cache.stats()["bytes"] == 0
    assert cache.stats()["lookups"] == 1  # stats are kept
    cache.reset_stats()
    assert cache.stats()["lookups"] == 0
    assert cache.stats()["by_namespace"] == {}


def test_settings_read_live_from_config(mocker):
    assert data_cache.active
    mocker.patch.dict(config["CONFIG"], {"CACHE_ENABLED": False})
    assert not data_cache.active
    assert data_cache.get_or_fetch(key(), lambda: 1).status == "disabled"
    mocker.patch.dict(config["CONFIG"], {"CACHE_ENABLED": True, "CACHE_TTL": 0.0})
    assert not data_cache.active
    mocker.patch.dict(config["CONFIG"], {"CACHE_TTL": 42.0, "CACHE_MAX_BYTES": 800})
    assert data_cache.active
    assert data_cache.ttl == 42.0
    assert data_cache.max_entry_bytes == 100


def test_invalid_settings_disable_caching(mocker):
    cache = DataCache()
    mocker.patch.dict(config["CONFIG"], {"CACHE_TTL": "bad"})
    assert cache.ttl == 0.0
    assert not cache.active
    assert cache.ttl == 0.0  # warning is only logged once
    assert cache._warned == {"CACHE_TTL"}


@pytest.mark.parametrize("ttl", [float("inf"), float("-inf"), float("nan")])
def test_non_finite_ttl_disables_caching(ttl):
    cache = make_cache(ttl=ttl)
    assert cache.ttl == 0.0
    assert not cache.active
    assert cache.stats()["ttl"] == 0.0  # stays valid JSON in state exports


@pytest.mark.parametrize("max_bytes", [0, 7, "garbage", float("inf")])
def test_max_bytes_too_small_or_invalid_disables_caching(max_bytes):
    cache = make_cache(max_bytes=max_bytes)
    assert not cache.active
    statuses = []
    # Both fetches must run at the same time (no single-flight waiting
    # when nothing can be stored), otherwise the barrier times out.
    barrier = threading.Barrier(2, timeout=5)

    def fetch():
        barrier.wait()
        return "value"

    def lookup():
        statuses.append(cache.get_or_fetch(key(), fetch).status)

    threads = [threading.Thread(target=lookup) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not barrier.broken
    assert statuses == ["disabled", "disabled"]
    assert cache.stats()["lookups"] == 0
    assert len(cache) == 0


def test_stats_shape_and_float_hit_rate():
    cache = make_cache()
    stats = cache.stats()
    assert stats["hit_rate"] == 0.0
    assert isinstance(stats["hit_rate"], float)
    assert isinstance(stats["ttl"], float)

    cache.get_or_fetch(key(), lambda: "abc", size_of=lambda _: 100)
    cache.get_or_fetch(key(), lambda: "abc")
    stats = cache.stats()
    assert stats["lookups"] == 2
    assert stats["served_from_cache"] == 1
    assert stats["hit_rate"] == 0.5
    assert stats["bytes_served"] == 100
    assert stats["entries"] == 1
    assert stats["by_namespace"]["http"]["hits"] == 1
    assert stats["by_namespace"]["http"]["misses"] == 1
    assert json.loads(json.dumps(stats)) == stats
    assert "1 of 2 lookups" in cache.summary()
    assert "http 1/2" in cache.summary()


def test_record_and_log_stats(mocker):
    mocker.patch.dict(state["runtime_configs"])  # undo changes after the test
    data_cache.get_or_fetch(key(), lambda: "v")
    data_cache.log_stats()
    assert state.cache_stats["lookups"] == 1
    assert state.cache_stats["by_namespace"]["http"]["misses"] == 1


def test_fingerprint_salted():
    first = make_cache()
    second = make_cache()
    assert first.fingerprint("user", "pass") == first.fingerprint("user", "pass")
    assert first.fingerprint("user", "pass") != first.fingerprint("user", "pass2")
    assert first.fingerprint("user", "pass") != second.fingerprint("user", "pass")
    assert "pass" not in first.fingerprint("user", "pass")


def test_stress_invariants():
    cache = make_cache(max_entries=50, max_bytes=8 * 1000)
    keys = [key(str(i)) for i in range(200)]
    errors = []

    def worker(seed: int) -> None:
        rng = random.Random(seed)
        try:
            for _ in range(500):
                k = rng.choice(keys)
                op = rng.random()
                if op < 0.8:
                    size = rng.randint(1, 130)
                    result = cache.get_or_fetch(
                        k, lambda k=k: k.resource, size_of=lambda _, size=size: size
                    )
                    assert result.value == k.resource
                elif op < 0.9:
                    cache.invalidate(resource=k.resource)
                else:
                    assert cache.get(k) in (None, k.resource)
                assert len(cache) <= 50  # takes the lock
        except Exception as ex:
            errors.append(ex)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)

    assert not errors
    assert len(cache) <= 50
    assert cache._bytes <= 8000
    assert sum(e.size for e in cache._entries.values()) == cache._bytes
    assert not cache._inflight
