"""
In-memory cache of data collected from devices during a run of PEAT.

This lets PEAT modules reuse data that another module (or an earlier
phase of the run, e.g. a scan before a pull) already retrieved from a
device, instead of requesting it from the device again. Examples are
HTTP pages, TLS (SSL) certificates, Telnet banners, FTP welcome
messages and FTP files.

- Data is kept in memory only, for the lifetime of the process.
  It is never written to disk.
- Entries expire after :attr:`~peat.settings.Configuration.CACHE_TTL`
  seconds. The cache is bounded by
  :attr:`~peat.settings.Configuration.CACHE_MAX_ENTRIES` and
  :attr:`~peat.settings.Configuration.CACHE_MAX_BYTES`, with
  least-recently-used (LRU) eviction.
- Keys contain everything that can change the answer (e.g. credentials,
  headers, cookies, parameters). These parts are digested with a salted
  HMAC (:meth:`DataCache.fingerprint`), and the digest is never logged.
- Values are copied when stored and when handed out, so a caller that
  modifies its copy can't affect other callers.
- Thread-safe. Concurrent requests for the same key are de-duplicated
  ("single-flight"): one thread fetches, the others wait for its result.
- Caching can be disabled globally (``CACHE_ENABLED``), per thread
  (:meth:`DataCache.bypass`) or per call (e.g. ``use_cache=False``).

Usage:

.. code-block:: python

    from peat.protocols.cache import CacheKey, data_cache

    key = CacheKey("my-proto", dev.ip, 1234, "device-info", data_cache.fingerprint(user))
    result = data_cache.get_or_fetch(key, lambda: query_device_info(dev, user))
    if result.from_cache:
        log.debug(f"Reusing device info fetched {result.age:.1f} seconds ago")
    info = result.value
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final, Literal, NamedTuple

from humanfriendly import format_size

from peat import config, log, state

NS_HTTP: Final[str] = "http"
"""HTTP ``GET`` responses."""

NS_HTTP_POST: Final[str] = "http-post"
"""HTTP ``POST`` responses (only if the caller opts in)."""

NS_TLS_CERT: Final[str] = "tls-cert"
"""Parsed TLS (SSL) certificate of a server."""

NS_TELNET_BANNER: Final[str] = "telnet-banner"
"""Raw bytes a Telnet server sends before PEAT sends any input."""

NS_FTP_WELCOME: Final[str] = "ftp-welcome"
"""FTP welcome message sent by the server on connect."""

NS_FTP_FILE: Final[str] = "ftp-file"
"""Contents of files downloaded using FTP."""

_ENTRY_FRACTION: Final[int] = 8  # one entry may use at most 1/8 of max_bytes
_DEFAULT_WAIT: Final[float] = 120.0  # max seconds a follower waits for an in-flight fetch
_COUNTERS: Final[tuple[str, ...]] = (
    "hits",
    "shared",
    "misses",
    "bypassed",
    "stored",
    "not_stored",
    "too_large",
    "expired",
    "evicted",
    "invalidated",
    "bytes_served",
)

CacheStatus = Literal["hit", "shared", "miss", "bypass", "disabled"]


class CacheKey(NamedTuple):
    """
    Identifies one item in the cache.
    """

    namespace: str
    """Type of data, one of the ``NS_*`` constants (or a module-defined string)."""

    host: str
    """IP address or hostname the data came from (empty string if not host-specific)."""

    port: int
    """Port the data came from (0 if not applicable)."""

    resource: str
    """
    Human-readable description of the item, e.g. ``GET http://192.0.2.1:80/``.
    This is logged, so it must not contain credentials or session tokens.
    """

    variant: str = ""
    """
    Opaque digest of the request context that can change the answer
    (credentials, headers, cookies, options), from
    :meth:`DataCache.fingerprint`. This is never logged.
    """

    @property
    def label(self) -> str:
        """Description of the key that is safe to log (excludes ``variant``)."""
        return f"{self.namespace}://{self.host}:{self.port} {self.resource}"


class CacheResult(NamedTuple):
    """
    Result of :meth:`DataCache.get_or_fetch`.
    """

    value: Any
    """The value, either from the cache or from the fetch function."""

    status: CacheStatus
    """
    - ``hit``: value was in the cache
    - ``shared``: value was fetched by another thread at the same time
    - ``miss``: value was fetched (and stored, if storable)
    - ``bypass``: value was fetched and the cache was not used
    - ``disabled``: value was fetched, caching is disabled
    """

    age: float | None = None
    """Seconds since the value was fetched (``hit`` and ``shared`` only)."""

    @property
    def from_cache(self) -> bool:
        """If the value came from the cache instead of the fetch function."""
        return self.status in ("hit", "shared")


@dataclass
class _Entry:
    value: Any
    size: int
    stored_at: float  # time.monotonic()
    expires_at: float  # time.monotonic()


@dataclass
class _Flight:
    owner: int  # threading.get_ident() of the leader
    done: threading.Event = field(default_factory=threading.Event)
    stored: bool = False


def _identity(value: Any) -> Any:
    return value


def _is_not_none(value: Any) -> bool:
    return value is not None


def estimate_size(value: Any) -> int:
    """
    Rough size in bytes of a value, used for the cache size limits.
    """
    if isinstance(value, (bytes, bytearray, str)):
        return len(value) + 64
    return 512


class DataCache:
    """
    Thread-safe, size-bounded, in-memory cache with a time-to-live (TTL).

    :data:`~peat.protocols.cache.data_cache` is the process-wide instance
    used by PEAT. Refer to the module documentation for details.

    Settings are read from :mod:`peat.config` each time they're used,
    unless overridden by the arguments to this class.

    Args:
        enabled: If caching is enabled. If :obj:`None`, use ``CACHE_ENABLED``.
        ttl: Seconds an entry stays fresh. If :obj:`None`, use ``CACHE_TTL``.
        max_entries: Maximum number of entries. If :obj:`None`, use ``CACHE_MAX_ENTRIES``.
        max_bytes: Maximum approximate total size in bytes.
            If :obj:`None`, use ``CACHE_MAX_BYTES``.
        clock: Function that returns monotonic time in seconds
    """

    def __init__(
        self,
        *,
        enabled: bool | None = None,
        ttl: float | None = None,
        max_entries: int | None = None,
        max_bytes: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._enabled = enabled
        self._ttl = ttl
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[CacheKey, _Entry] = OrderedDict()
        self._bytes: int = 0
        self._inflight: dict[CacheKey, _Flight] = {}
        self._local = threading.local()
        self._salt: bytes = secrets.token_bytes(16)
        self._stats: dict[str, Counter] = {}
        self._warned: set[str] = set()
        self.log = log.bind(classname=self.__class__.__name__)

    # -- Settings --

    def _number(self, name: str, override: Any, cast: type) -> Any:
        raw = getattr(config, name) if override is None else override
        try:
            value = cast(raw)
            if not math.isfinite(value):
                raise ValueError(raw)
            return max(value, 0)
        except (TypeError, ValueError, OverflowError):
            if name not in self._warned:
                self._warned.add(name)
                self.log.warning(f"Invalid value '{raw}' for {name}, caching is disabled")
            return cast(0)

    @property
    def enabled(self) -> bool:
        """If caching is enabled (``CACHE_ENABLED``)."""
        return bool(config.CACHE_ENABLED if self._enabled is None else self._enabled)

    @property
    def ttl(self) -> float:
        """Seconds an entry stays fresh (``CACHE_TTL``). Invalid values are ``0``."""
        return self._number("CACHE_TTL", self._ttl, float)

    @property
    def max_entries(self) -> int:
        """Maximum number of entries (``CACHE_MAX_ENTRIES``)."""
        return self._number("CACHE_MAX_ENTRIES", self._max_entries, int)

    @property
    def max_bytes(self) -> int:
        """Maximum approximate total size of all entries (``CACHE_MAX_BYTES``)."""
        return self._number("CACHE_MAX_BYTES", self._max_bytes, int)

    @property
    def max_entry_bytes(self) -> int:
        """Items larger than this are never stored (1/8 of ``max_bytes``)."""
        return self.max_bytes // _ENTRY_FRACTION

    @property
    def active(self) -> bool:
        """If caching applies to the current thread right now."""
        return (
            self.enabled
            and self.ttl > 0
            and self.max_entries > 0
            and self.max_entry_bytes > 0
            and not getattr(self._local, "bypass", 0)
        )

    # -- Helpers --

    def fingerprint(self, *parts: Any) -> str:
        """
        Salted, non-reversible digest of request context, for use as
        :attr:`CacheKey.variant`.

        Include every credential and option that can change what the device
        returns. The salt is random for each process, so digests can't be
        compared between runs and can't be used to recover the inputs.
        """
        msg = repr(parts).encode("utf-8", "backslashreplace")
        return hmac.new(self._salt, msg, hashlib.sha256).hexdigest()[:32]

    @contextmanager
    def bypass(self) -> Iterator[None]:
        """
        Context manager that disables cache reads and writes in the
        current thread inside the block. Other threads are not affected.
        """
        self._local.bypass = getattr(self._local, "bypass", 0) + 1
        try:
            yield
        finally:
            self._local.bypass -= 1

    def _count(self, namespace: str, name: str, n: int = 1) -> None:  # lock must be held
        self._stats.setdefault(namespace, Counter())[name] += n

    def _fresh_locked(self, key: CacheKey, now: float) -> _Entry | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= now:
            self._drop_locked(key)
            self._count(key.namespace, "expired")
            return None
        self._entries.move_to_end(key)  # mark as recently used
        return entry

    def _drop_locked(self, key: CacheKey) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._bytes -= entry.size

    def _store_locked(self, key: CacheKey, value: Any, size: int, ttl: float, now: float) -> bool:
        if size > self.max_entry_bytes:
            self._count(key.namespace, "too_large")
            self.log.trace2(f"Not caching {key.label}: {format_size(size)} is too large")
            return False

        self._drop_locked(key)
        self._entries[key] = _Entry(value, size, now, now + ttl)
        self._bytes += size
        self._count(key.namespace, "stored")
        self.log.trace2(f"Cached {key.label} ({format_size(size)}, ttl: {ttl}s)")

        max_entries = self.max_entries
        max_bytes = self.max_bytes
        if len(self._entries) > max_entries or self._bytes > max_bytes:
            for old in [k for k, e in self._entries.items() if e.expires_at <= now]:
                self._drop_locked(old)
                self._count(old.namespace, "expired")

        evicted = 0
        while self._entries and (len(self._entries) > max_entries or self._bytes > max_bytes):
            old = next(iter(self._entries))
            self._drop_locked(old)
            self._count(old.namespace, "evicted")
            evicted += 1
        if evicted:
            self.log.trace3(f"Evicted {evicted} least-recently-used entries")

        return key in self._entries

    def _serve_locked(self, key: CacheKey, entry: _Entry, status: str, copier: Callable) -> Any:
        value = copier(entry.value)
        self._count(key.namespace, status)
        self._count(key.namespace, "bytes_served", entry.size)
        return value

    # -- Public API --

    def get(self, key: CacheKey, default: Any = None, copier: Callable = _identity) -> Any:
        """
        Get a fresh value from the cache, without fetching it.

        Args:
            key: Key of the value
            default: Value to return if there is no fresh value in the cache
            copier: Function that copies the stored value before it's returned

        Returns:
            Copy of the cached value, or ``default``
        """
        if not self.active:
            return default

        with self._lock:
            entry = self._fresh_locked(key, self._clock())
            if entry is None:
                self._count(key.namespace, "misses")
                return default
            return self._serve_locked(key, entry, "hits", copier)

    def put(
        self,
        key: CacheKey,
        value: Any,
        *,
        ttl: float | None = None,
        size: int | None = None,
        copier: Callable = _identity,
    ) -> bool:
        """
        Store a value that was collected passively (e.g. a Telnet banner).

        Args:
            key: Key of the value
            value: Value to store. :obj:`None` is never stored.
            ttl: Seconds the value stays fresh. If :obj:`None`, use :attr:`ttl`.
                Values of 0 or less mean "don't store".
            size: Approximate size of the value in bytes.
                If :obj:`None`, it's estimated.
            copier: Function that copies the value before it's stored

        Returns:
            If the value was stored
        """
        if not self.active or value is None:
            return False

        ttl = self.ttl if ttl is None else ttl
        if ttl <= 0:
            return False

        try:
            stored_value = copier(value)
            size = estimate_size(value) if size is None else size
        except Exception as ex:
            self.log.trace2(f"Not caching {key.label}: {ex}")
            return False

        with self._lock:
            return self._store_locked(key, stored_value, size, ttl, self._clock())

    def get_or_fetch(
        self,
        key: CacheKey,
        fetch: Callable[[], Any],
        *,
        ttl: float | None = None,
        store_if: Callable[[Any], bool] | None = None,
        size_of: Callable[[Any], int] | None = None,
        copier: Callable[[Any], Any] = _identity,
        wait_timeout: float | None = None,
    ) -> CacheResult:
        """
        Get a fresh value from the cache, or fetch (and store) it.

        If another thread is already fetching the same key, wait for it and
        use its value, if it was stored. Otherwise, fetch the value here.
        Exceptions raised by ``fetch`` are passed to the caller and nothing
        is stored.

        Args:
            key: Key of the value
            fetch: Function with no arguments that retrieves the value
                (e.g. from the device). This is called without any locks held.
            ttl: Seconds the value stays fresh. If :obj:`None`, use :attr:`ttl`.
                Values of 0 or less mean "don't use the cache".
            store_if: Function that returns :obj:`True` if the fetched value
                can be stored. Default: store anything that isn't :obj:`None`.
            size_of: Function that returns the approximate size of the value in bytes
            copier: Function that copies a value. It's used to store a value and
                to hand out a stored value, so callers can't modify stored data.
            wait_timeout: Maximum seconds to wait for another thread
                that's fetching the same key (default: 120)

        Returns:
            The value and how it was obtained, as a :class:`CacheResult`
        """
        if not self.active:
            return CacheResult(fetch(), "disabled")

        ttl = self.ttl if ttl is None else ttl
        if ttl <= 0:
            return CacheResult(fetch(), "bypass")

        store_if = store_if or _is_not_none
        size_of = size_of or estimate_size
        me = threading.get_ident()

        with self._lock:
            now = self._clock()
            entry = self._fresh_locked(key, now)
            if entry is not None:
                try:
                    value = self._serve_locked(key, entry, "hits", copier)
                    return CacheResult(value, "hit", now - entry.stored_at)
                except Exception as ex:
                    # Drop the entry and fetch the value again
                    self.log.trace2(f"Failed to copy cached {key.label}: {ex}")
                    self._drop_locked(key)
            flight = self._inflight.get(key)
            if flight is None:
                flight = self._inflight[key] = _Flight(owner=me)
                role = "leader"
                self._count(key.namespace, "misses")
            elif flight.owner == me:
                # Same thread asks for the same key while fetching it.
                # Fetch without the cache, instead of deadlocking.
                role = "reentrant"
                self._count(key.namespace, "bypassed")
            else:
                role = "follower"

        if role == "reentrant":
            return CacheResult(fetch(), "bypass")

        if role == "follower":
            flight.done.wait(_DEFAULT_WAIT if wait_timeout is None else wait_timeout)
            with self._lock:
                now = self._clock()
                entry = self._fresh_locked(key, now) if flight.stored else None
                if entry is not None:
                    try:
                        value = self._serve_locked(key, entry, "shared", copier)
                        return CacheResult(value, "shared", now - entry.stored_at)
                    except Exception as ex:
                        self.log.trace2(f"Failed to copy cached {key.label}: {ex}")
                self._count(key.namespace, "bypassed")
            # The leader failed, produced a value that can't be stored,
            # or took too long. Only stored values are shared, so fetch here.
            return CacheResult(fetch(), "bypass")

        # Leader
        try:
            value = fetch()
            try:
                if store_if(value):
                    stored_value = copier(value)
                    size = int(size_of(value))
                else:
                    stored_value = None
                    size = -1
            except Exception as ex:
                self.log.trace2(f"Not caching {key.label}: {ex}")
                size = -1

            with self._lock:
                if size < 0:
                    self._count(key.namespace, "not_stored")
                else:
                    flight.stored = self._store_locked(key, stored_value, size, ttl, self._clock())

            return CacheResult(value, "miss")
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            flight.done.set()

    def invalidate(
        self,
        *,
        namespace: str | None = None,
        host: str | None = None,
        port: int | None = None,
        resource: str | None = None,
    ) -> int:
        """
        Remove matching entries from the cache.

        All filters must match. A filter of :obj:`None` matches anything,
        so calling this with no arguments removes all entries.

        Returns:
            Number of entries removed
        """
        with self._lock:
            doomed = [
                k
                for k in self._entries
                if (namespace is None or k.namespace == namespace)
                and (host is None or k.host == host)
                and (port is None or k.port == port)
                and (resource is None or k.resource == resource)
            ]
            for k in doomed:
                self._drop_locked(k)
                self._count(k.namespace, "invalidated")

        if doomed:
            self.log.trace3(f"Invalidated {len(doomed)} entries")
        return len(doomed)

    def discard(self, key: CacheKey) -> bool:
        """
        Remove one entry from the cache.

        Returns:
            If the entry was in the cache
        """
        with self._lock:
            found = key in self._entries
            self._drop_locked(key)
        return found

    def clear(self) -> None:
        """Remove all entries from the cache. Statistics are kept."""
        with self._lock:
            self._entries.clear()
            self._bytes = 0

    def reset_stats(self) -> None:
        """Reset the statistics to zero."""
        with self._lock:
            self._stats.clear()

    def stats(self) -> dict[str, Any]:
        """
        Statistics of the cache, as a JSON-serializable :class:`dict`.

        ``hit_rate`` is always a :class:`float`, for consistent
        Elasticsearch mappings.
        """
        with self._lock:
            by_namespace = {
                ns: {name: int(counts.get(name, 0)) for name in _COUNTERS}
                for ns, counts in sorted(self._stats.items())
            }
            entries = len(self._entries)
            size = self._bytes

        def _total(name: str) -> int:
            return sum(counts[name] for counts in by_namespace.values())

        served = _total("hits") + _total("shared")
        lookups = served + _total("misses") + _total("bypassed")

        return {
            "enabled": self.enabled,
            "ttl": float(self.ttl),
            "max_entries": self.max_entries,
            "max_bytes": self.max_bytes,
            "entries": entries,
            "bytes": size,
            "lookups": lookups,
            "served_from_cache": served,
            "hit_rate": float(served / lookups) if lookups else 0.0,
            "bytes_served": _total("bytes_served"),
            "by_namespace": by_namespace,
        }

    def summary(self) -> str:
        """One-line, human-readable summary of the statistics."""
        stats = self.stats()
        parts = []
        for ns, counts in stats["by_namespace"].items():
            served = counts["hits"] + counts["shared"]
            total = served + counts["misses"] + counts["bypassed"]
            if total:
                parts.append(f"{ns} {served}/{total}")

        return (
            f"Data cache: {stats['served_from_cache']} of {stats['lookups']} lookups "
            f"served from cache ({stats['hit_rate']:.1%}), "
            f"~{format_size(stats['bytes_served'])} not re-fetched "
            f"[{', '.join(parts)}]; "
            f"{stats['entries']} entries ({format_size(stats['bytes'])})"
        )

    def record_stats(self) -> None:
        """Save the statistics to :attr:`peat.settings.State.cache_stats`."""
        state.cache_stats = self.stats()

    def log_stats(self) -> None:
        """Save the statistics to ``state`` and log a summary, if the cache was used."""
        self.record_stats()
        if state.cache_stats["lookups"]:
            self.log.info(self.summary())

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __contains__(self, key: object) -> bool:
        with self._lock:
            entry = self._entries.get(key)  # type: ignore[call-overload]
            return entry is not None and entry.expires_at > self._clock()


data_cache = DataCache()
"""
Process-wide cache instance used by PEAT's protocol classes and modules.
"""


__all__ = [
    "NS_FTP_FILE",
    "NS_FTP_WELCOME",
    "NS_HTTP",
    "NS_HTTP_POST",
    "NS_TELNET_BANNER",
    "NS_TLS_CERT",
    "CacheKey",
    "CacheResult",
    "DataCache",
    "data_cache",
    "estimate_size",
]
