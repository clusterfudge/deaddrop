"""In-memory caching with write-through invalidation for deadrop.

This module provides a simple in-memory cache for auth-related data (rooms,
memberships, identity hashes) to eliminate redundant database round-trips.

Strategy: warm-on-startup + cache-aside with write-through invalidation.

Since deaddrop is deployed as a single process with a single worker, there
are no out-of-process writers.  Every mutation flows through our API handlers,
so we can invalidate/update cache entries at write time and never need
periodic background refreshes.

- Startup: bulk-load all rooms, memberships, and identity hashes
- Reads: check cache first, fall through to DB on miss, populate cache
- Writes: API handlers call invalidation helpers after mutations
- No TTL expiration needed (LRU eviction prevents unbounded memory growth)
- Admin cache-bust endpoint available for manual recovery

The identity secret table (``secret_map``) is the exception: a burned secret
must stop working in every process, so it also follows the database's
``auth_generation`` counter (see ``deadrop.db.refresh_secret_map``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar

from .metrics import metrics

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Cache size limits
ROOM_CACHE_SIZE = int(os.environ.get("DEADROP_ROOM_CACHE_SIZE", 1000))
MEMBERSHIP_CACHE_SIZE = int(os.environ.get("DEADROP_MEMBERSHIP_CACHE_SIZE", 10000))

# Cache warming configuration
CACHE_WARMING_ENABLED = os.environ.get("DEADROP_CACHE_WARMING", "1").lower() in (
    "1",
    "true",
    "yes",
)
CACHE_WARMING_TIMEOUT = int(os.environ.get("DEADROP_CACHE_WARMING_TIMEOUT", 30))  # 30s default


@dataclass
class CacheEntry:
    """A single cache entry."""

    value: Any
    created_at: float


@dataclass
class TTLCache:
    """Thread-safe in-memory cache with LRU eviction.

    With TTL=0 (default for single-process deployments), entries never
    expire — they are only evicted by LRU when the cache is full, or
    explicitly invalidated on write.

    Args:
        name: Name of the cache (for metrics)
        max_size: Maximum number of entries (LRU eviction when exceeded)
    """

    name: str
    max_size: int = 1000
    _data: dict[str, CacheEntry] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _access_order: list[str] = field(default_factory=list)

    def get(self, key: str) -> tuple[bool, Any]:
        """Get a value from the cache.

        Returns:
            (hit, value) tuple. If hit is False, value is None.
        """
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                metrics.record_cache_miss(self.name)
                return False, None

            # Update access order for LRU
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)

            metrics.record_cache_hit(self.name)
            return True, entry.value

    def set(self, key: str, value: Any, **_kwargs: Any) -> None:
        """Set a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        with self._lock:
            # If at max, evict LRU
            while len(self._data) >= self.max_size and self._access_order:
                oldest_key = self._access_order.pop(0)
                self._data.pop(oldest_key, None)

            self._data[key] = CacheEntry(
                value=value,
                created_at=time.time(),
            )
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)

    def set_bulk(self, items: dict[str, Any], **_kwargs: Any) -> int:
        """Set multiple values in the cache efficiently.

        Args:
            items: Dictionary of key -> value pairs

        Returns:
            Number of items added
        """
        added = 0
        now = time.time()

        with self._lock:
            for key, value in items.items():
                if len(self._data) >= self.max_size and self._access_order:
                    oldest_key = self._access_order.pop(0)
                    self._data.pop(oldest_key, None)

                self._data[key] = CacheEntry(value=value, created_at=now)
                if key in self._access_order:
                    self._access_order.remove(key)
                self._access_order.append(key)
                added += 1

        return added

    def delete(self, key: str) -> bool:
        """Delete a key from the cache.

        Returns:
            True if the key existed.
        """
        with self._lock:
            if key in self._data:
                del self._data[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                return True
            return False

    def invalidate_prefix(self, prefix: str) -> int:
        """Invalidate all keys starting with a prefix.

        Returns:
            Number of keys invalidated.
        """
        with self._lock:
            keys_to_delete = [k for k in self._data if k.startswith(prefix)]
            for key in keys_to_delete:
                del self._data[key]
                if key in self._access_order:
                    self._access_order.remove(key)
            return len(keys_to_delete)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._data.clear()
            self._access_order.clear()

    def stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._data),
                "max_size": self.max_size,
            }


@dataclass(frozen=True)
class SecretEntry:
    """One version of an identity's secret, as the auth lookup table holds it.

    ``switch_grace`` is set on a version minted by a rekey: its first
    authenticated use moves every older live version of the identity to
    ``grace`` for that many seconds (``0`` burns them at once). ``seen`` is
    whether that use has happened (``last_seen_at`` is set).
    """

    ns: str
    identity_id: str
    version: int
    status: str  # active | grace | burned
    grace_until: float | None = None
    seen: bool = False
    switch_grace: int | None = None

    def effective_status(self, now: float) -> str:
        """``grace`` past its deadline is ``burned``, in every process alike."""
        if self.status == "grace" and self.grace_until is not None and now >= self.grace_until:
            return "burned"
        return self.status


class SecretMap:
    """In-process ``sha256(secret) -> SecretEntry`` table for identity auth.

    Loaded whole at startup and refreshed when the ``auth_generation`` row
    moves (see :func:`deadrop.db.refresh_secret_map`). No LRU: once
    ``loaded`` it is authoritative, so a hash it does not hold is rejected
    without a database read (beyond a throttled generation check).

    Activity that is not auth-relevant (stale use of a burned secret, last
    use of a live one) is buffered here and flushed by the refresh tick, so
    a flood of stale requests costs no per-request write.
    """

    SEEN_FLUSH_INTERVAL = 300.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_hash: dict[str, SecretEntry] = {}
        self.loaded = False
        self.generation: int | None = None
        self.last_refresh = 0.0
        self._burned_hits: dict[str, tuple[int, float]] = {}
        self._seen: dict[str, float] = {}
        self._seen_flushed: dict[str, float] = {}

    def get(self, secret_hash: str) -> SecretEntry | None:
        entry = self._by_hash.get(secret_hash)
        if entry is None:
            metrics.record_cache_miss("secret_map")
        else:
            metrics.record_cache_hit("secret_map")
        return entry

    def replace_all(self, entries: dict[str, SecretEntry], generation: int | None) -> None:
        with self._lock:
            self._by_hash = dict(entries)
            self.generation = generation
            self.loaded = True

    def replace_identity(self, ns: str, identity_id: str, entries: dict[str, SecretEntry]) -> None:
        with self._lock:
            by_hash = {
                h: e
                for h, e in self._by_hash.items()
                if not (e.ns == ns and e.identity_id == identity_id)
            }
            by_hash.update(entries)
            self._by_hash = by_hash

    def drop_identity(self, ns: str, identity_id: str) -> None:
        self.replace_identity(ns, identity_id, {})

    def entries_for(self, ns: str, identity_id: str) -> dict[str, SecretEntry]:
        return {
            h: e for h, e in self._by_hash.items() if e.ns == ns and e.identity_id == identity_id
        }

    def has_due_grace(self, now: float) -> bool:
        return any(
            e.status == "grace" and e.grace_until is not None and now >= e.grace_until
            for e in self._by_hash.values()
        )

    def note_burned(self, secret_hash: str) -> None:
        with self._lock:
            count, _ = self._burned_hits.get(secret_hash, (0, 0.0))
            self._burned_hits[secret_hash] = (count + 1, time.time())

    def note_seen(self, secret_hash: str) -> None:
        now = time.time()
        if now - self._seen_flushed.get(secret_hash, 0.0) < self.SEEN_FLUSH_INTERVAL:
            return
        with self._lock:
            self._seen[secret_hash] = now

    def take_activity(self) -> tuple[dict[str, tuple[int, float]], dict[str, float]]:
        with self._lock:
            burned, self._burned_hits = self._burned_hits, {}
            seen, self._seen = self._seen, {}
            for h, ts in seen.items():
                self._seen_flushed[h] = ts
        return burned, seen

    def clear(self) -> None:
        with self._lock:
            self._by_hash = {}
            self.loaded = False
            self.generation = None
            self.last_refresh = 0.0
            self._burned_hits = {}
            self._seen = {}
            self._seen_flushed = {}

    def stats(self) -> dict:
        return {
            "size": len(self._by_hash),
            "loaded": self.loaded,
            "generation": self.generation,
        }


# Global cache instances
room_cache = TTLCache(name="room", max_size=ROOM_CACHE_SIZE)
membership_cache = TTLCache(name="membership", max_size=MEMBERSHIP_CACHE_SIZE)
secret_map = SecretMap()


# --- Write-through invalidation helpers ---
# These MUST be called by API handlers after every mutation to rooms,
# memberships, or identities.  Since we're a single-process server,
# this is the only mechanism that keeps the cache consistent.


def invalidate_room(room_id: str) -> None:
    """Invalidate all caches related to a room."""
    room_cache.delete(f"room:{room_id}")
    membership_cache.invalidate_prefix(f"member:{room_id}:")


def invalidate_membership(room_id: str, identity_id: str) -> None:
    """Invalidate membership cache for a specific room/identity pair."""
    membership_cache.delete(f"member:{room_id}:{identity_id}")


def invalidate_identity(ns: str, identity_id: str) -> None:
    """Invalidate all caches related to an identity.

    This does a broad membership invalidation because an identity's
    memberships span multiple rooms and we don't track which ones.
    """
    secret_map.drop_identity(ns, identity_id)
    membership_cache.invalidate_prefix("member:")


def clear_all_caches() -> None:
    """Clear all caches.  Used by the admin cache-bust endpoint and tests."""
    room_cache.clear()
    membership_cache.clear()
    secret_map.clear()
    logger.info("All caches cleared")


# --- Startup Cache Warming ---


async def warm_caches(conn: sqlite3.Connection | None = None) -> dict[str, int]:
    """Warm all caches by bulk-loading auth data from the database.

    Called once at startup to pre-populate caches.  After this, the caches
    are kept consistent via write-through invalidation — no periodic refresh
    is needed.

    All DB operations run on a single executor thread to ensure connection
    thread-safety (each libsql connection is thread-local).

    Args:
        conn: Optional database connection (uses thread-local if not provided)

    Returns:
        Dictionary with counts of items cached
    """
    from . import db

    def _warm_all_sync() -> dict[str, int]:
        """Run all cache warming on a single executor thread."""
        c = conn if conn is not None else db.get_connection()
        start = time.perf_counter()
        results = {"rooms": 0, "memberships": 0, "identities": 0}

        # Warm room cache
        cursor = c.execute(
            "SELECT room_id, ns, display_name, created_by, created_at FROM rooms",
            name="cache_warm.rooms",
        )
        rows = cursor.fetchall()
        room_items = {}
        for row in rows:
            room_data = db._row_to_dict(cursor.description, row)
            if room_data:
                room_items[f"room:{room_data['room_id']}"] = room_data
        results["rooms"] = room_cache.set_bulk(room_items)

        # Warm membership cache
        cursor = c.execute(
            "SELECT room_id, identity_id FROM room_members", name="cache_warm.memberships"
        )
        rows = cursor.fetchall()
        member_items = {}
        for row in rows:
            member_items[f"member:{row[0]}:{row[1]}"] = True
        results["memberships"] = membership_cache.set_bulk(member_items)

        # Load the identity secret lookup table (secret hash -> identity)
        results["identities"] = db.load_secret_map(conn)

        elapsed_ms = (time.perf_counter() - start) * 1000
        msg = (
            f"Cache warming complete in {elapsed_ms:.0f}ms: "
            f"{results['rooms']} rooms, {results['memberships']} memberships, "
            f"{results['identities']} identities"
        )
        logger.info(msg)
        print(f"INFO:     {msg}")

        return results

    loop = asyncio.get_event_loop()
    # Cache warming is all SELECT reads — use the read executor pool.
    executor = db.get_read_executor()

    try:
        return await loop.run_in_executor(executor, _warm_all_sync)
    except Exception as e:
        logger.error(f"Cache warming failed: {e}")
        print(f"ERROR:    Cache warming failed: {e}")
        raise


def schedule_cache_warming() -> None:
    """Schedule one-time cache warming as a background task on startup.

    No periodic refresh — the cache is kept consistent via write-through
    invalidation in the API handlers.
    """
    if not CACHE_WARMING_ENABLED:
        logger.info("Cache warming disabled via DEADROP_CACHE_WARMING=0")
        print("INFO:     Cache warming disabled via DEADROP_CACHE_WARMING=0")
        return

    async def _warm_on_startup():
        # Small delay to let the server fully start
        await asyncio.sleep(0.5)

        try:
            await asyncio.wait_for(warm_caches(), timeout=CACHE_WARMING_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error(f"Initial cache warming timed out after {CACHE_WARMING_TIMEOUT}s")
            print(f"ERROR:    Initial cache warming timed out after {CACHE_WARMING_TIMEOUT}s")
        except Exception as e:
            logger.error(f"Initial cache warming failed: {e}")
            print(f"ERROR:    Initial cache warming failed: {e}")

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_warm_on_startup())
        logger.info("Cache warming scheduled (one-time, no periodic refresh)")
    except RuntimeError:
        logger.warning("No event loop available for cache warming")
        print("WARNING:  No event loop available for cache warming")


def stop_cache_warming() -> None:
    """No-op — kept for backward compatibility with startup/shutdown hooks."""
    pass
