"""In-memory caching with TTL for deadrop.

This module provides a simple TTL-based cache that doesn't require external
dependencies. It's designed for caching auth-related data to reduce database
round-trips.

For single-instance deployments, we use long TTLs and background cache warming:
- Identity hashes NEVER change (identity must be deleted/recreated)
- Room info rarely changes (only display_name updates)
- Membership changes are explicitly invalidated on add/remove

Cache keys are designed to be invalidated when the underlying data changes.
LRU eviction prevents unbounded memory growth.
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

# Cache TTL configuration (can be overridden via environment)
# For single-instance deployments with cache warming, these can be very long
ROOM_CACHE_TTL = float(os.environ.get("DEADROP_ROOM_CACHE_TTL", 3600))  # 1 hour default
MEMBERSHIP_CACHE_TTL = float(os.environ.get("DEADROP_MEMBERSHIP_CACHE_TTL", 3600))  # 1 hour default
IDENTITY_CACHE_TTL = float(os.environ.get("DEADROP_IDENTITY_CACHE_TTL", 86400))  # 24 hours default

# Cache size limits
ROOM_CACHE_SIZE = int(os.environ.get("DEADROP_ROOM_CACHE_SIZE", 1000))
MEMBERSHIP_CACHE_SIZE = int(os.environ.get("DEADROP_MEMBERSHIP_CACHE_SIZE", 10000))
IDENTITY_CACHE_SIZE = int(os.environ.get("DEADROP_IDENTITY_CACHE_SIZE", 5000))

# Cache warming configuration
CACHE_WARMING_ENABLED = os.environ.get("DEADROP_CACHE_WARMING", "1").lower() in ("1", "true", "yes")
CACHE_REFRESH_INTERVAL = int(os.environ.get("DEADROP_CACHE_REFRESH_INTERVAL", 300))  # 5 min default
CACHE_WARMING_TIMEOUT = int(os.environ.get("DEADROP_CACHE_WARMING_TIMEOUT", 30))  # 30s default


@dataclass
class CacheEntry:
    """A single cache entry with expiration."""

    value: Any
    expires_at: float

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class TTLCache:
    """Thread-safe TTL cache with LRU eviction.

    Args:
        name: Name of the cache (for metrics)
        default_ttl: Default TTL in seconds (0 = no expiration, rely on LRU)
        max_size: Maximum number of entries (LRU eviction when exceeded)
    """

    name: str
    default_ttl: float = 3600.0
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

            # Check expiration (skip if TTL is 0 - no expiration)
            if self.default_ttl > 0 and entry.is_expired():
                del self._data[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                metrics.record_cache_miss(self.name)
                return False, None

            # Update access order for LRU
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)

            metrics.record_cache_hit(self.name)
            return True, entry.value

    def set(self, key: str, value: Any, ttl: float | None = None) -> None:
        """Set a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds (uses default_ttl if not specified, 0 = no expiration)
        """
        if ttl is None:
            ttl = self.default_ttl

        with self._lock:
            # Evict expired entries periodically
            if len(self._data) >= self.max_size:
                self._evict_expired()

            # If still at max, evict LRU
            while len(self._data) >= self.max_size and self._access_order:
                oldest_key = self._access_order.pop(0)
                self._data.pop(oldest_key, None)

            # For TTL of 0, set expiration far in the future (effectively no expiration)
            expires_at = time.time() + ttl if ttl > 0 else float("inf")

            self._data[key] = CacheEntry(
                value=value,
                expires_at=expires_at,
            )
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)

    def set_bulk(self, items: dict[str, Any], ttl: float | None = None) -> int:
        """Set multiple values in the cache efficiently.

        Args:
            items: Dictionary of key -> value pairs
            ttl: TTL in seconds (uses default_ttl if not specified)

        Returns:
            Number of items added
        """
        if ttl is None:
            ttl = self.default_ttl

        expires_at = time.time() + ttl if ttl > 0 else float("inf")
        added = 0

        with self._lock:
            for key, value in items.items():
                if len(self._data) >= self.max_size:
                    self._evict_expired()
                    if len(self._data) >= self.max_size and self._access_order:
                        oldest_key = self._access_order.pop(0)
                        self._data.pop(oldest_key, None)

                self._data[key] = CacheEntry(value=value, expires_at=expires_at)
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

    def _evict_expired(self) -> None:
        """Evict all expired entries. Must be called with lock held."""
        now = time.time()
        expired_keys = [k for k, v in self._data.items() if v.expires_at <= now]
        for key in expired_keys:
            del self._data[key]
            if key in self._access_order:
                self._access_order.remove(key)

    def stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._data),
                "max_size": self.max_size,
                "ttl_seconds": self.default_ttl,
            }


# Global cache instances with configurable TTLs
room_cache = TTLCache(
    name="room",
    default_ttl=ROOM_CACHE_TTL,
    max_size=ROOM_CACHE_SIZE,
)

membership_cache = TTLCache(
    name="membership",
    default_ttl=MEMBERSHIP_CACHE_TTL,
    max_size=MEMBERSHIP_CACHE_SIZE,
)

identity_hash_cache = TTLCache(
    name="identity_hash",
    default_ttl=IDENTITY_CACHE_TTL,
    max_size=IDENTITY_CACHE_SIZE,
)


def invalidate_room(room_id: str) -> None:
    """Invalidate all caches related to a room."""
    room_cache.delete(f"room:{room_id}")
    membership_cache.invalidate_prefix(f"member:{room_id}:")


def invalidate_membership(room_id: str, identity_id: str) -> None:
    """Invalidate membership cache for a specific room/identity pair."""
    membership_cache.delete(f"member:{room_id}:{identity_id}")


def invalidate_identity(ns: str, identity_id: str) -> None:
    """Invalidate all caches related to an identity."""
    identity_hash_cache.delete(f"identity:{ns}:{identity_id}")
    # Invalidate all memberships for this identity
    membership_cache.invalidate_prefix("member:")  # Broad invalidation


def clear_all_caches() -> None:
    """Clear all caches (useful for testing)."""
    room_cache.clear()
    membership_cache.clear()
    identity_hash_cache.clear()


# --- Cache Warming ---


async def warm_caches(conn: sqlite3.Connection | None = None) -> dict[str, int]:
    """Warm all caches by loading auth data from the database.

    This runs as a background task on startup to pre-populate caches with:
    - All rooms
    - All room memberships
    - All identity secret hashes

    Args:
        conn: Optional database connection (uses global if not provided)

    Returns:
        Dictionary with counts of items cached
    """
    from . import db

    if conn is None:
        # IMPORTANT: Get the connection in a thread pool to avoid blocking
        # the event loop.  For libsql/Turso, get_connection() acquires a
        # threading lock and runs a network health check — both blocking
        # operations that would freeze the entire server if executed on
        # the event loop thread.
        loop = asyncio.get_event_loop()
        conn = await loop.run_in_executor(None, db.get_connection)

    start_time = time.perf_counter()
    results = {"rooms": 0, "memberships": 0, "identities": 0}

    try:
        # Warm room cache
        rooms_cached = await _warm_room_cache(conn)
        results["rooms"] = rooms_cached

        # Warm membership cache
        memberships_cached = await _warm_membership_cache(conn)
        results["memberships"] = memberships_cached

        # Warm identity hash cache
        identities_cached = await _warm_identity_cache(conn)
        results["identities"] = identities_cached

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        msg = (
            f"Cache warming complete in {elapsed_ms:.0f}ms: "
            f"{results['rooms']} rooms, {results['memberships']} memberships, "
            f"{results['identities']} identities"
        )
        logger.info(msg)
        # Also print to ensure visibility in uvicorn logs
        print(f"INFO:     {msg}")

    except Exception as e:
        logger.error(f"Cache warming failed: {e}")
        print(f"ERROR:    Cache warming failed: {e}")
        raise

    return results


async def _warm_room_cache(conn: sqlite3.Connection) -> int:
    """Load all rooms into cache."""
    from . import db

    # Run DB query in thread pool to not block event loop
    loop = asyncio.get_event_loop()
    cursor = await loop.run_in_executor(
        None,
        lambda: conn.execute("SELECT room_id, ns, display_name, created_by, created_at FROM rooms"),
    )
    rows = await loop.run_in_executor(None, cursor.fetchall)

    # Build cache entries
    items = {}
    for row in rows:
        room_data = db._row_to_dict(cursor.description, row)
        if room_data:
            items[f"room:{room_data['room_id']}"] = room_data

    # Bulk insert
    return room_cache.set_bulk(items)


async def _warm_membership_cache(conn: sqlite3.Connection) -> int:
    """Load all room memberships into cache."""
    # Run DB query in thread pool
    loop = asyncio.get_event_loop()
    cursor = await loop.run_in_executor(
        None,
        lambda: conn.execute("SELECT room_id, identity_id FROM room_members"),
    )
    rows = await loop.run_in_executor(None, cursor.fetchall)

    # Build cache entries (membership is just a boolean - True if member)
    items = {}
    for row in rows:
        room_id = row[0]
        identity_id = row[1]
        items[f"member:{room_id}:{identity_id}"] = True

    return membership_cache.set_bulk(items)


async def _warm_identity_cache(conn: sqlite3.Connection) -> int:
    """Load all identity secret hashes into cache."""
    # Run DB query in thread pool
    loop = asyncio.get_event_loop()
    cursor = await loop.run_in_executor(
        None,
        lambda: conn.execute("SELECT ns, id, secret_hash FROM identities"),
    )
    rows = await loop.run_in_executor(None, cursor.fetchall)

    # Build cache entries
    items = {}
    for row in rows:
        ns = row[0]
        identity_id = row[1]
        secret_hash = row[2]
        items[f"identity:{ns}:{identity_id}"] = secret_hash

    return identity_hash_cache.set_bulk(items)


# Global flag to signal shutdown to background tasks
_shutdown_event: asyncio.Event | None = None


def schedule_cache_warming() -> None:
    """Schedule cache warming as a background task with periodic refresh.

    This should be called during application startup. It:
    1. Runs initial cache warming after a short delay (non-blocking)
    2. Schedules periodic refresh to pick up new data

    The refresh interval is controlled by DEADROP_CACHE_REFRESH_INTERVAL (default: 300s).
    """
    global _shutdown_event

    if not CACHE_WARMING_ENABLED:
        logger.info("Cache warming disabled via DEADROP_CACHE_WARMING=0")
        print("INFO:     Cache warming disabled via DEADROP_CACHE_WARMING=0")
        return

    async def _warm_and_refresh():
        global _shutdown_event
        _shutdown_event = asyncio.Event()

        # Small delay to let the server fully start
        await asyncio.sleep(0.5)

        # Initial warming (with timeout to prevent blocking on startup)
        try:
            await asyncio.wait_for(warm_caches(), timeout=CACHE_WARMING_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error(f"Initial cache warming timed out after {CACHE_WARMING_TIMEOUT}s")
            print(f"ERROR:    Initial cache warming timed out after {CACHE_WARMING_TIMEOUT}s")
        except Exception as e:
            logger.error(f"Initial cache warming failed: {e}")
            print(f"ERROR:    Initial cache warming failed: {e}")

        # Periodic refresh loop
        if CACHE_REFRESH_INTERVAL > 0:
            print(f"INFO:     Cache refresh scheduled every {CACHE_REFRESH_INTERVAL}s")
            while not _shutdown_event.is_set():
                try:
                    # Wait for the refresh interval or shutdown signal
                    await asyncio.wait_for(
                        _shutdown_event.wait(),
                        timeout=CACHE_REFRESH_INTERVAL,
                    )
                    # If we get here, shutdown was signaled
                    break
                except asyncio.TimeoutError:
                    # Timeout means it's time to refresh
                    pass

                # Refresh caches (with timeout to prevent blocking the event loop
                # if the Turso connection is stale or the network is unreachable)
                try:
                    results = await asyncio.wait_for(warm_caches(), timeout=CACHE_WARMING_TIMEOUT)
                    logger.debug(f"Cache refresh: {results}")
                except asyncio.TimeoutError:
                    logger.error(f"Cache refresh timed out after {CACHE_WARMING_TIMEOUT}s")
                    # Continue running - don't let refresh failures stop the loop
                except Exception as e:
                    logger.error(f"Cache refresh failed: {e}")
                    # Continue running - don't let refresh failures stop the loop

    # Get or create event loop and schedule the task
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_warm_and_refresh())
        logger.info("Cache warming scheduled as background task")
    except RuntimeError:
        # No running loop - we're probably in a sync context
        logger.warning("No event loop available for cache warming")
        print("WARNING:  No event loop available for cache warming")


def stop_cache_warming() -> None:
    """Signal the cache warming background task to stop.

    Should be called during application shutdown.
    """
    global _shutdown_event
    if _shutdown_event is not None:
        _shutdown_event.set()
