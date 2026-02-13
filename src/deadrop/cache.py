"""In-memory caching with TTL for deadrop.

This module provides a simple TTL-based cache that doesn't require external
dependencies. It's designed for caching auth-related data to reduce database
round-trips.

For single-instance deployments, we use long TTLs since:
- Identity hashes NEVER change (identity must be deleted/recreated)
- Room info rarely changes (only display_name updates)
- Membership changes are explicitly invalidated on add/remove

Cache keys are designed to be invalidated when the underlying data changes.
LRU eviction prevents unbounded memory growth.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .metrics import metrics

T = TypeVar("T")

# Cache TTL configuration (can be overridden via environment)
# For single-instance deployments, these can be very long
ROOM_CACHE_TTL = float(os.environ.get("DEADROP_ROOM_CACHE_TTL", 3600))  # 1 hour default
MEMBERSHIP_CACHE_TTL = float(os.environ.get("DEADROP_MEMBERSHIP_CACHE_TTL", 3600))  # 1 hour default
IDENTITY_CACHE_TTL = float(os.environ.get("DEADROP_IDENTITY_CACHE_TTL", 86400))  # 24 hours default

# Cache size limits
ROOM_CACHE_SIZE = int(os.environ.get("DEADROP_ROOM_CACHE_SIZE", 1000))
MEMBERSHIP_CACHE_SIZE = int(os.environ.get("DEADROP_MEMBERSHIP_CACHE_SIZE", 5000))
IDENTITY_CACHE_SIZE = int(os.environ.get("DEADROP_IDENTITY_CACHE_SIZE", 2000))


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
#
# For single-instance deployments:
# - Identity hashes NEVER change, so 24hr TTL (or set DEADROP_IDENTITY_CACHE_TTL=0 for infinite)
# - Room info rarely changes, 1hr TTL is plenty
# - Membership is explicitly invalidated on changes, 1hr TTL as safety net

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
    # Invalidate all memberships for this identity (they reference the identity)
    membership_cache.invalidate_prefix("member:")  # Broad invalidation - could optimize


def clear_all_caches() -> None:
    """Clear all caches (useful for testing)."""
    room_cache.clear()
    membership_cache.clear()
    identity_hash_cache.clear()
