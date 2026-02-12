"""In-memory caching with TTL for deadrop.

This module provides a simple TTL-based cache that doesn't require external
dependencies. It's designed for caching auth-related data to reduce database
round-trips.

Cache keys are designed to be invalidated when the underlying data changes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .metrics import metrics

T = TypeVar("T")


@dataclass
class CacheEntry:
    """A single cache entry with expiration."""

    value: Any
    expires_at: float

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class TTLCache:
    """Thread-safe TTL cache.

    Args:
        name: Name of the cache (for metrics)
        default_ttl: Default TTL in seconds
        max_size: Maximum number of entries (LRU eviction when exceeded)
    """

    name: str
    default_ttl: float = 60.0
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

            if entry.is_expired():
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
            ttl: TTL in seconds (uses default_ttl if not specified)
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

            self._data[key] = CacheEntry(
                value=value,
                expires_at=time.time() + ttl,
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
            }


# Global cache instances
# Room info cache - rooms rarely change
room_cache = TTLCache(name="room", default_ttl=300.0, max_size=500)  # 5 min TTL

# Room membership cache - memberships change occasionally
membership_cache = TTLCache(name="membership", default_ttl=60.0, max_size=2000)  # 1 min TTL

# Identity hash cache - secret hashes never change (identity would be deleted and recreated)
identity_hash_cache = TTLCache(name="identity_hash", default_ttl=600.0, max_size=1000)  # 10 min TTL


def invalidate_room(room_id: str) -> None:
    """Invalidate all caches related to a room."""
    room_cache.delete(f"room:{room_id}")
    membership_cache.invalidate_prefix(f"member:{room_id}:")


def invalidate_identity(ns: str, identity_id: str) -> None:
    """Invalidate all caches related to an identity."""
    identity_hash_cache.delete(f"identity:{ns}:{identity_id}")
    membership_cache.invalidate_prefix("member:")  # Broad invalidation


def clear_all_caches() -> None:
    """Clear all caches (useful for testing)."""
    room_cache.clear()
    membership_cache.clear()
    identity_hash_cache.clear()
