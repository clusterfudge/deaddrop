"""Simple metrics and telemetry for deadrop.

This module provides:
- Request timing middleware
- Database operation timing
- Cache hit/miss tracking
- Simple in-memory metrics that can be exposed via an endpoint

Metrics are designed to be lightweight and not require external dependencies.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from threading import Lock
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

# Type variable for generic function decoration
F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class TimingStats:
    """Statistics for a timed operation."""

    count: int = 0
    total_ms: float = 0.0
    min_ms: float = float("inf")
    max_ms: float = 0.0

    def record(self, duration_ms: float) -> None:
        """Record a timing measurement."""
        self.count += 1
        self.total_ms += duration_ms
        self.min_ms = min(self.min_ms, duration_ms)
        self.max_ms = max(self.max_ms, duration_ms)

    @property
    def avg_ms(self) -> float:
        """Average duration in milliseconds."""
        return self.total_ms / self.count if self.count > 0 else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "count": self.count,
            "total_ms": round(self.total_ms, 2),
            "avg_ms": round(self.avg_ms, 2),
            "min_ms": round(self.min_ms, 2) if self.count > 0 else 0,
            "max_ms": round(self.max_ms, 2),
        }


@dataclass
class CacheStats:
    """Statistics for cache operations."""

    hits: int = 0
    misses: int = 0

    def record_hit(self) -> None:
        self.hits += 1

    def record_miss(self) -> None:
        self.misses += 1

    @property
    def hit_rate(self) -> float:
        """Cache hit rate as a percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_pct": round(self.hit_rate, 2),
        }


@dataclass
class Metrics:
    """Global metrics collector."""

    _lock: Lock = field(default_factory=Lock)
    db_operations: dict[str, TimingStats] = field(default_factory=lambda: defaultdict(TimingStats))
    cache_stats: dict[str, CacheStats] = field(default_factory=lambda: defaultdict(CacheStats))
    request_stats: dict[str, TimingStats] = field(default_factory=lambda: defaultdict(TimingStats))
    _start_time: float = field(default_factory=time.time)

    def record_db_operation(self, operation: str, duration_ms: float) -> None:
        """Record a database operation timing."""
        with self._lock:
            self.db_operations[operation].record(duration_ms)

    def record_cache_hit(self, cache_name: str) -> None:
        """Record a cache hit."""
        with self._lock:
            self.cache_stats[cache_name].record_hit()

    def record_cache_miss(self, cache_name: str) -> None:
        """Record a cache miss."""
        with self._lock:
            self.cache_stats[cache_name].record_miss()

    def record_request(self, endpoint: str, duration_ms: float) -> None:
        """Record a request timing."""
        with self._lock:
            self.request_stats[endpoint].record(duration_ms)

    def to_dict(self) -> dict:
        """Export metrics as a dictionary."""
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self._start_time, 1),
                "db_operations": {k: v.to_dict() for k, v in self.db_operations.items()},
                "cache": {k: v.to_dict() for k, v in self.cache_stats.items()},
                "requests": {k: v.to_dict() for k, v in self.request_stats.items()},
            }

    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        with self._lock:
            self.db_operations.clear()
            self.cache_stats.clear()
            self.request_stats.clear()
            self._start_time = time.time()


# Global metrics instance
metrics = Metrics()


@contextmanager
def timed_db_operation(operation: str):
    """Context manager to time a database operation.

    Usage:
        with timed_db_operation("get_room"):
            cursor = conn.execute(...)
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        metrics.record_db_operation(operation, duration_ms)
        if duration_ms > 100:  # Log slow queries
            logger.warning(f"Slow DB operation: {operation} took {duration_ms:.1f}ms")


def timed_operation(operation_name: str) -> Callable[[F], F]:
    """Decorator to time a function and record as a DB operation.

    Usage:
        @timed_operation("get_room")
        def get_room(room_id: str) -> dict | None:
            ...
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = (time.perf_counter() - start) * 1000
                metrics.record_db_operation(operation_name, duration_ms)
                if duration_ms > 100:
                    logger.warning(f"Slow operation: {operation_name} took {duration_ms:.1f}ms")

        return wrapper  # type: ignore

    return decorator
