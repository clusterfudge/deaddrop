"""Lightweight statsd + in-memory metrics for deadrop.

Configurable via environment variables:
    STATSD_HOST: StatsD host (default: None = no-op for statsd)
    STATSD_PORT: StatsD port (default: 8125)
    STATSD_PREFIX: Metric prefix (default: deadrop)

When STATSD_HOST is not set, statsd calls are no-ops.
In-memory metrics (for /admin/metrics endpoint) are always collected.
"""

import contextvars
import functools
import logging as _logging
import os
import socket
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Generator

# --- Per-request query buffer (ContextVar so it's async-safe) ---

_request_query_buffer: contextvars.ContextVar[list[dict] | None] = contextvars.ContextVar(
    "_request_query_buffer", default=None
)

# --- Per-call connection-acquire accumulator (ContextVar so it's async-safe) ---
# Reset at the start of each timed_query call, incremented by get_connection().
# Allows timed_query to split total_ms into conn_ms + query_ms.

_conn_acquire_ms: contextvars.ContextVar[float] = contextvars.ContextVar(
    "_conn_acquire_ms", default=0.0
)

# --- StatsD transport ---

_STATSD_HOST = os.environ.get("STATSD_HOST")
_STATSD_PORT = int(os.environ.get("STATSD_PORT", "8125"))
_PREFIX = os.environ.get("STATSD_PREFIX", "deadrop")
_sock: socket.socket | None = None


def _get_sock() -> socket.socket | None:
    global _sock
    if _STATSD_HOST is None:
        return None
    if _sock is None:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return _sock


def _statsd_send(metric: str, value: str, metric_type: str, sample_rate: float = 1.0) -> None:
    sock = _get_sock()
    if sock is None:
        return
    try:
        key = f"{_PREFIX}.{metric}" if _PREFIX else metric
        payload = f"{key}:{value}|{metric_type}"
        if sample_rate < 1.0:
            payload += f"|@{sample_rate}"
        sock.sendto(payload.encode(), (_STATSD_HOST, _STATSD_PORT))
    except Exception:
        pass


def statsd_incr(metric: str, count: int = 1) -> None:
    _statsd_send(metric, str(count), "c")


def statsd_gauge(metric: str, value: int | float) -> None:
    _statsd_send(metric, str(value), "g")


def statsd_timing(metric: str, ms: float) -> None:
    _statsd_send(metric, f"{ms:.1f}", "ms")


# --- In-memory metrics (always active) ---


class Metrics:
    """Thread-safe in-memory metrics collector + statsd emitter."""

    def __init__(self) -> None:
        self._request_counts: dict[str, int] = defaultdict(int)
        self._request_durations: dict[str, list[float]] = defaultdict(list)
        self._status_counts: dict[str, int] = defaultdict(int)
        self._cache_hits: dict[str, int] = defaultdict(int)
        self._cache_misses: dict[str, int] = defaultdict(int)
        self._db_operation_counts: dict[str, int] = defaultdict(int)
        self._db_operation_durations: dict[str, list[float]] = defaultdict(list)
        self._counters: dict[str, int] = defaultdict(int)
        self._start_time = time.time()

    def record_request(self, endpoint: str, duration_ms: float, status: int = 200) -> None:
        self._request_counts[endpoint] += 1
        self._request_durations[endpoint].append(duration_ms)
        # Keep only last 1000 durations per endpoint
        if len(self._request_durations[endpoint]) > 1000:
            self._request_durations[endpoint] = self._request_durations[endpoint][-500:]
        self._status_counts[f"{status}"] += 1

        # StatsD
        statsd_timing(f"request.{endpoint}", duration_ms)
        statsd_incr(f"request.{endpoint}.count")
        statsd_incr(f"response.{status}")

    def record_cache_hit(self, cache_name: str) -> None:
        self._cache_hits[cache_name] += 1
        statsd_incr(f"cache.{cache_name}.hit")

    def record_cache_miss(self, cache_name: str) -> None:
        self._cache_misses[cache_name] += 1
        statsd_incr(f"cache.{cache_name}.miss")

    def record_db_operation(self, operation: str, duration_ms: float) -> None:
        self._db_operation_counts[operation] += 1
        self._db_operation_durations[operation].append(duration_ms)
        if len(self._db_operation_durations[operation]) > 1000:
            self._db_operation_durations[operation] = self._db_operation_durations[operation][-500:]
        statsd_timing(f"db.{operation}", duration_ms)

    def incr(self, key: str, count: int = 1) -> None:
        self._counters[key] += count
        statsd_incr(key, count)

    def gauge(self, key: str, value: int | float) -> None:
        statsd_gauge(key, value)

    def to_dict(self) -> dict:
        """Export metrics for the /admin/metrics endpoint."""

        def _summarize_durations(durations: list[float]) -> dict:
            if not durations:
                return {"count": 0}
            sorted_d = sorted(durations)
            n = len(sorted_d)
            return {
                "count": n,
                "avg_ms": round(sum(sorted_d) / n, 1),
                "p50_ms": round(sorted_d[n // 2], 1),
                "p95_ms": round(sorted_d[int(n * 0.95)], 1) if n >= 20 else None,
                "p99_ms": round(sorted_d[int(n * 0.99)], 1) if n >= 100 else None,
                "max_ms": round(sorted_d[-1], 1),
            }

        result: dict = {
            "uptime_seconds": round(time.time() - self._start_time),
            "statsd_enabled": _STATSD_HOST is not None,
        }

        if self._request_counts:
            result["requests"] = {
                endpoint: {
                    "count": self._request_counts[endpoint],
                    **_summarize_durations(self._request_durations.get(endpoint, [])),
                }
                for endpoint in sorted(self._request_counts)
            }

        if self._status_counts:
            result["status_codes"] = dict(sorted(self._status_counts.items()))

        if self._cache_hits or self._cache_misses:
            all_caches = set(self._cache_hits) | set(self._cache_misses)
            result["cache"] = {}
            for name in sorted(all_caches):
                hits = self._cache_hits.get(name, 0)
                misses = self._cache_misses.get(name, 0)
                total = hits + misses
                result["cache"][name] = {
                    "hits": hits,
                    "misses": misses,
                    "hit_rate": round(hits / total, 3) if total > 0 else 0,
                }

        if self._db_operation_counts:
            result["db_operations"] = {
                op: {
                    "count": self._db_operation_counts[op],
                    **_summarize_durations(self._db_operation_durations.get(op, [])),
                }
                for op in sorted(self._db_operation_counts)
            }

        if self._counters:
            result["counters"] = dict(sorted(self._counters.items()))

        return result


# Singleton
metrics = Metrics()


@contextmanager
def timed_db_operation(operation: str) -> Generator[None, None, None]:
    """Context manager to time a DB operation and record metrics."""
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000
        metrics.record_db_operation(operation, elapsed_ms)


_db_logger = _logging.getLogger("deadrop.db")


def timed_query(name: str):
    """Decorator that wraps a DB function with per-query timing.

    Emits:
        - statsd timing:  deadrop.db.query.<name>  (ms)
        - statsd counter: deadrop.db.query.<name>.count
        - statsd timing:  deadrop.db.conn_acquire.<name>  (ms) — connection-acquire portion
        - DEBUG log:      DB query <name>: total=<ms>ms conn=<ms>ms query=<ms>ms

    The buffer entry format is::

        {"name": str, "total_ms": float, "conn_ms": float, "query_ms": float}

    where ``conn_ms`` is the time spent in ``get_connection()`` / ``_get_conn()``
    (accumulated via the ``_conn_acquire_ms`` ContextVar) and ``query_ms`` is
    the remainder (actual SQL execution + row processing).

    Usage::

        @timed_query("send_room_message")
        def send_room_message(...):
            ...

    The decorator is transparent — it preserves the function's signature,
    return value, and exceptions.  statsd is fire-and-forget UDP so there
    is no meaningful overhead.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Reset the conn-acquire accumulator for this call so we get a
            # clean reading that belongs only to this invocation.
            _conn_acquire_ms.set(0.0)
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                total_ms = (time.perf_counter() - start) * 1000
                conn_ms = _conn_acquire_ms.get()
                query_ms = max(total_ms - conn_ms, 0.0)

                metric_name = f"query.{name}"
                statsd_timing(f"db.{metric_name}", total_ms)
                statsd_incr(f"db.{metric_name}.count")
                statsd_timing(f"db.conn_acquire.{name}", conn_ms)
                # Also feed into the in-memory metrics (same bucket as record_db_operation)
                metrics.record_db_operation(f"query.{name}", total_ms)
                # Append to per-request query buffer if one is active;
                # otherwise fall back to a plain DEBUG log.
                buf = _request_query_buffer.get()
                if buf is not None:
                    buf.append(
                        {
                            "name": name,
                            "total_ms": total_ms,
                            "conn_ms": conn_ms,
                            "query_ms": query_ms,
                        }
                    )
                else:
                    _db_logger.debug(
                        "DB query %s: total=%.1fms conn=%.1fms query=%.1fms",
                        name,
                        total_ms,
                        conn_ms,
                        query_ms,
                    )

        return wrapper

    return decorator
