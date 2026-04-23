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
import sqlite3 as _sqlite3
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
        - DEBUG log:      DB query <name>: <ms>ms

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
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                elapsed_ms = (time.perf_counter() - start) * 1000
                metric_name = f"query.{name}"
                statsd_timing(f"db.{metric_name}", elapsed_ms)
                statsd_incr(f"db.{metric_name}.count")
                # Also feed into the in-memory metrics (same bucket as record_db_operation)
                metrics.record_db_operation(f"query.{name}", elapsed_ms)
                # Append to per-request query buffer if one is active;
                # otherwise fall back to a plain DEBUG log.
                buf = _request_query_buffer.get()
                if buf is not None:
                    buf.append({"name": name, "ms": elapsed_ms})
                else:
                    _db_logger.debug("DB query %s: %.1fms", name, elapsed_ms)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Per-SQL-statement instrumentation
# ---------------------------------------------------------------------------


def _record_query(name: str, ms: float) -> None:
    """Emit a per-SQL-statement timing to statsd + the per-request query buffer.

    This is the single funnel for ``InstrumentedConnection`` timing data.

    Args:
        name: Short name for the query, e.g. ``"select.room_messages"``.
        ms:   Elapsed time in milliseconds.
    """
    statsd_timing(f"db.sql.{name}", ms)
    buf = _request_query_buffer.get()
    if buf is not None:
        buf.append({"name": name, "ms": ms})


# ---------------------------------------------------------------------------
# InstrumentedConnection -- auto-times every execute() / commit()
# ---------------------------------------------------------------------------


class InstrumentedConnection:
    """Transparent proxy around a raw DB connection that auto-times SQL.

    Wraps any connection object that supports ``.execute(sql, params)`` and
    ``.commit()`` (sqlite3, libsql, etc.) and records timing for every call
    via :func:`_record_query`.

    All other attributes/methods are forwarded to the underlying connection
    unchanged via ``__getattr__``, so ``row_factory``, ``executescript``,
    ``close``, cursor properties, etc. all work transparently.

    Usage::

        raw_conn = sqlite3.connect(...)
        conn = InstrumentedConnection(raw_conn)
        # All DAO code uses conn.execute() as normal -- timing is automatic.
    """

    _conn: _sqlite3.Connection
    __slots__ = ("_conn",)

    def __init__(self, conn: _sqlite3.Connection) -> None:
        # Use object.__setattr__ to avoid triggering our own __setattr__
        object.__setattr__(self, "_conn", conn)

    # -- Core instrumented methods --

    def execute(self, sql: str, params=(), *, name: str = "unnamed") -> _sqlite3.Cursor:
        t0 = time.perf_counter()
        try:
            result = self._conn.execute(sql, params)
        finally:
            ms = (time.perf_counter() - t0) * 1000
            _record_query(name, ms)
        return result

    def commit(self) -> None:
        t0 = time.perf_counter()
        try:
            self._conn.commit()
        finally:
            ms = (time.perf_counter() - t0) * 1000
            _record_query("commit", ms)

    # -- Transparent proxy for everything else --

    def __getattr__(self, name: str) -> object:  # noqa: ANN401
        return getattr(object.__getattribute__(self, "_conn"), name)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_conn":
            object.__setattr__(self, name, value)
        else:
            setattr(object.__getattribute__(self, "_conn"), name, value)

    def __repr__(self) -> str:
        return f"InstrumentedConnection({object.__getattribute__(self, '_conn')!r})"
