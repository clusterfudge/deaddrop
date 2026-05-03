"""Metrics layer for deadrop.

This module is the **internal** metrics API used by db.py, api.py, cache.py,
and the instrumentation middleware.  It wraps the pluggable
:mod:`~deadrop.instrument` sink so that all call sites continue to work
unchanged while the underlying transport is configurable at runtime.

Legacy statsd helpers (``statsd_incr``, ``statsd_gauge``, ``statsd_timing``)
are preserved for backward compatibility but now forward to the active
``instrument.sink``.

For new instrumentation code, import ``instrument.sink`` directly.

Per-request query buffer
-------------------------
``_request_query_buffer`` is a :class:`~contextvars.ContextVar` that
:class:`InstrumentedConnection` and :func:`timed_query` append to.  The
middleware in ``api.py`` installs a fresh list at request start and reads it
at request end for slow-request diagnostics.
"""

from __future__ import annotations

import contextvars
import functools
import logging as _logging
import sqlite3 as _sqlite3
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Generator

from . import instrument

# Re-export for convenience (existing ``from .metrics import metrics`` still works)
__all__ = [
    "metrics",
    "timed_db_operation",
    "timed_query",
    "InstrumentedConnection",
    "_request_query_buffer",
    # legacy helpers
    "statsd_incr",
    "statsd_gauge",
    "statsd_timing",
]

# ---------------------------------------------------------------------------
# Per-request query buffer (ContextVar — async-safe)
# ---------------------------------------------------------------------------

_request_query_buffer: contextvars.ContextVar[list[dict] | None] = contextvars.ContextVar(
    "_request_query_buffer", default=None
)

# ---------------------------------------------------------------------------
# Legacy statsd helpers — now forward to instrument.sink
# ---------------------------------------------------------------------------


def statsd_incr(metric: str, count: int = 1) -> None:
    """Increment a counter via the active metrics sink."""
    instrument.sink.counter(metric, count)


def statsd_gauge(metric: str, value: int | float) -> None:
    """Record a gauge via the active metrics sink."""
    instrument.sink.gauge(metric, float(value))


def statsd_timing(metric: str, ms: float) -> None:
    """Record a timing (ms) via the active metrics sink."""
    instrument.sink.timing(metric, ms)


# ---------------------------------------------------------------------------
# In-memory Metrics collector (always active — powers /metrics endpoint)
# ---------------------------------------------------------------------------


class Metrics:
    """Thread-safe in-memory metrics collector.

    Aggregates counters and timing histograms in memory for the ``/metrics``
    admin endpoint.  Also forwards every observation to ``instrument.sink``
    so that whichever external backend is configured receives it too.
    """

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
        if len(self._request_durations[endpoint]) > 1000:
            self._request_durations[endpoint] = self._request_durations[endpoint][-500:]
        self._status_counts[f"{status}"] += 1

        instrument.sink.timing("request.duration_ms", duration_ms, tags={"endpoint": endpoint})
        instrument.sink.counter("request.count", tags={"endpoint": endpoint})
        instrument.sink.counter("response.status", tags={"status": str(status)})

    def record_cache_hit(self, cache_name: str) -> None:
        self._cache_hits[cache_name] += 1
        instrument.sink.counter("cache.hit", tags={"cache": cache_name})

    def record_cache_miss(self, cache_name: str) -> None:
        self._cache_misses[cache_name] += 1
        instrument.sink.counter("cache.miss", tags={"cache": cache_name})

    def record_db_operation(self, operation: str, duration_ms: float) -> None:
        self._db_operation_counts[operation] += 1
        self._db_operation_durations[operation].append(duration_ms)
        if len(self._db_operation_durations[operation]) > 1000:
            self._db_operation_durations[operation] = self._db_operation_durations[operation][-500:]
        instrument.sink.timing("db.operation_ms", duration_ms, tags={"op": operation})

    def incr(self, key: str, count: int = 1) -> None:
        self._counters[key] += count
        instrument.sink.counter(key, count)

    def gauge(self, key: str, value: int | float) -> None:
        instrument.sink.gauge(key, float(value))

    def to_dict(self) -> dict:
        """Export aggregated metrics as a plain dict for the /metrics endpoint."""

        def _summarize(durations: list[float]) -> dict:
            if not durations:
                return {"count": 0}
            s = sorted(durations)
            n = len(s)
            return {
                "count": n,
                "avg_ms": round(sum(s) / n, 1),
                "p50_ms": round(s[n // 2], 1),
                "p95_ms": round(s[int(n * 0.95)], 1) if n >= 20 else None,
                "p99_ms": round(s[int(n * 0.99)], 1) if n >= 100 else None,
                "max_ms": round(s[-1], 1),
            }

        result: dict = {
            "uptime_seconds": round(time.time() - self._start_time),
            "metrics_sink": type(instrument.sink).__name__,
        }

        if self._request_counts:
            result["requests"] = {
                ep: {
                    "count": self._request_counts[ep],
                    **_summarize(self._request_durations.get(ep, [])),
                }
                for ep in sorted(self._request_counts)
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
                    **_summarize(self._db_operation_durations.get(op, [])),
                }
                for op in sorted(self._db_operation_counts)
            }

        if self._counters:
            result["counters"] = dict(sorted(self._counters.items()))

        return result


# Singleton used throughout the codebase
metrics = Metrics()


# ---------------------------------------------------------------------------
# Context manager helpers
# ---------------------------------------------------------------------------


@contextmanager
def timed_db_operation(operation: str) -> Generator[None, None, None]:
    """Time a DB operation and emit metrics on exit."""
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000
        metrics.record_db_operation(operation, elapsed_ms)


# ---------------------------------------------------------------------------
# timed_query decorator
# ---------------------------------------------------------------------------

_db_logger = _logging.getLogger("deadrop.db")


def timed_query(name: str):
    """Decorator: wraps a DB function with per-query timing.

    Emits timing via the active ``instrument.sink`` and appends to the
    per-request query buffer when one is active.

    Usage::

        @timed_query("send_room_message")
        def send_room_message(...):
            ...
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                elapsed_ms = (time.perf_counter() - start) * 1000
                metrics.record_db_operation(f"query.{name}", elapsed_ms)
                buf = _request_query_buffer.get()
                if buf is not None:
                    buf.append({"name": name, "ms": elapsed_ms})
                else:
                    _db_logger.debug("DB query %s: %.1fms", name, elapsed_ms)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Per-SQL-statement instrumentation helpers
# ---------------------------------------------------------------------------


def _record_query(name: str, ms: float) -> None:
    """Emit a per-SQL timing to sink + per-request query buffer."""
    instrument.sink.timing("db.sql_ms", ms, tags={"query": name})
    buf = _request_query_buffer.get()
    if buf is not None:
        buf.append({"name": name, "ms": ms})


# ---------------------------------------------------------------------------
# InstrumentedConnection — transparent proxy with auto-timing
# ---------------------------------------------------------------------------


class InstrumentedConnection:
    """Transparent proxy around a raw DB connection that auto-times SQL.

    Wraps any connection object that supports ``.execute(sql, params)`` and
    ``.commit()`` (sqlite3, libsql, etc.) and records timing for every call
    via :func:`_record_query`.

    All other attributes/methods are forwarded to the underlying connection
    unchanged via ``__getattr__``, so ``row_factory``, ``executescript``,
    ``close``, cursor properties, etc. all work transparently.
    """

    _conn: _sqlite3.Connection
    __slots__ = ("_conn",)

    def __init__(self, conn: _sqlite3.Connection) -> None:
        object.__setattr__(self, "_conn", conn)

    _MISSING = object()

    def execute(self, sql: str, params=(), *, name: str | object = _MISSING) -> _sqlite3.Cursor:
        if name is self._MISSING:
            # Auto-name PRAGMA and utility SQL; reject unnamed real queries
            sql_upper = sql.strip().upper()
            if sql_upper.startswith("PRAGMA"):
                name = "pragma"
            elif sql_upper in ("SELECT 1",):
                name = "health_check"
            elif sql_upper.startswith(("CREATE ", "ALTER ", "DROP ")):
                name = "ddl"
            elif "SQLITE_MASTER" in sql_upper:
                name = "sqlite_master"
            else:
                raise TypeError(
                    f"InstrumentedConnection.execute() requires name= for query: "
                    f"{sql[:80]!r}"
                )
        t0 = time.perf_counter()
        try:
            result = self._conn.execute(sql, params)
        finally:
            _record_query(name, (time.perf_counter() - t0) * 1000)
        return result

    def commit(self) -> None:
        t0 = time.perf_counter()
        try:
            self._conn.commit()
        finally:
            _record_query("commit", (time.perf_counter() - t0) * 1000)

    def __getattr__(self, name: str) -> object:  # noqa: ANN401
        return getattr(object.__getattribute__(self, "_conn"), name)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_conn":
            object.__setattr__(self, name, value)
        else:
            setattr(object.__getattribute__(self, "_conn"), name, value)

    def __repr__(self) -> str:
        return f"InstrumentedConnection({object.__getattribute__(self, '_conn')!r})"
