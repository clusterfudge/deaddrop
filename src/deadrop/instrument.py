"""Pluggable instrumentation for deadrop.

Provides a generic MetricsSink protocol and multiple backend implementations.
All instrumentation is no-op by default — enable via environment variable.

Configuration
-------------
``DEADROP_METRICS_SINK``
    Which sink to activate.  Choices: ``null`` (default), ``logging``,
    ``statsd``, ``prometheus``.

``DEADROP_METRICS_PREFIX``
    Prefix prepended to every metric name (default: ``deadrop``).

``DEADROP_METRICS_STATSD_HOST``
    StatsD host (required when sink=statsd).

``DEADROP_METRICS_STATSD_PORT``
    StatsD UDP port (default: ``8125``).

``DEADROP_DEBUG_STATE_AUTH``
    Secret token required to access ``/debug/state``.  When unset the
    endpoint falls back to the existing admin-token check.

Usage
-----
All instrumentation code should import the module-level ``sink`` singleton::

    from .instrument import sink

    sink.counter("thing.happened")
    sink.gauge("queue.depth", len(q))

    with sink.timed("db.query"):
        ...

The ``sink`` object is always available; when ``DEADROP_METRICS_SINK=null``
every call is a no-op with essentially zero overhead.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any, Generator, Protocol, runtime_checkable

logger = logging.getLogger("deadrop.instrument")

# ---------------------------------------------------------------------------
# Protocol — what every sink must implement
# ---------------------------------------------------------------------------


@runtime_checkable
class MetricsSink(Protocol):
    """Generic metrics emission interface.

    All methods are fire-and-forget; implementations must never raise.

    Tags are optional ``{key: value}`` dicts.  Sinks that don't support
    tags (e.g. plain statsd) should fold them into the metric name or
    silently ignore them.
    """

    def counter(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        """Increment a counter."""
        ...

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Record a point-in-time gauge value."""
        ...

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Record a value in a histogram distribution."""
        ...

    def timing(self, name: str, value_ms: float, tags: dict[str, str] | None = None) -> None:
        """Record a duration in milliseconds."""
        ...


# ---------------------------------------------------------------------------
# NullSink — default, zero-overhead no-op
# ---------------------------------------------------------------------------


class NullSink:
    """No-op sink.  All calls discard their arguments immediately."""

    __slots__ = ()

    def counter(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:  # noqa: D102
        pass

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:  # noqa: D102
        pass

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:  # noqa: D102
        pass

    def timing(self, name: str, value_ms: float, tags: dict[str, str] | None = None) -> None:  # noqa: D102
        pass


# ---------------------------------------------------------------------------
# LoggingSink — emits to stderr via the standard logging module
# ---------------------------------------------------------------------------


class LoggingSink:
    """Emits metrics as DEBUG-level log lines.

    Useful for development / smoke-testing without a metrics backend.
    """

    __slots__ = ("_log", "_prefix")

    def __init__(self, prefix: str = "deadrop") -> None:
        self._log = logging.getLogger("deadrop.metrics")
        self._prefix = prefix

    def _n(self, name: str) -> str:
        return f"{self._prefix}.{name}" if self._prefix else name

    def counter(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        self._log.debug("counter %s=%d tags=%s", self._n(name), value, tags)

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        self._log.debug("gauge   %s=%g tags=%s", self._n(name), value, tags)

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        self._log.debug("hist    %s=%g tags=%s", self._n(name), value, tags)

    def timing(self, name: str, value_ms: float, tags: dict[str, str] | None = None) -> None:
        self._log.debug("timing  %s=%.1fms tags=%s", self._n(name), value_ms, tags)


# ---------------------------------------------------------------------------
# StatsdSink — UDP push, no third-party deps
# ---------------------------------------------------------------------------


class StatsdSink:
    """Statsd / DogStatsD UDP sink.

    Supports DogStatsD-style tags when ``dogstatsd=True``.  Falls back to
    folding tag key=value pairs into the metric name (``metric.k_v``) when
    ``dogstatsd=False``.

    All socket errors are swallowed — metrics must never break the app.
    """

    __slots__ = ("_host", "_port", "_prefix", "_dogstatsd", "_sock")

    def __init__(
        self,
        host: str,
        port: int = 8125,
        prefix: str = "deadrop",
        dogstatsd: bool = False,
    ) -> None:
        self._host = host
        self._port = port
        self._prefix = prefix
        self._dogstatsd = dogstatsd
        self._sock: socket.socket | None = None

    def _get_sock(self) -> socket.socket | None:
        if self._sock is None:
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except Exception:
                return None
        return self._sock

    def _tag_suffix(self, tags: dict[str, str] | None) -> str:
        if not tags:
            return ""
        if self._dogstatsd:
            parts = ",".join(f"{k}:{v}" for k, v in sorted(tags.items()))
            return f"|#{parts}"
        # Fold into metric name
        return "." + ".".join(f"{k}_{v}" for k, v in sorted(tags.items()))

    def _name(self, name: str, tags: dict[str, str] | None) -> str:
        base = f"{self._prefix}.{name}" if self._prefix else name
        if self._dogstatsd:
            return base
        return base + self._tag_suffix(tags)

    def _send(self, payload: str, tags: dict[str, str] | None = None) -> None:
        if self._dogstatsd and tags:
            payload += self._tag_suffix(tags)
        sock = self._get_sock()
        if sock is None:
            return
        try:
            sock.sendto(payload.encode(), (self._host, self._port))
        except Exception:
            pass

    def counter(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        self._send(f"{self._name(name, tags)}:{value}|c", tags)

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        self._send(f"{self._name(name, tags)}:{value}|g", tags)

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        self._send(f"{self._name(name, tags)}:{value}|h", tags)

    def timing(self, name: str, value_ms: float, tags: dict[str, str] | None = None) -> None:
        self._send(f"{self._name(name, tags)}:{value_ms:.1f}|ms", tags)


# ---------------------------------------------------------------------------
# PrometheusSink — opt-in /metrics endpoint (requires prometheus_client)
# ---------------------------------------------------------------------------


class PrometheusSink:
    """Prometheus sink backed by the ``prometheus_client`` library.

    ``prometheus_client`` is an optional dependency.  If it is not installed
    this sink raises ``ImportError`` at construction time so the error is
    caught at startup rather than on first metric emit.
    """

    def __init__(self, prefix: str = "deadrop") -> None:
        try:
            import prometheus_client as prom  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "prometheus_client is required for PrometheusSink — "
                "install it with: pip install prometheus_client"
            ) from exc
        self._prom = prom
        self._prefix = prefix.replace(".", "_").replace("-", "_")
        self._counters: dict[str, Any] = {}
        self._gauges: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}

    def _safe_name(self, name: str) -> str:
        return f"{self._prefix}_{name}".replace(".", "_").replace("-", "_")

    def counter(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        sname = self._safe_name(name)
        if sname not in self._counters:
            self._counters[sname] = self._prom.Counter(sname, sname)
        try:
            self._counters[sname].inc(value)
        except Exception:
            pass

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        sname = self._safe_name(name)
        if sname not in self._gauges:
            self._gauges[sname] = self._prom.Gauge(sname, sname)
        try:
            self._gauges[sname].set(value)
        except Exception:
            pass

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        sname = self._safe_name(name)
        if sname not in self._histograms:
            self._histograms[sname] = self._prom.Histogram(sname, sname)
        try:
            self._histograms[sname].observe(value)
        except Exception:
            pass

    def timing(self, name: str, value_ms: float, tags: dict[str, str] | None = None) -> None:
        self.histogram(name, value_ms / 1000.0, tags)

    def generate_latest(self) -> bytes:  # pragma: no cover
        """Return Prometheus text format exposition for /metrics."""
        return self._prom.generate_latest()


# ---------------------------------------------------------------------------
# Factory — build sink from environment
# ---------------------------------------------------------------------------


def _build_sink_from_env() -> MetricsSink:
    sink_name = os.environ.get("DEADROP_METRICS_SINK", "null").lower().strip()
    prefix = os.environ.get("DEADROP_METRICS_PREFIX", "deadrop")

    if sink_name == "null":
        return NullSink()

    if sink_name == "logging":
        logger.info("Metrics sink: logging (prefix=%s)", prefix)
        return LoggingSink(prefix=prefix)

    if sink_name == "statsd":
        host = os.environ.get("DEADROP_METRICS_STATSD_HOST", "")
        if not host:
            logger.warning(
                "DEADROP_METRICS_SINK=statsd but DEADROP_METRICS_STATSD_HOST is unset "
                "— falling back to null sink"
            )
            return NullSink()
        port = int(os.environ.get("DEADROP_METRICS_STATSD_PORT", "8125"))
        dogstatsd = os.environ.get("DEADROP_METRICS_DOGSTATSD", "").lower() in ("1", "true", "yes")
        logger.info(
            "Metrics sink: statsd %s:%d (dogstatsd=%s, prefix=%s)", host, port, dogstatsd, prefix
        )
        return StatsdSink(host=host, port=port, prefix=prefix, dogstatsd=dogstatsd)

    if sink_name in ("prom", "prometheus"):
        logger.info("Metrics sink: prometheus (prefix=%s)", prefix)
        return PrometheusSink(prefix=prefix)

    logger.warning("Unknown DEADROP_METRICS_SINK=%r — falling back to null sink", sink_name)
    return NullSink()


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly
# ---------------------------------------------------------------------------

#: The active metrics sink.  Import and call it from anywhere.
sink: MetricsSink = NullSink()  # replaced by init_sink() at app startup


def init_sink() -> MetricsSink:
    """Initialise the module-level ``sink`` from environment variables.

    Called once from ``lifespan()`` in ``api.py``.  Safe to call multiple
    times — subsequent calls replace the singleton.
    """
    global sink
    sink = _build_sink_from_env()
    return sink


# ---------------------------------------------------------------------------
# Convenience context manager
# ---------------------------------------------------------------------------


@contextmanager
def timed(name: str, tags: dict[str, str] | None = None) -> Generator[None, None, None]:
    """Context manager that records a timing metric on exit.

    Usage::

        with instrument.timed("db.write"):
            conn.execute(...)
    """
    t0 = time.perf_counter()
    try:
        yield
    finally:
        sink.timing(name, (time.perf_counter() - t0) * 1000, tags)


# ---------------------------------------------------------------------------
# Background sampler — event loop lag, thread state, memory, GC
# ---------------------------------------------------------------------------

_SAMPLER_INTERVAL = float(os.environ.get("DEADROP_METRICS_SAMPLE_INTERVAL", "10"))

# Shared state written by the sampler, read by /debug/state
_sampler_state: dict[str, Any] = {}


async def _event_loop_heartbeat(interval: float = 1.0) -> None:
    """Continuously measure event loop lag.

    Schedules itself every ``interval`` seconds and computes the actual wall
    time elapsed since the last schedule.  The difference is the event loop
    lag — how long callbacks were delayed.

    Writes the latest lag to ``_sampler_state`` and emits a gauge.
    """
    last = time.perf_counter()
    while True:
        await asyncio.sleep(interval)
        now = time.perf_counter()
        lag_ms = max(0.0, (now - last - interval) * 1000)
        last = now
        sink.gauge("eventloop.lag_ms", lag_ms)
        _sampler_state["eventloop_lag_ms"] = round(lag_ms, 2)


async def _periodic_sampler(interval: float = _SAMPLER_INTERVAL) -> None:
    """Background task that samples process-wide metrics every ``interval`` seconds.

    Covers:
    * asyncio task count + long-running tasks (> 30 s)
    * thread counts (total + per named pool)
    * process RSS (via /proc/self/status on Linux, fallback to psutil if available)
    * GC generation counts and stats
    """
    long_task_threshold = float(os.environ.get("DEADROP_LONG_TASK_THRESHOLD", "30"))

    while True:
        await asyncio.sleep(interval)
        try:
            _sample_tasks(long_task_threshold)
            _sample_threads()
            _sample_memory()
            _sample_gc()
        except Exception:
            logger.debug("Sampler tick error", exc_info=True)


def _sample_tasks(long_task_threshold: float) -> None:
    loop = asyncio.get_event_loop()
    all_tasks = asyncio.all_tasks(loop)
    pending = len(all_tasks)
    sink.gauge("asyncio.pending_tasks", pending)
    _sampler_state["asyncio_pending_tasks"] = pending

    long_running = []
    now = loop.time()
    for t in all_tasks:
        # asyncio.Task stores _started in Python >= 3.12; use private attr with fallback
        started = getattr(t, "_started", None) or getattr(t, "_loop_start", None)
        if started is not None:
            age = now - started
            if age > long_task_threshold:
                coro_name = getattr(t.get_coro(), "__qualname__", str(t))
                long_running.append({"name": coro_name, "age_s": round(age, 1)})
    sink.gauge("asyncio.long_tasks", len(long_running))
    _sampler_state["asyncio_long_tasks"] = long_running


def _sample_threads() -> None:
    all_threads = threading.enumerate()
    total = len(all_threads)
    sink.gauge("threads.total", total)
    _sampler_state["threads_total"] = total

    # Count per named pool (FastAPI/Starlette use "ThreadPoolExecutor-N_M" names)
    pool_counts: dict[str, int] = {}
    for t in all_threads:
        name = t.name or ""
        if "ThreadPoolExecutor" in name:
            # Extract pool index before the underscore separator
            parts = name.split("_")
            pool_key = parts[0] if parts else name
            pool_counts[pool_key] = pool_counts.get(pool_key, 0) + 1
    sink.gauge("threads.pools", len(pool_counts))
    _sampler_state["thread_pools"] = pool_counts


def _sample_memory() -> None:
    rss_kb: int | None = None
    # Fast path: Linux /proc
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
    except OSError:
        pass

    if rss_kb is None:
        # Fallback: psutil (optional)
        try:
            import psutil  # type: ignore[import]

            proc = psutil.Process()
            rss_kb = proc.memory_info().rss // 1024
        except Exception:
            pass

    if rss_kb is not None:
        sink.gauge("process.rss_kb", rss_kb)
        _sampler_state["process_rss_kb"] = rss_kb


def _sample_gc() -> None:
    counts = gc.get_count()  # (gen0, gen1, gen2)
    for i, c in enumerate(counts):
        sink.gauge(f"gc.gen{i}_count", c)
    _sampler_state["gc_counts"] = {"gen0": counts[0], "gen1": counts[1], "gen2": counts[2]}

    stats = gc.get_stats()  # list of dicts per generation
    gc_stats_out = []
    for i, s in enumerate(stats):
        gc_stats_out.append(
            {
                "gen": i,
                "collections": s.get("collections", 0),
                "collected": s.get("collected", 0),
                "uncollectable": s.get("uncollectable", 0),
            }
        )
    _sampler_state["gc_stats"] = gc_stats_out


# ---------------------------------------------------------------------------
# Active request tracking (written by middleware in api.py)
# ---------------------------------------------------------------------------

# {endpoint: count}  — updated atomically by the middleware
_active_requests: dict[str, int] = {}
_active_requests_lock = threading.Lock()

# Running list of (start_time, endpoint) for in-flight requests
_inflight: list[tuple[float, str]] = []
_inflight_lock = threading.Lock()


def request_start(endpoint: str) -> float:
    """Record a request starting.  Returns the start timestamp."""
    t = time.perf_counter()
    with _active_requests_lock:
        _active_requests[endpoint] = _active_requests.get(endpoint, 0) + 1
    with _inflight_lock:
        _inflight.append((t, endpoint))
    sink.counter("request.started", tags={"endpoint": endpoint})
    return t


def request_end(endpoint: str, start_t: float, status: int) -> None:
    """Record a request finishing."""
    duration_ms = (time.perf_counter() - start_t) * 1000
    with _active_requests_lock:
        _active_requests[endpoint] = max(0, _active_requests.get(endpoint, 1) - 1)
    with _inflight_lock:
        try:
            _inflight.remove((start_t, endpoint))
        except ValueError:
            pass
    sink.timing("request.duration_ms", duration_ms, tags={"endpoint": endpoint})
    sink.counter("request.completed", tags={"endpoint": endpoint, "status": str(status)})


def get_active_requests_snapshot() -> dict[str, Any]:
    """Return a snapshot of active/in-flight request state for /debug/state."""
    now = time.perf_counter()
    with _active_requests_lock:
        active = dict(_active_requests)
    with _inflight_lock:
        inflight_snap = list(_inflight)

    longest = 0.0
    inflight_detail = []
    for start_t, ep in inflight_snap:
        age_ms = (now - start_t) * 1000
        longest = max(longest, age_ms)
        inflight_detail.append({"endpoint": ep, "age_ms": round(age_ms, 1)})

    return {
        "active_by_endpoint": active,
        "total_active": sum(active.values()),
        "longest_active_ms": round(longest, 1),
        "inflight": inflight_detail,
    }


# ---------------------------------------------------------------------------
# Full debug state snapshot (for /debug/state endpoint)
# ---------------------------------------------------------------------------


def get_debug_state() -> dict[str, Any]:
    """Return a full system state snapshot as a plain dict.

    Combines:
    * Sampler state (event loop lag, threads, memory, GC)
    * Active request state
    * Current time / uptime
    """
    return {
        "timestamp": time.time(),
        "sampler": dict(_sampler_state),
        "requests": get_active_requests_snapshot(),
        "sink": type(sink).__name__,
        "sample_interval_s": _SAMPLER_INTERVAL,
    }


# ---------------------------------------------------------------------------
# Startup helper — called from lifespan
# ---------------------------------------------------------------------------


def start_background_tasks() -> None:
    """Schedule background instrumentation tasks on the running event loop.

    Must be called from within a running async context (i.e. inside
    ``lifespan``).
    """
    asyncio.create_task(_event_loop_heartbeat(), name="instrument.heartbeat")
    asyncio.create_task(_periodic_sampler(), name="instrument.sampler")
    logger.debug("Instrumentation background tasks started (sink=%s)", type(sink).__name__)
