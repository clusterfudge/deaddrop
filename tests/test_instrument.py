"""Tests for the pluggable instrumentation module (deadrop.instrument).

Covers:
- NullSink: all methods are no-ops, never raise
- LoggingSink: emits DEBUG-level log lines
- StatsdSink: sends correct UDP payloads (mocked socket)
- Factory: _build_sink_from_env returns correct sink for each DEADROP_METRICS_SINK value
- init_sink: replaces module-level singleton
- timed(): context manager records timing to sink
- get_debug_state(): returns expected keys
- request_start / request_end: update _active_requests and _inflight
- get_active_requests_snapshot: returns sane structure
"""

from __future__ import annotations

import os
import socket
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from deadrop import instrument
from deadrop.instrument import (
    LoggingSink,
    MetricsSink,
    NullSink,
    StatsdSink,
    _build_sink_from_env,
    get_active_requests_snapshot,
    get_debug_state,
    init_sink,
    request_end,
    request_start,
    timed,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class RecordingSink:
    """Test sink that records all calls."""

    def __init__(self):
        self.calls: list[tuple[str, str, Any, dict | None]] = []

    def counter(self, name, value=1, tags=None):
        self.calls.append(("counter", name, value, tags))

    def gauge(self, name, value, tags=None):
        self.calls.append(("gauge", name, value, tags))

    def histogram(self, name, value, tags=None):
        self.calls.append(("histogram", name, value, tags))

    def timing(self, name, value_ms, tags=None):
        self.calls.append(("timing", name, value_ms, tags))

    def of_type(self, method: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == method]


@contextmanager
def swap_sink(new_sink):
    """Context manager: temporarily replace instrument.sink."""
    original = instrument.sink
    instrument.sink = new_sink
    try:
        yield new_sink
    finally:
        instrument.sink = original


# ---------------------------------------------------------------------------
# NullSink
# ---------------------------------------------------------------------------


class TestNullSink:
    def setup_method(self):
        self.sink = NullSink()

    def test_counter_no_raise(self):
        self.sink.counter("foo", 5, tags={"k": "v"})

    def test_gauge_no_raise(self):
        self.sink.gauge("bar", 3.14)

    def test_histogram_no_raise(self):
        self.sink.histogram("baz", 42.0)

    def test_timing_no_raise(self):
        self.sink.timing("qux", 123.4)

    def test_implements_protocol(self):
        assert isinstance(self.sink, MetricsSink)


# ---------------------------------------------------------------------------
# LoggingSink
# ---------------------------------------------------------------------------


class TestLoggingSink:
    def test_counter_logs_debug(self, caplog):
        import logging

        sink = LoggingSink(prefix="test")
        with caplog.at_level(logging.DEBUG, logger="deadrop.metrics"):
            sink.counter("things.happened", 3)
        assert any(
            "counter" in r.message and "things.happened" in r.message for r in caplog.records
        )

    def test_gauge_logs_debug(self, caplog):
        import logging

        sink = LoggingSink(prefix="test")
        with caplog.at_level(logging.DEBUG, logger="deadrop.metrics"):
            sink.gauge("queue.depth", 7.0)
        assert any("gauge" in r.message and "queue.depth" in r.message for r in caplog.records)

    def test_timing_logs_debug(self, caplog):
        import logging

        sink = LoggingSink(prefix="test")
        with caplog.at_level(logging.DEBUG, logger="deadrop.metrics"):
            sink.timing("db.query", 55.5)
        assert any("timing" in r.message and "db.query" in r.message for r in caplog.records)

    def test_prefix_applied(self, caplog):
        import logging

        sink = LoggingSink(prefix="myapp")
        with caplog.at_level(logging.DEBUG, logger="deadrop.metrics"):
            sink.counter("events", 1)
        assert any("myapp.events" in r.message for r in caplog.records)

    def test_implements_protocol(self):
        assert isinstance(LoggingSink(), MetricsSink)


# ---------------------------------------------------------------------------
# StatsdSink
# ---------------------------------------------------------------------------


class TestStatsdSink:
    def _make_sink(self, **kwargs) -> tuple[StatsdSink, MagicMock]:
        sink = StatsdSink(host="localhost", port=9999, **kwargs)
        mock_sock = MagicMock(spec=socket.socket)
        # Inject the mock socket
        object.__setattr__(sink, "_sock", mock_sock)
        return sink, mock_sock

    def _sent_payload(self, mock_sock: MagicMock) -> str:
        args, kwargs = mock_sock.sendto.call_args
        return args[0].decode()

    def test_counter_sends_correct_payload(self):
        sink, sock = self._make_sink(prefix="app")
        sink.counter("foo.bar", 2)
        payload = self._sent_payload(sock)
        assert payload == "app.foo.bar:2|c"

    def test_gauge_sends_correct_payload(self):
        sink, sock = self._make_sink(prefix="app")
        sink.gauge("mem.rss", 1234.5)
        payload = self._sent_payload(sock)
        assert payload == "app.mem.rss:1234.5|g"

    def test_timing_sends_correct_payload(self):
        sink, sock = self._make_sink(prefix="app")
        sink.timing("req.duration", 42.7)
        payload = self._sent_payload(sock)
        assert payload == "app.req.duration:42.7|ms"

    def test_histogram_sends_correct_payload(self):
        sink, sock = self._make_sink(prefix="app")
        sink.histogram("latency", 100.0)
        payload = self._sent_payload(sock)
        assert payload == "app.latency:100.0|h"

    def test_tags_folded_into_name(self):
        sink, sock = self._make_sink(prefix="app", dogstatsd=False)
        sink.counter("req", 1, tags={"endpoint": "health", "status": "200"})
        payload = self._sent_payload(sock)
        # Tags folded alphabetically: endpoint_health.status_200
        assert "endpoint_health" in payload
        assert "status_200" in payload

    def test_dogstatsd_tags_appended(self):
        sink, sock = self._make_sink(prefix="app", dogstatsd=True)
        sink.counter("req", 1, tags={"endpoint": "health"})
        payload = self._sent_payload(sock)
        assert "|#endpoint:health" in payload

    def test_socket_error_swallowed(self):
        sink, sock = self._make_sink(prefix="app")
        sock.sendto.side_effect = OSError("unreachable")
        sink.counter("foo", 1)  # should not raise

    def test_no_prefix(self):
        sink, sock = self._make_sink(prefix="")
        sink.counter("bare.metric", 1)
        payload = self._sent_payload(sock)
        assert payload == "bare.metric:1|c"

    def test_implements_protocol(self):
        assert isinstance(StatsdSink(host="localhost"), MetricsSink)


# ---------------------------------------------------------------------------
# Factory: _build_sink_from_env
# ---------------------------------------------------------------------------


class TestBuildSinkFromEnv:
    def test_default_is_null(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEADROP_METRICS_SINK", None)
            s = _build_sink_from_env()
        assert isinstance(s, NullSink)

    def test_null_explicit(self):
        with patch.dict(os.environ, {"DEADROP_METRICS_SINK": "null"}):
            s = _build_sink_from_env()
        assert isinstance(s, NullSink)

    def test_logging_sink(self):
        with patch.dict(os.environ, {"DEADROP_METRICS_SINK": "logging"}):
            s = _build_sink_from_env()
        assert isinstance(s, LoggingSink)

    def test_statsd_sink(self):
        with patch.dict(
            os.environ,
            {"DEADROP_METRICS_SINK": "statsd", "DEADROP_METRICS_STATSD_HOST": "localhost"},
        ):
            s = _build_sink_from_env()
        assert isinstance(s, StatsdSink)

    def test_statsd_without_host_falls_back_to_null(self):
        env = {"DEADROP_METRICS_SINK": "statsd"}
        env_clean = {k: v for k, v in os.environ.items() if k != "DEADROP_METRICS_STATSD_HOST"}
        with patch.dict(env_clean, env, clear=True):
            s = _build_sink_from_env()
        assert isinstance(s, NullSink)

    def test_unknown_sink_falls_back_to_null(self):
        with patch.dict(os.environ, {"DEADROP_METRICS_SINK": "xyzzy"}):
            s = _build_sink_from_env()
        assert isinstance(s, NullSink)

    def test_prefix_applied_to_logging_sink(self):
        with patch.dict(
            os.environ,
            {"DEADROP_METRICS_SINK": "logging", "DEADROP_METRICS_PREFIX": "myapp"},
        ):
            s = _build_sink_from_env()
        assert isinstance(s, LoggingSink)
        assert s._prefix == "myapp"


# ---------------------------------------------------------------------------
# init_sink
# ---------------------------------------------------------------------------


class TestInitSink:
    def test_replaces_singleton(self):
        original = instrument.sink
        try:
            with patch.dict(os.environ, {"DEADROP_METRICS_SINK": "logging"}):
                returned = init_sink()
            assert isinstance(instrument.sink, LoggingSink)
            assert returned is instrument.sink
        finally:
            instrument.sink = original


# ---------------------------------------------------------------------------
# timed() context manager
# ---------------------------------------------------------------------------


class TestTimed:
    def test_timed_records_timing(self):
        with swap_sink(RecordingSink()) as rsink:
            with timed("my.operation"):
                pass
            timings = rsink.of_type("timing")
            assert len(timings) == 1
            _, name, value_ms, tags = timings[0]
            assert name == "my.operation"
            assert isinstance(value_ms, float)
            assert value_ms >= 0.0

    def test_timed_with_tags(self):
        with swap_sink(RecordingSink()) as rsink:
            with timed("db.query", tags={"op": "select"}):
                pass
            timings = rsink.of_type("timing")
            assert timings[0][3] == {"op": "select"}

    def test_timed_records_even_on_exception(self):
        with swap_sink(RecordingSink()) as rsink:
            with pytest.raises(ValueError):
                with timed("risky.op"):
                    raise ValueError("oops")
            assert len(rsink.of_type("timing")) == 1


# ---------------------------------------------------------------------------
# request_start / request_end / get_active_requests_snapshot
# ---------------------------------------------------------------------------


class TestRequestTracking:
    def setup_method(self):
        # Clear shared state before each test
        instrument._active_requests.clear()
        instrument._inflight.clear()

    def teardown_method(self):
        instrument._active_requests.clear()
        instrument._inflight.clear()

    def test_request_start_increments_active(self):
        with swap_sink(RecordingSink()):
            request_start("health")
        assert instrument._active_requests.get("health", 0) == 1

    def test_request_end_decrements_active(self):
        with swap_sink(RecordingSink()):
            t = request_start("health")
            request_end("health", t, 200)
        assert instrument._active_requests.get("health", 0) == 0

    def test_request_end_emits_timing(self):
        with swap_sink(RecordingSink()) as rsink:
            t = request_start("inbox.GET")
            request_end("inbox.GET", t, 200)
        timings = rsink.of_type("timing")
        assert any(name == "request.duration_ms" for _, name, _, _ in timings)

    def test_request_end_emits_counter(self):
        with swap_sink(RecordingSink()) as rsink:
            t = request_start("inbox.GET")
            request_end("inbox.GET", t, 404)
        counters = rsink.of_type("counter")
        assert any(
            name == "request.completed" and tags == {"endpoint": "inbox.GET", "status": "404"}
            for _, name, _, tags in counters
        )

    def test_snapshot_total_active(self):
        with swap_sink(RecordingSink()):
            request_start("rooms/messages.POST")
            request_start("rooms/messages.POST")
        snap = get_active_requests_snapshot()
        assert snap["active_by_endpoint"]["rooms/messages.POST"] == 2
        assert snap["total_active"] == 2

    def test_snapshot_longest_active_ms(self):
        import time

        with swap_sink(RecordingSink()):
            request_start("subscribe")
            time.sleep(0.01)  # 10ms minimum
        snap = get_active_requests_snapshot()
        assert snap["longest_active_ms"] >= 0.0

    def test_snapshot_structure(self):
        snap = get_active_requests_snapshot()
        assert "active_by_endpoint" in snap
        assert "total_active" in snap
        assert "longest_active_ms" in snap
        assert "inflight" in snap


# ---------------------------------------------------------------------------
# get_debug_state
# ---------------------------------------------------------------------------


class TestGetDebugState:
    def test_returns_expected_keys(self):
        state = get_debug_state()
        assert "timestamp" in state
        assert "sampler" in state
        assert "requests" in state
        assert "sink" in state
        assert "sample_interval_s" in state

    def test_sink_name_matches_active(self):
        state = get_debug_state()
        assert state["sink"] == type(instrument.sink).__name__

    def test_timestamp_is_recent(self):
        import time

        before = time.time()
        state = get_debug_state()
        after = time.time()
        assert before <= state["timestamp"] <= after
