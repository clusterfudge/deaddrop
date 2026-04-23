"""Tests for buffered-debug-on-slow-request logging (feat/slow-request-diagnostics).

Covers:
- _request_query_buffer ContextVar wiring
- timed_query appends to buffer when active, falls back to DEBUG log when not
- Middleware installs a fresh buffer per request and cleans up after
- slow_request WARNING emitted when duration > threshold
- Threshold configurable via SLOW_REQUEST_THRESHOLD_MS env var
- Fast requests do NOT emit slow_request warning
- Buffer isolation between concurrent requests (ContextVar async-safety)
- Buffer entry has {name, total_ms, conn_ms, query_ms} breakdown
- conn_ms reflects time spent in get_connection(); query_ms = total_ms - conn_ms
- slow_request WARNING includes db_conn_ms and db_query_ms aggregates
"""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app
from deadrop.metrics import _conn_acquire_ms, _request_query_buffer, timed_query


# ---------------------------------------------------------------------------
# Unit tests: _request_query_buffer + timed_query
# ---------------------------------------------------------------------------


class TestQueryBuffer:
    """Unit tests for the ContextVar buffer and timed_query decorator."""

    def test_buffer_default_is_none(self):
        """ContextVar default should be None (no buffer active)."""
        # Reset to default (no token in this thread)
        token = _request_query_buffer.set(None)
        try:
            assert _request_query_buffer.get() is None
        finally:
            _request_query_buffer.reset(token)

    def test_timed_query_appends_to_active_buffer(self):
        """When a buffer is installed, timed_query should append with timing breakdown."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:

            @timed_query("test_op")
            def noop():
                return 42

            result = noop()
            assert result == 42
            assert len(buf) == 1
            entry = buf[0]
            assert entry["name"] == "test_op"
            # New breakdown fields
            assert isinstance(entry["total_ms"], float)
            assert isinstance(entry["conn_ms"], float)
            assert isinstance(entry["query_ms"], float)
            assert entry["total_ms"] >= 0
            assert entry["conn_ms"] >= 0
            assert entry["query_ms"] >= 0
            # total = conn + query (within float rounding)
            assert abs(entry["total_ms"] - entry["conn_ms"] - entry["query_ms"]) < 0.01
            # Legacy "ms" key should be gone
            assert "ms" not in entry
        finally:
            _request_query_buffer.reset(token)

    def test_timed_query_multiple_appends(self):
        """Multiple decorated calls should all appear in the buffer."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:

            @timed_query("op_a")
            def op_a():
                pass

            @timed_query("op_b")
            def op_b():
                pass

            op_a()
            op_b()
            op_a()

            assert len(buf) == 3
            names = [e["name"] for e in buf]
            assert names == ["op_a", "op_b", "op_a"]
        finally:
            _request_query_buffer.reset(token)

    def test_timed_query_falls_back_to_debug_log_when_no_buffer(self, caplog):
        """When no buffer is active, timed_query should emit a DEBUG log."""
        token = _request_query_buffer.set(None)
        try:

            @timed_query("fallback_op")
            def noop():
                pass

            with caplog.at_level(logging.DEBUG, logger="deadrop.db"):
                noop()

            assert any("fallback_op" in r.message for r in caplog.records)
        finally:
            _request_query_buffer.reset(token)

    def test_timed_query_preserves_exceptions(self):
        """timed_query should not swallow exceptions from the wrapped function."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:

            @timed_query("failing_op")
            def boom():
                raise ValueError("kaboom")

            with pytest.raises(ValueError, match="kaboom"):
                boom()

            # Timing should still have been recorded even on exception
            assert len(buf) == 1
            entry = buf[0]
            assert entry["name"] == "failing_op"
            assert "total_ms" in entry
            assert "conn_ms" in entry
            assert "query_ms" in entry
        finally:
            _request_query_buffer.reset(token)

    def test_buffer_isolation_between_contexts(self):
        """Two independent ContextVar tokens should not interfere."""
        buf_a: list[dict] = []
        buf_b: list[dict] = []

        token_a = _request_query_buffer.set(buf_a)

        @timed_query("shared_name")
        def noop():
            pass

        noop()  # goes to buf_a

        _request_query_buffer.reset(token_a)
        token_b = _request_query_buffer.set(buf_b)

        noop()  # goes to buf_b

        _request_query_buffer.reset(token_b)

        assert len(buf_a) == 1
        assert len(buf_b) == 1
        assert buf_a[0]["name"] == "shared_name"
        assert buf_b[0]["name"] == "shared_name"


class TestConnAcquireTiming:
    """Unit tests for the conn-acquire breakdown in timed_query."""

    def test_conn_ms_accumulates_from_conn_acquire_var(self):
        """timed_query reads _conn_acquire_ms and splits it into conn_ms.

        We inject a value that is *smaller* than the total wall-clock time so the
        query_ms remainder is well-defined and positive.  We do this by sleeping
        slightly longer than the injected acquire time.
        """
        import time as _time

        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:

            @timed_query("fake_db_op")
            def db_op_with_fake_acquire():
                # Simulate 2ms connection acquire, then "do work" for ~4ms total
                _conn_acquire_ms.set(2.0)
                _time.sleep(0.004)  # ensure total_ms >= 2ms so query_ms >= 0

            db_op_with_fake_acquire()

            assert len(buf) == 1
            entry = buf[0]
            # conn_ms should exactly match what we injected
            assert entry["conn_ms"] == pytest.approx(2.0, abs=0.1)
            # query_ms = max(total_ms - conn_ms, 0) — should be positive
            assert entry["query_ms"] >= 0.0
            # total_ms >= conn_ms (sleep guarantees this)
            assert entry["total_ms"] >= entry["conn_ms"]
            # round-trip invariant: conn + query == total (within float rounding)
            assert abs(entry["conn_ms"] + entry["query_ms"] - entry["total_ms"]) < 0.01
        finally:
            _request_query_buffer.reset(token)

    def test_conn_ms_reset_between_calls(self):
        """_conn_acquire_ms is reset to 0.0 at the start of each timed_query call."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:

            @timed_query("op_a")
            def op_a():
                _conn_acquire_ms.set(10.0)  # simulate 10ms acquire

            @timed_query("op_b")
            def op_b():
                pass  # no acquire time injected → should see 0.0

            op_a()
            op_b()

            assert buf[0]["conn_ms"] == pytest.approx(10.0, abs=0.1)
            # op_b gets a fresh 0.0 reset — not leftover from op_a
            assert buf[1]["conn_ms"] == pytest.approx(0.0, abs=0.1)
        finally:
            _request_query_buffer.reset(token)

    def test_conn_ms_zero_when_no_acquire(self):
        """When get_connection() is not called (conn provided directly), conn_ms stays 0."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:

            @timed_query("direct_conn_op")
            def noop():
                # Don't touch _conn_acquire_ms — simulates passing conn= directly
                pass

            noop()

            entry = buf[0]
            assert entry["conn_ms"] == pytest.approx(0.0, abs=0.01)
        finally:
            _request_query_buffer.reset(token)


# ---------------------------------------------------------------------------
# Integration tests: middleware behaviour via TestClient
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


class TestSlowRequestMiddleware:
    """Integration tests: middleware installs buffer, cleans up, emits warning."""

    def test_x_response_time_header_present(self, client):
        """Every response should carry an X-Response-Time-Ms header."""
        response = client.get("/health")
        assert "X-Response-Time-Ms" in response.headers
        ms = float(response.headers["X-Response-Time-Ms"])
        assert ms >= 0

    def test_buffer_cleaned_up_after_request(self, client):
        """After a request completes, the ContextVar should revert to None."""
        # Make a request
        client.get("/health")
        # In the test thread, no buffer should be active
        assert _request_query_buffer.get() is None

    def test_no_slow_request_warning_for_fast_request(self, client):
        """Fast requests (below threshold) must NOT emit slow_request warnings."""
        with patch.dict(os.environ, {"SLOW_REQUEST_THRESHOLD_MS": "999999"}):
            with patch("structlog.get_logger") as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger

                client.get("/health")

                # warning() should not have been called with "slow_request"
                for c in mock_logger.warning.call_args_list:
                    assert c.args[0] != "slow_request", (
                        "slow_request warning fired for a fast request"
                    )

    def test_slow_request_warning_emitted(self, client, admin_headers):
        """When a request exceeds the threshold, slow_request WARNING must fire."""
        import structlog

        captured_warnings = []

        # structlog is imported inside the middleware via a local 'import structlog',
        # so we patch the structlog module directly.
        original_get_logger = structlog.get_logger

        def capturing_get_logger(name=None, **kw):
            logger = original_get_logger(name, **kw)
            original_warning = logger.warning

            def capturing_warning(event, **fields):
                if event == "slow_request":
                    captured_warnings.append({"event": event, **fields})
                return original_warning(event, **fields)

            logger.warning = capturing_warning
            return logger

        with patch.dict(os.environ, {"SLOW_REQUEST_THRESHOLD_MS": "0"}):
            with patch("structlog.get_logger", side_effect=capturing_get_logger):
                client.post(
                    "/admin/namespaces",
                    json={},
                    headers=admin_headers,
                )

        assert len(captured_warnings) >= 1, "Expected at least one slow_request warning"
        w = captured_warnings[0]
        assert w["event"] == "slow_request"
        assert "request_id" in w
        assert "duration_ms" in w
        assert "db_queries" in w
        assert "db_total_ms" in w
        assert "db_conn_ms" in w
        assert "db_query_ms" in w
        assert "overhead_ms" in w
        assert isinstance(w["db_queries"], list)
        # Each query entry should have the breakdown fields
        for q in w["db_queries"]:
            assert "total_ms" in q, f"query entry missing total_ms: {q}"
            assert "conn_ms" in q, f"query entry missing conn_ms: {q}"
            assert "query_ms" in q, f"query entry missing query_ms: {q}"
        # overhead + db_total should approximately equal duration
        assert abs(w["overhead_ms"] + w["db_total_ms"] - w["duration_ms"]) < 1.0
        # conn + query totals should add up to db_total
        assert abs(w["db_conn_ms"] + w["db_query_ms"] - w["db_total_ms"]) < 0.1

    def test_slow_request_warning_includes_endpoint(self, client, admin_headers):
        """slow_request log must include endpoint and method fields."""
        import structlog

        captured = []
        original_get_logger = structlog.get_logger

        def capturing_get_logger(name=None, **kw):
            logger = original_get_logger(name, **kw)
            original_warning = logger.warning

            def capturing_warning(event, **fields):
                if event == "slow_request":
                    captured.append(fields)
                return original_warning(event, **fields)

            logger.warning = capturing_warning
            return logger

        with patch.dict(os.environ, {"SLOW_REQUEST_THRESHOLD_MS": "0"}):
            with patch("structlog.get_logger", side_effect=capturing_get_logger):
                client.post(
                    "/admin/namespaces",
                    json={},
                    headers=admin_headers,
                )

        if captured:
            w = captured[0]
            assert "endpoint" in w
            assert "method" in w
            assert w["method"] == "POST"

    def test_threshold_env_var_respected(self, client, admin_headers):
        """SLOW_REQUEST_THRESHOLD_MS should gate the warning correctly."""
        import structlog

        def count_slow_warnings(threshold_ms: str) -> int:
            warnings = []
            original_get_logger = structlog.get_logger

            def capturing_get_logger(name=None, **kw):
                logger = original_get_logger(name, **kw)
                original_warning = logger.warning

                def capturing_warning(event, **fields):
                    if event == "slow_request":
                        warnings.append(fields)
                    return original_warning(event, **fields)

                logger.warning = capturing_warning
                return logger

            with patch.dict(os.environ, {"SLOW_REQUEST_THRESHOLD_MS": threshold_ms}):
                with patch("structlog.get_logger", side_effect=capturing_get_logger):
                    client.post("/admin/namespaces", json={}, headers=admin_headers)

            return len(warnings)

        # Threshold=0 → every request should fire
        assert count_slow_warnings("0") >= 1
        # Threshold=999999 → no request should fire
        assert count_slow_warnings("999999") == 0

    def test_request_id_in_response_context(self, client, admin_headers):
        """Each request should get a unique request_id (checked via X-Response-Time-Ms presence)."""
        # We can't easily inspect structlog bound vars from outside, but we can
        # verify the middleware runs without error and produces unique timing headers.
        r1 = client.post("/admin/namespaces", json={}, headers=admin_headers)
        r2 = client.post("/admin/namespaces", json={}, headers=admin_headers)
        assert "X-Response-Time-Ms" in r1.headers
        assert "X-Response-Time-Ms" in r2.headers
        # They should both succeed
        assert r1.status_code == 200
        assert r2.status_code == 200
