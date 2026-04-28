"""Tests for InstrumentedConnection and supporting helpers.

Covers:
- _record_query: statsd emit + buffer append
- InstrumentedConnection.execute: explicit name=, unnamed fallback, timing, results
- InstrumentedConnection.commit: timing captured
- InstrumentedConnection.__getattr__: transparent proxy for other attrs
- Integration: full POST through TestClient shows named per-SQL entries in buffer
"""

from __future__ import annotations

import os
import sqlite3
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from deadrop.metrics import (
    InstrumentedConnection,
    _record_query,
    _request_query_buffer,
)


# ---------------------------------------------------------------------------
# Unit tests: _record_query
# ---------------------------------------------------------------------------


class TestRecordQuery:
    """_record_query emits to statsd + appends to active buffer."""

    def test_appends_to_active_buffer(self):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            _record_query("send_room_message.dedup_check", 1.23)
            assert len(buf) == 1
            assert buf[0]["name"] == "send_room_message.dedup_check"
            assert abs(buf[0]["ms"] - 1.23) < 0.001
        finally:
            _request_query_buffer.reset(token)

    def test_no_buffer_no_error(self):
        """When no buffer is active, _record_query should not raise."""
        token = _request_query_buffer.set(None)
        try:
            _record_query("commit", 0.5)  # should not raise
        finally:
            _request_query_buffer.reset(token)

    def test_sink_called_with_db_sql_timing(self):
        """_record_query emits to the active instrument.sink with db.sql_ms timing."""
        from deadrop import instrument

        class CapturingSink:
            calls: list[tuple] = []

            def counter(self, name, value=1, tags=None):
                pass

            def gauge(self, name, value, tags=None):
                pass

            def histogram(self, name, value, tags=None):
                pass

            def timing(self, name, value_ms, tags=None):
                self.calls.append((name, value_ms, tags))

        token = _request_query_buffer.set(None)
        test_sink = CapturingSink()
        original_sink = instrument.sink
        try:
            instrument.sink = test_sink
            _record_query("send_message.insert", 2.5)
            # Backward-compatible flat name: db.sql.{name} (no tags).
            # This matches the pre-PR53 statsd_timing(f"db.sql.{name}", ms) behaviour
            # that the Grafana dashboard queries depend on.
            assert any(
                name == "db.sql.send_message.insert" and tags is None
                for name, _, tags in test_sink.calls
            ), f"Expected db.sql.send_message.insert (flat, no tags), got: {test_sink.calls}"
        finally:
            instrument.sink = original_sink
            _request_query_buffer.reset(token)

    def test_multiple_records_in_order(self):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            _record_query("send_room_message.upsert", 1.0)
            _record_query("commit", 0.5)
            assert [e["name"] for e in buf] == [
                "send_room_message.upsert",
                "commit",
            ]
        finally:
            _request_query_buffer.reset(token)


# ---------------------------------------------------------------------------
# Unit tests: InstrumentedConnection
# ---------------------------------------------------------------------------


class TestInstrumentedConnection:
    """InstrumentedConnection wraps a raw connection and times execute/commit."""

    @pytest.fixture
    def raw_conn(self):
        """Fresh in-memory SQLite connection."""
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, val TEXT)")
        conn.commit()
        yield conn
        conn.close()

    @pytest.fixture
    def instrumented(self, raw_conn):
        return InstrumentedConnection(raw_conn)

    # -- execute() with explicit name --

    def test_execute_returns_cursor(self, instrumented):
        cursor = instrumented.execute("SELECT 1", name="health_check")
        row = cursor.fetchone()
        assert row[0] == 1

    def test_execute_named_appends_to_buffer(self, instrumented):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            instrumented.execute("SELECT * FROM test_table", name="test_fn.select")
            assert len(buf) == 1
            assert buf[0]["name"] == "test_fn.select"
            assert isinstance(buf[0]["ms"], float)
            assert buf[0]["ms"] >= 0
        finally:
            _request_query_buffer.reset(token)

    def test_execute_with_params_and_name(self, instrumented):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            instrumented.execute(
                "INSERT INTO test_table (id, val) VALUES (?, ?)",
                (1, "hello"),
                name="test_fn.insert",
            )
            assert len(buf) == 1
            assert buf[0]["name"] == "test_fn.insert"
        finally:
            _request_query_buffer.reset(token)

    def test_execute_multiple_named_ops_all_captured(self, instrumented):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            instrumented.execute(
                "INSERT INTO test_table (id, val) VALUES (?, ?)", (1, "a"), name="fn.insert_a"
            )
            instrumented.execute(
                "INSERT INTO test_table (id, val) VALUES (?, ?)", (2, "b"), name="fn.insert_b"
            )
            instrumented.execute("SELECT * FROM test_table", name="fn.select")
            assert [e["name"] for e in buf] == ["fn.insert_a", "fn.insert_b", "fn.select"]
        finally:
            _request_query_buffer.reset(token)

    # -- unnamed fallback --

    def test_execute_without_name_emits_unnamed(self, instrumented):
        """execute() without name= kwarg records as 'unnamed'."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            instrumented.execute("SELECT * FROM test_table")
            assert len(buf) == 1
            assert buf[0]["name"] == "unnamed"
        finally:
            _request_query_buffer.reset(token)

    def test_execute_unnamed_still_returns_cursor(self, instrumented):
        cursor = instrumented.execute("SELECT 1")
        assert cursor.fetchone()[0] == 1

    # -- timing properties --

    def test_execute_timing_is_nonnegative_float(self, instrumented):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            instrumented.execute("SELECT * FROM test_table", name="timing_test")
            assert isinstance(buf[0]["ms"], float)
            assert buf[0]["ms"] >= 0.0
        finally:
            _request_query_buffer.reset(token)

    def test_execute_propagates_exception_and_still_records(self, instrumented):
        """Exceptions from execute() propagate; timing is still recorded (finally block)."""
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            with pytest.raises(Exception):
                instrumented.execute("SELECT * FROM nonexistent_table", name="bad_query")
            assert len(buf) == 1
            assert buf[0]["name"] == "bad_query"
        finally:
            _request_query_buffer.reset(token)

    # -- commit() --

    def test_commit_appends_commit_entry(self, instrumented):
        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            instrumented.commit()
            assert len(buf) == 1
            assert buf[0]["name"] == "commit"
            assert isinstance(buf[0]["ms"], float)
        finally:
            _request_query_buffer.reset(token)

    def test_commit_actually_persists_data(self, instrumented, raw_conn):
        instrumented.execute(
            "INSERT INTO test_table (id, val) VALUES (?, ?)", (42, "hello"), name="test.insert"
        )
        instrumented.commit()
        row = raw_conn.execute("SELECT val FROM test_table WHERE id = 42").fetchone()
        assert row is not None
        assert row[0] == "hello"

    # -- __getattr__ proxy --

    def test_row_factory_readable_via_proxy(self, instrumented, raw_conn):
        assert instrumented.row_factory is raw_conn.row_factory

    def test_executescript_proxied(self, instrumented):
        """executescript (not overridden) delegates to raw conn."""
        instrumented.executescript("CREATE TABLE IF NOT EXISTS proxy_test (x INTEGER);")
        cursor = instrumented.execute(
            "SELECT name FROM sqlite_master WHERE name='proxy_test'",
            name="schema_check",
        )
        assert cursor.fetchone() is not None

    def test_close_proxied(self):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        instrumented = InstrumentedConnection(conn)
        instrumented.close()
        with pytest.raises(Exception):
            conn.execute("SELECT 1")

    def test_setattr_row_factory(self, instrumented, raw_conn):
        instrumented.row_factory = None
        assert raw_conn.row_factory is None

    def test_repr_contains_class_name(self, instrumented):
        assert "InstrumentedConnection" in repr(instrumented)

    # -- No buffer active --

    def test_execute_without_buffer_no_error(self, instrumented):
        cursor = instrumented.execute("SELECT 1", name="health_check")
        assert cursor.fetchone()[0] == 1

    def test_commit_without_buffer_no_error(self, instrumented):
        instrumented.commit()  # should not raise


# ---------------------------------------------------------------------------
# Integration tests: full HTTP request shows named per-SQL entries in buffer
# ---------------------------------------------------------------------------


class TestIntegrationNamedQueriesInBuffer:
    """Integration: real HTTP requests produce explicitly-named SQL entries."""

    @pytest.fixture
    def client(self):
        from deadrop.api import app

        with TestClient(app, raise_server_exceptions=True) as c:
            yield c

    @pytest.fixture
    def admin_headers(self):
        return {"X-Admin-Token": "test-admin-token"}

    def _capture_slow_request(self, fn):
        """Run fn() with SLOW_REQUEST_THRESHOLD_MS=0; return captured slow_request fields."""
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
                fn()

        return captured

    def test_all_entries_have_name_and_ms(self, client, admin_headers):
        """Every buffer entry must have name (str) and ms (float >= 0)."""
        captured = self._capture_slow_request(
            lambda: client.post("/admin/namespaces", json={}, headers=admin_headers)
        )
        assert len(captured) >= 1
        for entry in captured[0]["db_queries"]:
            assert isinstance(entry["name"], str), f"name not str: {entry}"
            assert isinstance(entry["ms"], float), f"ms not float: {entry}"
            assert entry["ms"] >= 0, f"ms negative: {entry}"

    def test_create_namespace_has_commit_entry(self, client, admin_headers):
        """POST /admin/namespaces must produce a 'commit' entry from InstrumentedConnection."""
        captured = self._capture_slow_request(
            lambda: client.post("/admin/namespaces", json={}, headers=admin_headers)
        )
        assert len(captured) >= 1
        names = [q["name"] for q in captured[0]["db_queries"]]
        assert "commit" in names, f"Expected 'commit' in {names}"

    def test_no_inference_all_names_explicit_or_unnamed(self, client, admin_headers):
        """No inferred names like 'select.namespaces' — only explicit names or 'unnamed'."""
        captured = self._capture_slow_request(
            lambda: client.post("/admin/namespaces", json={}, headers=admin_headers)
        )
        assert len(captured) >= 1
        names = [q["name"] for q in captured[0]["db_queries"]]
        for name in names:
            # No dot-separated SQL-inferred names (those were the old design)
            assert not (
                name.startswith("select.")
                or name.startswith("insert.")
                or name.startswith("update.")
                or name.startswith("delete.")
                or name.startswith("pragma.")
            ), f"Inferred SQL name found — should be explicit or 'unnamed': {name!r}"

    def test_send_room_message_has_named_entries(self, client, admin_headers):
        """send_room_message produces explicitly-named per-SQL entries + @timed_query total."""
        ns_resp = client.post("/admin/namespaces", json={}, headers=admin_headers)
        ns_data = ns_resp.json()
        ns, ns_secret = ns_data["ns"], ns_data["secret"]

        id_resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
        identity_secret = id_resp.json()["secret"]

        room_resp = client.post(
            f"/{ns}/rooms",
            json={"display_name": "test-room"},
            headers={"X-Inbox-Secret": identity_secret},
        )
        room_id = room_resp.json()["room_id"]

        captured = self._capture_slow_request(
            lambda: client.post(
                f"/{ns}/rooms/{room_id}/messages",
                json={"body": "hello world"},
                headers={"X-Inbox-Secret": identity_secret},
            )
        )
        assert len(captured) >= 1

        names = [q["name"] for q in captured[0]["db_queries"]]

        # Explicit named SQL entries from InstrumentedConnection.
        # send_room_message.upsert replaces the old dedup_check + insert pair —
        # the conditional INSERT-SELECT eliminates the separate dedup SELECT round-trip.
        assert "send_room_message.upsert" in names, f"Expected send_room_message.upsert in {names}"
        assert "commit" in names, f"Expected 'commit' in {names}"
        # Old names should no longer appear
        assert "send_room_message.dedup_check" not in names, (
            f"send_room_message.dedup_check should be gone (batched into upsert): {names}"
        )
        assert "send_room_message.insert" not in names, (
            f"send_room_message.insert should be gone (batched into upsert): {names}"
        )

        # @timed_query function-level total
        assert "send_room_message" in names, (
            f"Expected 'send_room_message' @timed_query entry in {names}"
        )

    def test_send_room_message_both_levels_present(self, client, admin_headers):
        """Buffer contains both per-SQL (InstrumentedConnection) and function-level (@timed_query) entries."""
        ns_resp = client.post("/admin/namespaces", json={}, headers=admin_headers)
        ns_data = ns_resp.json()
        ns, ns_secret = ns_data["ns"], ns_data["secret"]

        id_resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
        identity_secret = id_resp.json()["secret"]

        room_resp = client.post(
            f"/{ns}/rooms",
            json={"display_name": "test"},
            headers={"X-Inbox-Secret": identity_secret},
        )
        room_id = room_resp.json()["room_id"]

        captured = self._capture_slow_request(
            lambda: client.post(
                f"/{ns}/rooms/{room_id}/messages",
                json={"body": "hi"},
                headers={"X-Inbox-Secret": identity_secret},
            )
        )
        assert len(captured) >= 1
        names = [q["name"] for q in captured[0]["db_queries"]]

        # Per-SQL: named with dot notation (function.step)
        per_sql = [n for n in names if "." in n or n == "commit"]
        # Function-level: @timed_query entries (no dot, not commit)
        func_level = [n for n in names if "." not in n and n != "commit"]

        assert len(per_sql) > 0, f"No per-SQL entries in {names}"
        assert len(func_level) > 0, f"No @timed_query entries in {names}"
