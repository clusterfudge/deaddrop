"""Tests for the DB-layer diagnostics instrumentation (issue #51).

Instrumentation-only: these verify the counters/gauges and the ``/debug/db``
snapshot endpoint, not any change in DB behavior.
"""

import pytest
from fastapi.testclient import TestClient

from deadrop import db
from deadrop.api import app


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


class TestDbDebugState:
    def test_snapshot_has_expected_keys(self):
        state = db.get_db_debug_state()
        expected = {
            "backend",
            "read_pool_threads",
            "write_pool_threads",
            "read_pool_size",
            "write_pool_size",
            "libsql_registry_size",
            "executor_replace_count_total",
            "last_executor_replace_at",
            "last_executor_replace_age_seconds",
            "hrana_stream_errors_total",
            "libsql_connect_count_total",
            "health_check_runs_total",
            "health_check_failures_total",
        }
        assert expected.issubset(state.keys())

    def test_counters_are_ints(self):
        state = db.get_db_debug_state()
        for key in (
            "executor_replace_count_total",
            "hrana_stream_errors_total",
            "libsql_connect_count_total",
            "health_check_runs_total",
            "health_check_failures_total",
        ):
            assert isinstance(state[key], int)

    def test_executor_thread_count_none_is_zero(self):
        assert db._executor_thread_count(None) == 0

    def test_libsql_registry_size_reads_registry(self):
        # Consistent with the live registry length, whatever it is.
        assert db._libsql_registry_size() == len(db._libsql_conn_registry)


class TestReplaceExecutorInstrumentation:
    def test_replace_increments_counter_and_stamps_time(self, monkeypatch):
        # Force the libsql branch so _replace_db_executor does its work.
        monkeypatch.setattr(db, "is_using_libsql", lambda: True)

        before = db.get_db_debug_state()["executor_replace_count_total"]
        db._replace_db_executor()
        after = db.get_db_debug_state()

        assert after["executor_replace_count_total"] == before + 1
        # Timestamp + age are now populated.
        assert after["last_executor_replace_at"] is not None
        assert after["last_executor_replace_age_seconds"] is not None

    def test_replace_is_noop_for_non_libsql(self, monkeypatch):
        monkeypatch.setattr(db, "is_using_libsql", lambda: False)
        before = db.get_db_debug_state()["executor_replace_count_total"]
        db._replace_db_executor()
        after = db.get_db_debug_state()["executor_replace_count_total"]
        assert after == before


class TestDebugDbEndpoint:
    def test_requires_admin(self, client):
        resp = client.get("/debug/db")
        assert resp.status_code in (401, 403)

    def test_returns_snapshot_with_admin(self, client, admin_headers):
        resp = client.get("/debug/db", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "executor_replace_count_total" in body
        assert "backend" in body
