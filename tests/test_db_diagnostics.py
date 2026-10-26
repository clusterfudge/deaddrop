"""Tests for the DB-layer diagnostics instrumentation.

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
            "turso_read_retries_total",
        }
        assert expected.issubset(state.keys())

    def test_counters_are_ints(self):
        assert isinstance(db.get_db_debug_state()["turso_read_retries_total"], int)

    def test_executor_thread_count_none_is_zero(self):
        assert db._executor_thread_count(None) == 0


class TestDebugDbEndpoint:
    def test_requires_admin(self, client):
        resp = client.get("/debug/db")
        assert resp.status_code in (401, 403)

    def test_returns_snapshot_with_admin(self, client, admin_headers):
        resp = client.get("/debug/db", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "turso_read_retries_total" in body
        assert "backend" in body
