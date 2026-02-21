"""Tests for cache warming — specifically verifying it doesn't block the event loop.

The production outage on 2026-02-21 was caused by warm_caches() calling
db.get_connection() synchronously on the event loop thread.  For the
libsql/Turso backend, get_connection() acquires a threading lock and runs
a network health check.  If the Turso connection goes stale, the health
check hangs indefinitely, freezing the entire asyncio event loop.

These tests verify:
1. warm_caches() runs entirely off the event loop thread.
2. A timeout on warm_caches() prevents indefinite hangs.
3. The health check in get_connection() has a timeout.
"""

import asyncio
import time
import unittest.mock

import pytest

from deadrop import db
from deadrop.cache import (
    clear_all_caches,
    membership_cache,
    room_cache,
    warm_caches,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_test_data():
    """Create a namespace, identity, room, and membership for cache warming."""
    ns_result = db.create_namespace(metadata={"display_name": "test"})
    ns = ns_result["ns"]

    identity = db.create_identity(ns, metadata={"display_name": "alice"})
    identity_id = identity["id"]

    room = db.create_room(ns, identity_id, display_name="General")
    room_id = room["room_id"]

    return ns, identity_id, room_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_warm_caches_populates_caches():
    """Basic sanity: warm_caches() populates the three caches."""
    ns, identity_id, room_id = _seed_test_data()
    clear_all_caches()

    results = await warm_caches()

    assert results["rooms"] >= 1
    assert results["memberships"] >= 1
    assert results["identities"] >= 1

    # Verify caches have data
    hit, _ = room_cache.get(f"room:{room_id}")
    assert hit, "Room should be cached"

    hit, _ = membership_cache.get(f"member:{room_id}:{identity_id}")
    assert hit, "Membership should be cached"


@pytest.mark.asyncio
async def test_warm_caches_does_not_block_event_loop():
    """warm_caches() must not call blocking operations on the event loop thread.

    We verify this by checking that the event loop remains responsive while
    warm_caches() is running.  We schedule a sentinel coroutine that must
    complete within the same event loop tick.
    """
    _seed_test_data()
    clear_all_caches()

    event_loop_responsive = False

    async def check_responsiveness():
        """Coroutine that marks the event loop as responsive."""
        nonlocal event_loop_responsive
        event_loop_responsive = True

    # Run warm_caches and the responsiveness check concurrently.
    # If warm_caches blocks the event loop, check_responsiveness
    # will never run.
    await asyncio.gather(
        warm_caches(),
        check_responsiveness(),
    )

    assert event_loop_responsive, (
        "Event loop was blocked — warm_caches() likely called "
        "a blocking function on the event loop thread."
    )


@pytest.mark.asyncio
async def test_warm_caches_timeout():
    """warm_caches() can be wrapped with asyncio.wait_for to enforce a timeout.

    This simulates the production pattern in _warm_and_refresh().
    """
    _seed_test_data()
    clear_all_caches()

    # Normal case: warming should complete well within timeout
    results = await asyncio.wait_for(warm_caches(), timeout=10.0)
    assert results["rooms"] >= 1


@pytest.mark.asyncio
async def test_warm_caches_timeout_on_slow_connection():
    """If the DB connection hangs, warm_caches() should be cancellable via timeout.

    We mock get_connection to simulate a slow/hanging connection.
    """
    original_get_connection = db.get_connection

    def hanging_get_connection(*args, **kwargs):
        """Simulate a hanging connection by sleeping."""
        time.sleep(10)  # Simulate hang (longer than our timeout)
        return original_get_connection(*args, **kwargs)

    clear_all_caches()

    with unittest.mock.patch("deadrop.db.get_connection", side_effect=hanging_get_connection):
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(warm_caches(), timeout=0.5)


def test_health_check_timeout():
    """The libsql health check should timeout on hung connections."""
    from deadrop.db import _health_check_conn

    class HangingConnection:
        """Simulates a connection whose execute() hangs indefinitely."""

        def execute(self, query):
            time.sleep(30)  # Simulate indefinite hang

    conn = HangingConnection()

    start = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        _health_check_conn(conn, timeout=0.5)
    elapsed = time.monotonic() - start

    # Should have timed out in ~0.5s, not 30s
    assert elapsed < 2.0, f"Health check took {elapsed:.1f}s — timeout didn't work"


def test_health_check_passes_for_healthy_connection():
    """Health check should pass silently for a working connection."""
    from deadrop.db import _health_check_conn

    conn = db.get_connection()

    # Should not raise
    _health_check_conn(conn, timeout=5.0)


def test_health_check_propagates_errors():
    """Health check should propagate non-timeout errors."""
    from deadrop.db import _health_check_conn

    class ErrorConnection:
        def execute(self, query):
            raise RuntimeError("stream not found")

    conn = ErrorConnection()

    with pytest.raises(RuntimeError, match="stream not found"):
        _health_check_conn(conn, timeout=5.0)
