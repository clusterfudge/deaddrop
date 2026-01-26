"""Shared pytest configuration and fixtures."""

import os

# Set environment variables before any imports
# Use legacy admin token for tests (no external heare-auth dependency)
os.environ["DEADROP_ADMIN_TOKEN"] = "test-admin-token"
os.environ["DEADROP_DB"] = ":memory:"
# Ensure heare-auth is NOT used in tests
os.environ.pop("HEARE_AUTH_URL", None)


import pytest
from deadrop import db


@pytest.fixture(autouse=True, scope="function")
def reset_database():
    """Reset database before each test function.

    For in-memory shared cache databases, we need to do a full reset_db()
    to clear all tables, since close_db() doesn't destroy the shared cache.
    """
    # Get connection and drop all tables first (in case migration tests
    # left partial schemas)
    conn = db.get_connection()
    conn.executescript("""
        DROP TABLE IF EXISTS archive_batches;
        DROP TABLE IF EXISTS invites;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS identities;
        DROP TABLE IF EXISTS namespaces;
        DROP TABLE IF EXISTS schema_version;
        DROP TABLE IF EXISTS rooms;
        DROP TABLE IF EXISTS room_members;
        DROP TABLE IF EXISTS room_messages;
    """)
    conn.commit()

    # Now initialize fresh schema
    db.init_db_with_conn(conn)
    yield
    db.close_db()  # Cleanup after test
