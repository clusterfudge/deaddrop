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
    """Reset database before each test function."""
    db.close_db()  # Close any existing connection
    db.init_db()   # Initialize fresh
    yield
    db.close_db()  # Cleanup after test
