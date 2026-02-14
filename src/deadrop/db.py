"""Database layer for deadrop - supports SQLite, Turso, and pluggable connections.

This module provides database operations for deaddrop with support for:
- Global singleton connection (backward compatible)
- Custom connection paths for local backends
- In-memory databases for testing
- Turso (libsql) for production

Connection Management:
    # Global singleton (existing behavior)
    init_db()
    ns = create_namespace(...)

    # Scoped connection (new)
    with scoped_connection("/path/to/db.sqlite") as conn:
        init_db_with_conn(conn)
        ns = create_namespace_with_conn(conn, ...)

    # In-memory for testing
    with scoped_connection(":memory:") as conn:
        init_db_with_conn(conn)
        ...
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from uuid_extensions import uuid7 as make_uuid7

from .auth import derive_id, generate_secret, hash_secret

# Default TTL in hours when messages are read
DEFAULT_TTL_HOURS = 24

# Current schema version (increment when adding migrations)
SCHEMA_VERSION = 3

# Thread-local storage for per-thread connections
# This ensures each thread gets its own SQLite connection, avoiding
# concurrency issues with async/threaded code (FastAPI runs sync DB ops in thread pool)
_local = threading.local()

# Global config for connection parameters (shared across threads)
_db_config: dict[str, Any] = {
    "path": None,  # Will be set from env or explicit path
    "is_libsql": False,
}

# Legacy global connection (only used for explicit single-connection scenarios)
_conn: sqlite3.Connection | None = None
_is_libsql: bool = False


def is_using_libsql() -> bool:
    """Check if the database backend is libsql/Turso.

    This is used by the API layer to determine whether DB operations need
    to be serialized (libsql uses a single shared connection).
    """
    return _is_libsql or os.environ.get("TURSO_URL", "").startswith("libsql://")


# Lock for thread-safe libsql reconnection
_libsql_lock = threading.Lock()

# Timeout for libsql connection operations (seconds)
LIBSQL_CONNECT_TIMEOUT = 10.0
LIBSQL_HEALTH_CHECK_TIMEOUT = 5.0


def _reset_libsql_connection() -> None:
    """Reset the global libsql connection.

    Called when the connection is detected as stale (e.g., Hrana stream expired).
    Thread-safe - uses a lock to prevent multiple threads from reconnecting simultaneously.

    Raises:
        TimeoutError: If unable to acquire lock within timeout.
    """
    global _conn, _is_libsql

    lock_acquired = _libsql_lock.acquire(timeout=LIBSQL_CONNECT_TIMEOUT)
    if not lock_acquired:
        import logging

        logging.warning("Timeout acquiring lock to reset libsql connection")
        return  # Can't reset, but don't block indefinitely

    try:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass  # Ignore close errors on stale connection
            _conn = None
            _is_libsql = False
    finally:
        _libsql_lock.release()


def _is_hrana_stream_error(error: Exception) -> bool:
    """Check if an exception indicates a stale Hrana stream.

    Turso/libsql uses HTTP/2 streams that can expire or disconnect.
    When this happens, we need to reconnect.
    """
    error_str = str(error).lower()
    return (
        "stream not found" in error_str
        or "hrana" in error_str
        or "connection" in error_str
        and "closed" in error_str
    )


# --- Connection Management ---


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Get or create database connection.

    Uses thread-local storage to give each thread its own connection,
    which is essential for safe concurrent access in async/threaded environments.

    Args:
        db_path: Optional explicit database path. If None, uses thread-local connection
                 based on environment config. Special value ":memory:" creates an
                 in-memory database (note: each thread will get a SEPARATE in-memory DB).

    Returns:
        SQLite connection with row_factory set to sqlite3.Row.

    Raises:
        TimeoutError: If unable to acquire connection lock within timeout.
        RuntimeError: If libsql connection fails after retries.
    """
    global _conn, _is_libsql, _db_config

    # If explicit path provided, create a new connection (not thread-local)
    # This is used by scoped_connection() for explicit connection management
    if db_path is not None:
        if str(db_path) == ":memory:":
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
            # Enable WAL mode for better concurrent read/write performance
            conn.execute("PRAGMA journal_mode=WAL")
        # Enable foreign key enforcement
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    # Check for Turso/libsql (uses single global connection, not thread-local)
    db_url = os.environ.get("TURSO_URL", "")
    if db_url.startswith("libsql://"):
        # Use non-blocking lock acquisition with timeout to prevent deadlocks
        lock_acquired = _libsql_lock.acquire(timeout=LIBSQL_CONNECT_TIMEOUT)
        if not lock_acquired:
            raise TimeoutError(
                f"Timeout acquiring database connection lock after {LIBSQL_CONNECT_TIMEOUT}s. "
                "Another connection attempt may be hanging."
            )

        # Track whether we need to release the lock (for reconnection path)
        should_release_lock = True
        try:
            if _conn is None:
                import libsql_experimental as libsql  # type: ignore[import-not-found]
                import logging

                logging.info(f"Creating new libsql connection to {db_url[:50]}...")
                try:
                    _conn = libsql.connect(
                        db_url, auth_token=os.environ.get("TURSO_AUTH_TOKEN", "")
                    )
                    _is_libsql = True
                except Exception as e:
                    logging.error(f"Failed to connect to libsql: {e}")
                    raise RuntimeError(f"Failed to connect to Turso database: {e}") from e

            # Test connection health with a simple query
            # This catches stale Hrana streams before they cause operation failures
            try:
                _conn.execute("SELECT 1")
            except Exception as e:
                if _is_hrana_stream_error(e):
                    import logging

                    logging.warning(f"Libsql connection stale, reconnecting: {e}")
                    try:
                        _conn.close()
                    except Exception:
                        pass
                    _conn = None
                    _is_libsql = False
                    # Release lock before recursive call to avoid deadlock
                    _libsql_lock.release()
                    should_release_lock = False
                    # Recursive call to create fresh connection
                    return get_connection(db_path)
                raise

            return _conn
        finally:
            if should_release_lock:
                _libsql_lock.release()

    # Thread-local connection for SQLite
    # Each thread gets its own connection to avoid concurrency issues
    if not hasattr(_local, "conn") or _local.conn is None:
        db_path_env = os.environ.get("DEADROP_DB", ":memory:")

        if db_path_env == ":memory:":
            # For in-memory databases, use shared cache so all threads see
            # the same data. The database name includes the process ID to
            # ensure tests don't interfere with each other across processes.
            _local.conn = sqlite3.connect(
                f"file:memdb_{os.getpid()}?mode=memory&cache=shared",
                uri=True,
                check_same_thread=False,
            )
            # Set busy timeout to wait for locks instead of failing immediately
            _local.conn.execute("PRAGMA busy_timeout=5000")
            # Enable foreign key enforcement
            _local.conn.execute("PRAGMA foreign_keys=ON")
        else:
            _local.conn = sqlite3.connect(db_path_env, check_same_thread=False)
            # Enable WAL mode for better concurrent read/write performance
            _local.conn.execute("PRAGMA journal_mode=WAL")
            # Set busy timeout to wait for locks instead of failing immediately
            _local.conn.execute("PRAGMA busy_timeout=5000")
            # Enable foreign key enforcement
            _local.conn.execute("PRAGMA foreign_keys=ON")

        _local.conn.row_factory = sqlite3.Row

    return _local.conn


@contextmanager
def scoped_connection(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Context manager for scoped database connections.

    Creates a new connection that is automatically closed when the context exits.
    Useful for local backends and testing.

    Args:
        db_path: Path to database file, or ":memory:" for in-memory.

    Yields:
        SQLite connection.

    Example:
        with scoped_connection("/path/to/.deaddrop/data.db") as conn:
            init_db_with_conn(conn)
            create_namespace_with_conn(conn, ...)
    """
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def close_db():
    """Close database connections.

    Closes both the thread-local connection (if any) and the global connection
    (used for libsql/Turso).
    """
    global _conn, _is_libsql

    # Close thread-local connection
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None

    # Close global connection (libsql)
    if _conn:
        _conn.close()
        _conn = None
        _is_libsql = False


def close_thread_connection():
    """Close the connection for the current thread only.

    Useful for cleanup in long-running threads or when done with a batch of operations.
    """
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None


def _get_conn(conn: sqlite3.Connection | None) -> sqlite3.Connection:
    """Helper to get connection - uses provided conn or falls back to global."""
    if conn is not None:
        return conn
    return get_connection()


def _execute_with_retry(
    operation: Callable[[], Any],
    max_retries: int = 2,
) -> Any:
    """Execute a database operation with automatic reconnection for libsql.

    If the operation fails due to a stale Hrana stream, resets the connection
    and retries the operation.

    Args:
        operation: A callable that performs the database operation
        max_retries: Maximum number of retry attempts (default: 2)

    Returns:
        The result of the operation

    Raises:
        The original exception if all retries fail
    """
    global _is_libsql

    last_error: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return operation()
        except Exception as e:
            last_error = e

            # Only retry for libsql Hrana stream errors
            if _is_libsql and _is_hrana_stream_error(e) and attempt < max_retries:
                import logging

                logging.warning(
                    f"Libsql connection error (attempt {attempt + 1}/{max_retries + 1}), reconnecting: {e}"
                )
                _reset_libsql_connection()
                # The next get_connection() call will create a fresh connection
                continue

            # For non-libsql or non-retryable errors, raise immediately
            raise

    # Should not reach here, but just in case
    if last_error:
        raise last_error


def _row_to_dict(cursor_description: Any, row: tuple | sqlite3.Row | None) -> dict | None:
    """Convert a database row to a dictionary."""
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    # For libsql, manually create dict from cursor description
    columns = [col[0] for col in cursor_description]
    return dict(zip(columns, row))


def _rows_to_dicts(cursor_description: Any, rows: list) -> list[dict]:
    """Convert database rows to a list of dictionaries."""
    if not rows:
        return []
    if rows and isinstance(rows[0], sqlite3.Row):
        return [dict(row) for row in rows]
    # For libsql, manually create dicts from cursor description
    columns = [col[0] for col in cursor_description]
    return [dict(zip(columns, row)) for row in rows]


# --- Schema and Migrations ---


def _ensure_schema_version_table(conn: sqlite3.Connection) -> None:
    """Create the schema_version table if it doesn't exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        )
    """)
    conn.commit()


def get_schema_version(conn: sqlite3.Connection | None = None) -> int:
    """Get the current schema version from the database.

    Returns 0 if no migrations have been applied yet.
    """
    conn = _get_conn(conn)
    _ensure_schema_version_table(conn)

    cursor = conn.execute("SELECT MAX(version) FROM schema_version")
    row = cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


def record_migration(conn: sqlite3.Connection, version: int, description: str) -> None:
    """Record that a migration has been applied."""
    conn.execute(
        "INSERT INTO schema_version (version, description) VALUES (?, ?)",
        (version, description),
    )
    conn.commit()


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    cursor = conn.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns


# --- Migration Functions ---


def _migrate_001_add_content_type(conn: sqlite3.Connection) -> None:
    """Migration 001: Add content_type column to messages table."""
    if not _column_exists(conn, "messages", "content_type"):
        conn.execute("ALTER TABLE messages ADD COLUMN content_type TEXT DEFAULT 'text/plain'")
        conn.commit()


def _migrate_002_add_rooms(conn: sqlite3.Connection) -> None:
    """Migration 002: Add rooms tables for group communication."""
    # Create rooms table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            room_id TEXT PRIMARY KEY,
            ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
            display_name TEXT,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create room_members table with per-user read tracking
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_members (
            room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
            identity_id TEXT NOT NULL,
            ns TEXT NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_read_mid TEXT,
            PRIMARY KEY (room_id, identity_id),
            FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE
        )
    """)

    # Create room_messages table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_messages (
            mid TEXT PRIMARY KEY,
            room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
            from_id TEXT NOT NULL,
            body TEXT NOT NULL,
            content_type TEXT DEFAULT 'text/plain',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rooms_ns ON rooms(ns)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_members_identity ON room_members(ns, identity_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id, created_at)"
    )

    conn.commit()


def _migrate_003_add_reference_mid(conn: sqlite3.Connection) -> None:
    """Migration 003: Add reference_mid column to room_messages for reactions."""
    conn.execute("ALTER TABLE room_messages ADD COLUMN reference_mid TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_messages_reference ON room_messages(reference_mid)"
    )
    conn.commit()


# Migration registry: (version, description, migration_function)
MIGRATIONS: list[tuple[int, str, Callable[[sqlite3.Connection], None]]] = [
    (1, "Add content_type column to messages", _migrate_001_add_content_type),
    (2, "Add rooms tables for group communication", _migrate_002_add_rooms),
    (3, "Add reference_mid to room_messages for reactions", _migrate_003_add_reference_mid),
]


def run_migrations(conn: sqlite3.Connection | None = None) -> list[int]:
    """Run any pending migrations.

    Returns a list of migration versions that were applied.
    """
    conn = _get_conn(conn)
    _ensure_schema_version_table(conn)
    current_version = get_schema_version(conn)
    applied: list[int] = []

    for version, description, migrate_fn in MIGRATIONS:
        if version > current_version:
            try:
                migrate_fn(conn)
                record_migration(conn, version, description)
                applied.append(version)
            except Exception as e:
                raise RuntimeError(f"Migration {version} failed: {e}") from e

    return applied


# --- Schema Definition ---


SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS namespaces (
        ns TEXT PRIMARY KEY,
        secret_hash TEXT NOT NULL,
        slug TEXT UNIQUE,
        metadata JSON DEFAULT '{}',
        ttl_hours INTEGER DEFAULT 24,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        archived_at TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_namespaces_slug ON namespaces(slug);
    
    CREATE TABLE IF NOT EXISTS identities (
        id TEXT NOT NULL,
        ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
        secret_hash TEXT NOT NULL,
        metadata JSON DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (ns, id)
    );
    
    CREATE TABLE IF NOT EXISTS messages (
        mid TEXT PRIMARY KEY,
        ns TEXT NOT NULL,
        to_id TEXT NOT NULL,
        from_id TEXT NOT NULL,
        body TEXT NOT NULL,
        content_type TEXT DEFAULT 'text/plain',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        read_at TIMESTAMP,
        expires_at TIMESTAMP,
        archived_at TIMESTAMP,
        FOREIGN KEY (ns, to_id) REFERENCES identities(ns, id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_messages_inbox 
        ON messages(ns, to_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_expires 
        ON messages(expires_at) WHERE expires_at IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_messages_archived
        ON messages(ns, to_id, archived_at) WHERE archived_at IS NOT NULL;
    
    CREATE TABLE IF NOT EXISTS invites (
        invite_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
        identity_id TEXT NOT NULL,
        encrypted_secret TEXT NOT NULL,
        display_name TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        claimed_at TIMESTAMP,
        claimed_by TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_invites_ns ON invites(ns);
    
    CREATE TABLE IF NOT EXISTS archive_batches (
        batch_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL,
        archive_path TEXT NOT NULL,
        message_count INTEGER NOT NULL,
        min_created_at TIMESTAMP,
        max_created_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Rooms for group communication
    CREATE TABLE IF NOT EXISTS rooms (
        room_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL REFERENCES namespaces(ns) ON DELETE CASCADE,
        display_name TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_rooms_ns ON rooms(ns);
    
    CREATE TABLE IF NOT EXISTS room_members (
        room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        identity_id TEXT NOT NULL,
        ns TEXT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_read_mid TEXT,
        PRIMARY KEY (room_id, identity_id),
        FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_members_identity ON room_members(ns, identity_id);
    
    CREATE TABLE IF NOT EXISTS room_messages (
        mid TEXT PRIMARY KEY,
        room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        from_id TEXT NOT NULL,
        body TEXT NOT NULL,
        content_type TEXT DEFAULT 'text/plain',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id, created_at);
"""


def init_db_with_conn(conn: sqlite3.Connection) -> None:
    """Initialize database schema with an explicit connection.

    Args:
        conn: Database connection to initialize.
    """
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    run_migrations(conn)


def init_db():
    """Initialize database schema using the global connection."""
    conn = get_connection()
    init_db_with_conn(conn)


def reset_db(conn: sqlite3.Connection | None = None):
    """Reset database (for testing)."""
    conn = _get_conn(conn)
    conn.executescript("""
        DROP TABLE IF EXISTS room_messages;
        DROP TABLE IF EXISTS room_members;
        DROP TABLE IF EXISTS rooms;
        DROP TABLE IF EXISTS archive_batches;
        DROP TABLE IF EXISTS invites;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS identities;
        DROP TABLE IF EXISTS namespaces;
        DROP TABLE IF EXISTS schema_version;
    """)
    conn.commit()
    init_db_with_conn(conn)


# --- Slug Utilities ---


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    if not text:
        return ""
    slug = text.lower().strip()
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = slug.strip("-")
    return slug


def make_unique_slug(
    base_slug: str,
    exclude_ns: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Generate a unique slug, appending a number if necessary."""
    conn = _get_conn(conn)
    slug = base_slug or "namespace"

    query = "SELECT COUNT(*) FROM namespaces WHERE slug = ?"
    params: list[Any] = [slug]
    if exclude_ns:
        query += " AND ns != ?"
        params.append(exclude_ns)

    cursor = conn.execute(query, tuple(params))
    count = cursor.fetchone()[0]

    if count == 0:
        return slug

    counter = 2
    while True:
        new_slug = f"{slug}-{counter}"
        params[0] = new_slug
        cursor = conn.execute(query, tuple(params))
        if cursor.fetchone()[0] == 0:
            return new_slug
        counter += 1


# --- Namespace Operations ---


def create_namespace(
    metadata: dict[str, Any] | None = None,
    ttl_hours: int = DEFAULT_TTL_HOURS,
    slug: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, str | None]:
    """Create a new namespace. Returns {ns, secret, slug}."""
    conn = _get_conn(conn)

    secret = generate_secret()
    ns = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    if not slug and metadata and metadata.get("display_name"):
        slug = slugify(metadata["display_name"])
    if slug:
        slug = make_unique_slug(slug, conn=conn)

    conn.execute(
        "INSERT INTO namespaces (ns, secret_hash, slug, metadata, ttl_hours) VALUES (?, ?, ?, ?, ?)",
        (ns, secret_hash, slug, metadata_json, ttl_hours),
    )
    conn.commit()

    return {"ns": ns, "secret": secret, "slug": slug}


def get_namespace(ns: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get namespace by ID."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ns, slug, metadata, ttl_hours, created_at, archived_at FROM namespaces WHERE ns = ?",
        (ns,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "ns": row["ns"],
            "slug": row["slug"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
    return None


def get_namespace_by_slug(slug: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get namespace by slug."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ns, slug, metadata, ttl_hours, created_at, archived_at FROM namespaces WHERE slug = ?",
        (slug,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "ns": row["ns"],
            "slug": row["slug"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
    return None


def get_or_create_namespace_slug(
    ns: str,
    suggested_slug: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Get existing slug or create one for namespace."""
    conn = _get_conn(conn)

    cursor = conn.execute("SELECT slug, metadata FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    if row["slug"]:
        return row["slug"]

    metadata = json.loads(row["metadata"] or "{}")
    base_slug = suggested_slug or slugify(metadata.get("display_name", "")) or ns[:8]
    slug = make_unique_slug(base_slug, exclude_ns=ns, conn=conn)

    conn.execute("UPDATE namespaces SET slug = ? WHERE ns = ?", (slug, ns))
    conn.commit()
    return slug


def set_namespace_slug(ns: str, slug: str, conn: sqlite3.Connection | None = None) -> bool:
    """Set a namespace's slug. Returns False if slug already taken or ns not found."""
    conn = _get_conn(conn)

    clean_slug = slugify(slug)
    if not clean_slug:
        return False

    cursor = conn.execute("SELECT ns FROM namespaces WHERE slug = ? AND ns != ?", (clean_slug, ns))
    if cursor.fetchone():
        return False

    cursor = conn.execute("UPDATE namespaces SET slug = ? WHERE ns = ?", (clean_slug, ns))
    conn.commit()
    return cursor.rowcount > 0


def is_namespace_archived(ns: str, conn: sqlite3.Connection | None = None) -> bool:
    """Check if namespace is archived (read-only)."""
    conn = _get_conn(conn)
    cursor = conn.execute("SELECT archived_at FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row is not None and row["archived_at"] is not None


def archive_namespace(ns: str, conn: sqlite3.Connection | None = None) -> bool:
    """Archive a namespace (soft-delete, rejects future writes)."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE namespaces SET archived_at = ? WHERE ns = ? AND archived_at IS NULL", (now, ns)
    )
    conn.commit()
    return cursor.rowcount > 0


def get_namespace_ttl_hours(ns: str, conn: sqlite3.Connection | None = None) -> int:
    """Get the TTL hours for a namespace. Returns default for persistent namespaces."""
    conn = _get_conn(conn)
    cursor = conn.execute("SELECT ttl_hours FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row["ttl_hours"] if row else DEFAULT_TTL_HOURS


def list_namespaces(conn: sqlite3.Connection | None = None) -> list[dict]:
    """List all namespaces."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT ns, slug, metadata, ttl_hours, created_at, archived_at FROM namespaces ORDER BY created_at"
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "ns": row["ns"],
            "slug": row["slug"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
        for row in rows
    ]


def verify_namespace_secret(ns: str, secret: str, conn: sqlite3.Connection | None = None) -> bool:
    """Verify a namespace secret."""
    if derive_id(secret) != ns:
        return False

    conn = _get_conn(conn)
    cursor = conn.execute("SELECT secret_hash FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return False

    from .auth import verify_secret

    return verify_secret(secret, row["secret_hash"])


def delete_namespace(ns: str, conn: sqlite3.Connection | None = None) -> bool:
    """Delete a namespace and all its data."""
    conn = _get_conn(conn)
    cursor = conn.execute("DELETE FROM namespaces WHERE ns = ?", (ns,))
    conn.commit()
    return cursor.rowcount > 0


def update_namespace_metadata(
    ns: str,
    metadata: dict[str, Any],
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update namespace metadata."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE namespaces SET metadata = ? WHERE ns = ?", (json.dumps(metadata), ns)
    )
    conn.commit()
    return cursor.rowcount > 0


# --- Identity Operations ---


def create_identity(
    ns: str,
    metadata: dict[str, Any] | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, str]:
    """Create a new identity in a namespace. Returns {id, secret}."""
    conn = _get_conn(conn)

    secret = generate_secret()
    identity_id = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    conn.execute(
        "INSERT INTO identities (id, ns, secret_hash, metadata) VALUES (?, ?, ?, ?)",
        (identity_id, ns, secret_hash, metadata_json),
    )
    conn.commit()

    return {"id": identity_id, "secret": secret}


def get_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get identity by ID."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT id, metadata, created_at FROM identities WHERE ns = ? AND id = ?", (ns, identity_id)
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "id": row["id"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "created_at": row["created_at"],
        }
    return None


def get_identity_secret_hash(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Get the secret hash for an identity (used for invite creation)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?", (ns, identity_id)
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row["secret_hash"] if row else None


def list_identities(ns: str, conn: sqlite3.Connection | None = None) -> list[dict]:
    """List all identities in a namespace."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT id, metadata, created_at FROM identities WHERE ns = ? ORDER BY created_at", (ns,)
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "id": row["id"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def verify_identity_secret(
    ns: str,
    identity_id: str,
    secret: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Verify an identity secret."""
    if derive_id(secret) != identity_id:
        return False

    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?", (ns, identity_id)
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return False

    from .auth import verify_secret

    return verify_secret(secret, row["secret_hash"])


def verify_identity_in_namespace(
    ns: str,
    secret: str,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Verify a secret belongs to some identity in the namespace. Returns identity ID or None."""
    identity_id = derive_id(secret)

    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?", (ns, identity_id)
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    from .auth import verify_secret

    if verify_secret(secret, row["secret_hash"]):
        return identity_id
    return None


def delete_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Delete an identity and all its messages."""
    conn = _get_conn(conn)
    cursor = conn.execute("DELETE FROM identities WHERE ns = ? AND id = ?", (ns, identity_id))
    conn.commit()
    return cursor.rowcount > 0


def update_identity_metadata(
    ns: str,
    identity_id: str,
    metadata: dict[str, Any],
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update identity metadata."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE identities SET metadata = ? WHERE ns = ? AND id = ?",
        (json.dumps(metadata), ns, identity_id),
    )
    conn.commit()
    return cursor.rowcount > 0


# --- Message Operations ---


def send_message(
    ns: str,
    from_id: str,
    to_id: str,
    body: str,
    content_type: str = "text/plain",
    ttl_hours: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Send a message. Returns message info."""
    conn = _get_conn(conn)

    # Verify recipient exists
    cursor = conn.execute("SELECT id FROM identities WHERE ns = ? AND id = ?", (ns, to_id))
    row = cursor.fetchone()

    if not row:
        raise ValueError(f"Recipient {to_id} not found in namespace {ns}")

    mid = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    expires_at = None
    if ttl_hours is not None and ttl_hours > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

    conn.execute(
        """INSERT INTO messages (mid, ns, to_id, from_id, body, content_type, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (mid, ns, to_id, from_id, body, content_type, now, expires_at),
    )
    conn.commit()

    return {
        "mid": mid,
        "from": from_id,
        "to": to_id,
        "content_type": content_type,
        "created_at": now,
    }


def has_new_messages(
    ns: str,
    identity_id: str,
    after_mid: str | None = None,
    unread_only: bool = False,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if there are new messages without fetching them.

    This is a lightweight check using COUNT - more efficient than get_messages
    when you only need to know if messages exist.

    Args:
        ns: Namespace ID
        identity_id: Identity ID
        after_mid: Only count messages after this message ID
        unread_only: Only count unread messages

    Returns:
        True if there are matching messages, False otherwise.
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    query = """
        SELECT COUNT(*) FROM messages 
        WHERE ns = ? AND to_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
        AND archived_at IS NULL
    """
    params: list[Any] = [ns, identity_id, now]

    if unread_only:
        query += " AND read_at IS NULL"

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    cursor = conn.execute(query, tuple(params))
    count = cursor.fetchone()[0]
    return count > 0


def get_messages(
    ns: str,
    identity_id: str,
    unread_only: bool = False,
    after_mid: str | None = None,
    mark_as_read: bool = True,
    include_archived: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get messages for an identity, optionally marking unread messages as read."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    ttl_hours = get_namespace_ttl_hours(ns, conn=conn)

    query = """
        SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at
        FROM messages 
        WHERE ns = ? AND to_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
    """
    params: list[Any] = [ns, identity_id, now]

    if not include_archived:
        query += " AND archived_at IS NULL"

    if unread_only:
        query += " AND read_at IS NULL"

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    query += " ORDER BY mid"

    cursor = conn.execute(query, tuple(params))
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    messages = [
        {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row.get("archived_at"),
        }
        for row in rows
    ]

    if mark_as_read:
        unread_mids = [m["mid"] for m in messages if m["read_at"] is None]
        if unread_mids:
            if ttl_hours > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
            else:
                expires_at = None

            placeholders = ",".join("?" * len(unread_mids))
            conn.execute(
                f"UPDATE messages SET read_at = ?, expires_at = ? WHERE mid IN ({placeholders})",
                tuple([now, expires_at] + unread_mids),
            )
            conn.commit()

            for m in messages:
                if m["read_at"] is None:
                    m["read_at"] = now
                    m["expires_at"] = expires_at

    return messages


def get_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get a single message."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at
           FROM messages 
           WHERE ns = ? AND to_id = ? AND mid = ?
           AND (expires_at IS NULL OR expires_at > ?)""",
        (ns, identity_id, mid, now),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row.get("archived_at"),
        }
    return None


def delete_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Immediately delete a message."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "DELETE FROM messages WHERE ns = ? AND to_id = ? AND mid = ?", (ns, identity_id, mid)
    )
    conn.commit()
    return cursor.rowcount > 0


def archive_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Archive a message (hide from inbox but preserve)."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """UPDATE messages SET archived_at = ?, expires_at = NULL 
           WHERE ns = ? AND to_id = ? AND mid = ? AND archived_at IS NULL""",
        (now, ns, identity_id, mid),
    )
    conn.commit()
    return cursor.rowcount > 0


def unarchive_message(
    ns: str,
    identity_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Unarchive a message (restore to inbox)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE messages SET archived_at = NULL WHERE ns = ? AND to_id = ? AND mid = ?",
        (ns, identity_id, mid),
    )
    conn.commit()
    return cursor.rowcount > 0


def get_archived_messages(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get archived messages for an identity."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at
           FROM messages 
           WHERE ns = ? AND to_id = ? AND archived_at IS NOT NULL
           ORDER BY archived_at DESC""",
        (ns, identity_id),
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row["archived_at"],
        }
        for row in rows
    ]


# --- Invite Operations ---


def create_invite(
    invite_id: str,
    ns: str,
    identity_id: str,
    encrypted_secret: str,
    display_name: str | None = None,
    created_by: str | None = None,
    expires_at: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Create an invite record."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO invites 
           (invite_id, ns, identity_id, encrypted_secret, display_name, created_by, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (invite_id, ns, identity_id, encrypted_secret, display_name, created_by, now, expires_at),
    )
    conn.commit()

    return {
        "invite_id": invite_id,
        "ns": ns,
        "identity_id": identity_id,
        "display_name": display_name,
        "created_at": now,
        "expires_at": expires_at,
    }


def get_invite(invite_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get an invite by ID."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, encrypted_secret, display_name,
                  created_by, created_at, expires_at, claimed_at, claimed_by
           FROM invites WHERE invite_id = ?""",
        (invite_id,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row


def get_invite_info(invite_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get public invite info (without secrets)."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, display_name, created_at, expires_at, claimed_at
           FROM invites WHERE invite_id = ?""",
        (invite_id,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        ns_info = get_namespace(row["ns"], conn=conn)
        if ns_info:
            row["namespace_slug"] = ns_info.get("slug")
            row["namespace_display_name"] = ns_info.get("metadata", {}).get("display_name")
            row["namespace_ttl_hours"] = ns_info.get("ttl_hours")

        identity_info = get_identity(row["ns"], row["identity_id"], conn=conn)
        if identity_info:
            row["identity_display_name"] = identity_info.get("metadata", {}).get("display_name")

    return row


def claim_invite(
    invite_id: str,
    claimed_by: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Claim an invite (mark as used and return encrypted secret)."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, encrypted_secret, display_name,
                  created_by, created_at, expires_at, claimed_at
           FROM invites 
           WHERE invite_id = ? 
           AND claimed_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)""",
        (invite_id, now),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    conn.execute(
        "UPDATE invites SET claimed_at = ?, claimed_by = ? WHERE invite_id = ?",
        (now, claimed_by, invite_id),
    )
    conn.commit()

    ns_info = get_namespace(row["ns"], conn=conn)
    if ns_info:
        row["namespace_slug"] = ns_info.get("slug") or get_or_create_namespace_slug(
            row["ns"], conn=conn
        )
        row["namespace_display_name"] = ns_info.get("metadata", {}).get("display_name")
        row["namespace_ttl_hours"] = ns_info.get("ttl_hours")

    identity_info = get_identity(row["ns"], row["identity_id"], conn=conn)
    if identity_info:
        row["identity_display_name"] = identity_info.get("metadata", {}).get("display_name")

    row["claimed_at"] = now
    row["claimed_by"] = claimed_by

    return row


def list_invites(
    ns: str,
    include_claimed: bool = False,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List invites for a namespace."""
    conn = _get_conn(conn)

    query = """SELECT invite_id, ns, identity_id, display_name, created_by, 
                      created_at, expires_at, claimed_at, claimed_by
               FROM invites WHERE ns = ?"""

    if not include_claimed:
        query += " AND claimed_at IS NULL"

    query += " ORDER BY created_at DESC"

    cursor = conn.execute(query, (ns,))
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def revoke_invite(invite_id: str, conn: sqlite3.Connection | None = None) -> bool:
    """Revoke (delete) an invite."""
    conn = _get_conn(conn)
    cursor = conn.execute("DELETE FROM invites WHERE invite_id = ?", (invite_id,))
    conn.commit()
    return cursor.rowcount > 0


def cleanup_expired_invites(conn: sqlite3.Connection | None = None) -> int:
    """Delete expired unclaimed invites. Returns count deleted."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at <= ? AND claimed_at IS NULL",
        (now,),
    )
    conn.commit()
    return cursor.rowcount


# --- TTL and Archive Operations ---


def get_expired_messages(
    limit: int = 1000,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get messages past their expiration time."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, ns, to_id, from_id, body, content_type, created_at, read_at, expires_at
           FROM messages 
           WHERE expires_at IS NOT NULL AND expires_at <= ? AND archived_at IS NULL
           ORDER BY expires_at
           LIMIT ?""",
        (now, limit),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def delete_expired_messages(conn: sqlite3.Connection | None = None) -> int:
    """Delete all expired messages (excluding archived). Returns count deleted."""
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ? AND archived_at IS NULL",
        (now,),
    )
    conn.commit()
    return cursor.rowcount


def mark_messages_archived(
    mids: list[str],
    archive_key: str,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Mark messages as archived with a reference key."""
    if not mids:
        return 0
    return len(mids)


def create_archive_batch(
    ns: str,
    archive_path: str,
    message_count: int,
    min_created_at: str,
    max_created_at: str,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Record an archive batch."""
    conn = _get_conn(conn)
    batch_id = str(make_uuid7())
    conn.execute(
        """INSERT INTO archive_batches 
           (batch_id, ns, archive_path, message_count, min_created_at, max_created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (batch_id, ns, archive_path, message_count, min_created_at, max_created_at),
    )
    conn.commit()
    return batch_id


def get_archive_batches(
    ns: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get archive batch records, optionally filtered by namespace."""
    conn = _get_conn(conn)

    if ns:
        cursor = conn.execute(
            "SELECT * FROM archive_batches WHERE ns = ? ORDER BY created_at", (ns,)
        )
    else:
        cursor = conn.execute("SELECT * FROM archive_batches ORDER BY created_at")

    return _rows_to_dicts(cursor.description, cursor.fetchall())


# --- Room Operations ---


def create_room(
    ns: str,
    created_by: str,
    display_name: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Create a new room in a namespace.

    The creator is automatically added as the first member.

    Args:
        ns: Namespace ID
        created_by: Identity ID of the creator
        display_name: Optional display name for the room
        conn: Optional database connection

    Returns:
        Room info dict with room_id, ns, display_name, created_by, created_at
    """
    conn = _get_conn(conn)

    # Verify creator exists in namespace
    cursor = conn.execute("SELECT id FROM identities WHERE ns = ? AND id = ?", (ns, created_by))
    if not cursor.fetchone():
        raise ValueError(f"Creator {created_by} not found in namespace {ns}")

    room_id = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    # Create the room
    conn.execute(
        """INSERT INTO rooms (room_id, ns, display_name, created_by, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (room_id, ns, display_name, created_by, now),
    )

    # Add creator as first member
    conn.execute(
        """INSERT INTO room_members (room_id, identity_id, ns, joined_at)
           VALUES (?, ?, ?, ?)""",
        (room_id, created_by, ns, now),
    )

    conn.commit()

    return {
        "room_id": room_id,
        "ns": ns,
        "display_name": display_name,
        "created_by": created_by,
        "created_at": now,
    }


def get_room(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get room by ID.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Room info dict or None if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT room_id, ns, display_name, created_by, created_at
           FROM rooms WHERE room_id = ?""",
        (room_id,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row


def list_rooms(
    ns: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List all rooms in a namespace.

    Args:
        ns: Namespace ID
        conn: Optional database connection

    Returns:
        List of room info dicts
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT room_id, ns, display_name, created_by, created_at
           FROM rooms WHERE ns = ? ORDER BY created_at""",
        (ns,),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def list_rooms_for_identity(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List rooms that an identity is a member of.

    Args:
        ns: Namespace ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        List of room info dicts with member info
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT r.room_id, r.ns, r.display_name, r.created_by, r.created_at,
                  m.joined_at, m.last_read_mid,
                  (SELECT COUNT(*) FROM room_members rm WHERE rm.room_id = r.room_id)
                      AS member_count
           FROM rooms r
           JOIN room_members m ON r.room_id = m.room_id
           WHERE r.ns = ? AND m.identity_id = ?
           ORDER BY r.created_at""",
        (ns, identity_id),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def delete_room(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Delete a room and all its messages/members.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        True if deleted, False if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute("DELETE FROM rooms WHERE room_id = ?", (room_id,))
    conn.commit()
    return cursor.rowcount > 0


def is_room_member(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if an identity is a member of a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        True if member, False otherwise
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT 1 FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
    )
    return cursor.fetchone() is not None


def add_room_member(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Add a member to a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID to add
        conn: Optional database connection

    Returns:
        Member info dict

    Raises:
        ValueError: If room not found or identity not in same namespace
    """
    conn = _get_conn(conn)

    # Get room info to verify it exists and get namespace
    room = get_room(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    ns = room["ns"]

    # Verify identity exists in same namespace
    cursor = conn.execute("SELECT id FROM identities WHERE ns = ? AND id = ?", (ns, identity_id))
    if not cursor.fetchone():
        raise ValueError(f"Identity {identity_id} not found in namespace {ns}")

    # Check if already a member
    if is_room_member(room_id, identity_id, conn=conn):
        # Return existing membership
        cursor = conn.execute(
            "SELECT room_id, identity_id, ns, joined_at, last_read_mid FROM room_members WHERE room_id = ? AND identity_id = ?",
            (room_id, identity_id),
        )
        return _row_to_dict(cursor.description, cursor.fetchone())  # type: ignore

    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO room_members (room_id, identity_id, ns, joined_at)
           VALUES (?, ?, ?, ?)""",
        (room_id, identity_id, ns, now),
    )
    conn.commit()

    return {
        "room_id": room_id,
        "identity_id": identity_id,
        "ns": ns,
        "joined_at": now,
        "last_read_mid": None,
    }


def remove_room_member(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Remove a member from a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID to remove
        conn: Optional database connection

    Returns:
        True if removed, False if not a member
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "DELETE FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def list_room_members(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List all members of a room.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        List of member info dicts with identity metadata
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT m.room_id, m.identity_id, m.ns, m.joined_at, m.last_read_mid,
                  i.metadata
           FROM room_members m
           JOIN identities i ON m.ns = i.ns AND m.identity_id = i.id
           WHERE m.room_id = ?
           ORDER BY m.joined_at""",
        (room_id,),
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    # Parse metadata JSON
    for row in rows:
        row["metadata"] = json.loads(row.get("metadata") or "{}")

    return rows


def send_room_message(
    room_id: str,
    from_id: str,
    body: str,
    content_type: str = "text/plain",
    reference_mid: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Send a message to a room.

    Args:
        room_id: Room ID
        from_id: Sender identity ID (must be a member)
        body: Message body
        content_type: Content type (default: text/plain)
        reference_mid: Optional message ID this message references (e.g. for reactions)
        conn: Optional database connection

    Returns:
        Message info dict

    Raises:
        ValueError: If room not found or sender not a member
    """
    conn = _get_conn(conn)

    # Verify room exists
    room = get_room(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    # Verify sender is a member
    if not is_room_member(room_id, from_id, conn=conn):
        raise ValueError(f"Identity {from_id} is not a member of room {room_id}")

    mid = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO room_messages
               (mid, room_id, from_id, body, content_type, reference_mid, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (mid, room_id, from_id, body, content_type, reference_mid, now),
    )
    conn.commit()

    return {
        "mid": mid,
        "room_id": room_id,
        "from": from_id,
        "body": body,
        "content_type": content_type,
        "reference_mid": reference_mid,
        "created_at": now,
    }


def has_new_room_messages(
    room_id: str,
    after_mid: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if there are new messages in a room.

    Lightweight check using COUNT - efficient for polling.

    Args:
        room_id: Room ID
        after_mid: Only count messages after this message ID
        conn: Optional database connection

    Returns:
        True if there are new messages
    """
    conn = _get_conn(conn)

    query = "SELECT COUNT(*) FROM room_messages WHERE room_id = ?"
    params: list[Any] = [room_id]

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    cursor = conn.execute(query, tuple(params))
    count = cursor.fetchone()[0]
    return count > 0


def get_room_messages(
    room_id: str,
    after_mid: str | None = None,
    limit: int = 100,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """Get messages from a room.

    Args:
        room_id: Room ID
        after_mid: Only get messages after this message ID (for pagination/polling)
        limit: Maximum number of messages to return
        conn: Optional database connection

    Returns:
        List of message dicts ordered by creation time
    """
    conn = _get_conn(conn)

    query = """
        SELECT mid, room_id, from_id, body, content_type, reference_mid, created_at
        FROM room_messages
        WHERE room_id = ?
    """
    params: list[Any] = [room_id]

    if after_mid:
        query += " AND mid > ?"
        params.append(after_mid)

    query += " ORDER BY mid LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, tuple(params))
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "mid": row["mid"],
            "room_id": row["room_id"],
            "from": row["from_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "reference_mid": row.get("reference_mid"),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def get_room_message(
    room_id: str,
    mid: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get a single room message.

    Args:
        room_id: Room ID
        mid: Message ID
        conn: Optional database connection

    Returns:
        Message dict or None if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT mid, room_id, from_id, body, content_type, reference_mid, created_at
           FROM room_messages WHERE room_id = ? AND mid = ?""",
        (room_id, mid),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "mid": row["mid"],
            "room_id": row["room_id"],
            "from": row["from_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "reference_mid": row.get("reference_mid"),
            "created_at": row["created_at"],
        }
    return None


def update_room_read_cursor(
    room_id: str,
    identity_id: str,
    last_read_mid: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update the read cursor for a member in a room.

    Only updates if the new cursor is ahead of the current one.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        last_read_mid: Message ID of the last read message
        conn: Optional database connection

    Returns:
        True if updated, False if member not found
    """
    conn = _get_conn(conn)

    # Only update if cursor moves forward (UUID7 is lexicographically sortable)
    cursor = conn.execute(
        """UPDATE room_members 
           SET last_read_mid = ?
           WHERE room_id = ? AND identity_id = ?
           AND (last_read_mid IS NULL OR last_read_mid < ?)""",
        (last_read_mid, room_id, identity_id, last_read_mid),
    )
    conn.commit()

    # Return True if we actually updated (not just if member exists)
    # If the cursor didn't move, rowcount will be 0
    if cursor.rowcount > 0:
        return True

    # Check if member exists (they might already have a later cursor)
    cursor = conn.execute(
        "SELECT 1 FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
    )
    return cursor.fetchone() is not None


def get_room_unread_count(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Get the count of unread messages for a member in a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        Number of unread messages (0 if not a member)
    """
    conn = _get_conn(conn)

    # Get member's last read cursor
    cursor = conn.execute(
        "SELECT last_read_mid FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
    )
    row = cursor.fetchone()

    if not row:
        return 0  # Not a member

    last_read_mid = row[0]

    # Count messages after the cursor
    if last_read_mid:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM room_messages WHERE room_id = ? AND mid > ?",
            (room_id, last_read_mid),
        )
    else:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM room_messages WHERE room_id = ?",
            (room_id,),
        )

    return cursor.fetchone()[0]


def get_room_member_info(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get membership info for an identity in a room.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        Member info dict or None if not a member
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT m.room_id, m.identity_id, m.ns, m.joined_at, m.last_read_mid,
                  i.metadata
           FROM room_members m
           JOIN identities i ON m.ns = i.ns AND m.identity_id = i.id
           WHERE m.room_id = ? AND m.identity_id = ?""",
        (room_id, identity_id),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        row["metadata"] = json.loads(row.get("metadata") or "{}")

    return row


# --- Optimized Combined Queries for Performance ---
# These functions reduce round-trips by combining multiple queries into one
# and leveraging caching for frequently-accessed data.


def verify_room_access(
    room_id: str,
    identity_id: str,
    secret: str,
    conn: sqlite3.Connection | None = None,
) -> tuple[dict | None, str | None]:
    """Verify room access in a single optimized query.

    This combines:
    - get_room (room exists check)
    - is_room_member (membership check)
    - verify_identity_secret (auth check)

    Into a single database round-trip plus cached hash verification.

    Args:
        room_id: Room ID to access
        identity_id: Identity ID (derived from secret)
        secret: The inbox secret for verification
        conn: Optional database connection

    Returns:
        (room, error_message) tuple:
        - If successful: (room_dict, None)
        - If failed: (None, error_message)
    """
    from .auth import derive_id, verify_secret
    from .cache import identity_hash_cache, membership_cache, room_cache
    from .metrics import timed_db_operation

    # First verify the identity_id matches the secret (no DB needed)
    if derive_id(secret) != identity_id:
        return None, "Secret does not match identity"

    # Check room cache first
    cache_hit, cached_room = room_cache.get(f"room:{room_id}")
    if cache_hit and cached_room is None:
        return None, "Room not found"

    # Check membership cache
    membership_key = f"member:{room_id}:{identity_id}"
    membership_hit, is_member = membership_cache.get(membership_key)

    # Check identity hash cache
    ns = cached_room["ns"] if cache_hit and cached_room else None
    identity_key = f"identity:{ns}:{identity_id}" if ns else None
    hash_hit, cached_hash = identity_hash_cache.get(identity_key) if identity_key else (False, None)

    # If all cache hits, we can skip the database entirely
    if cache_hit and cached_room and membership_hit and is_member and hash_hit and cached_hash:
        # Just verify the password hash
        if verify_secret(secret, cached_hash):
            return cached_room, None
        else:
            return None, "Invalid inbox secret"

    # Need to hit database - use optimized combined query
    conn = _get_conn(conn)

    with timed_db_operation("verify_room_access"):
        cursor = conn.execute(
            """
            SELECT 
                r.room_id, r.ns, r.display_name, r.created_by, r.created_at,
                m.identity_id as member_id,
                i.secret_hash
            FROM rooms r
            LEFT JOIN room_members m ON r.room_id = m.room_id AND m.identity_id = ?
            LEFT JOIN identities i ON r.ns = i.ns AND i.id = ?
            WHERE r.room_id = ?
            """,
            (identity_id, identity_id, room_id),
        )
        row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        room_cache.set(f"room:{room_id}", None, ttl=60)  # Cache negative result briefly
        return None, "Room not found"

    # Build room dict
    room = {
        "room_id": row["room_id"],
        "ns": row["ns"],
        "display_name": row["display_name"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }

    # Cache the room
    room_cache.set(f"room:{room_id}", room)

    # Check membership
    if not row.get("member_id"):
        membership_cache.set(membership_key, False)
        return None, "Not a member of this room"
    membership_cache.set(membership_key, True)

    # Check identity exists and verify secret
    secret_hash = row.get("secret_hash")
    if not secret_hash:
        return None, "Identity not found in namespace"

    # Cache the hash
    identity_hash_cache.set(f"identity:{room['ns']}:{identity_id}", secret_hash)

    # Verify the secret
    if not verify_secret(secret, secret_hash):
        return None, "Invalid inbox secret"

    return room, None


def get_room_cached(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get room by ID with caching.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Room info dict or None if not found
    """
    from .cache import room_cache
    from .metrics import timed_db_operation

    # Check cache first
    cache_hit, cached_room = room_cache.get(f"room:{room_id}")
    if cache_hit:
        return cached_room

    # Cache miss - fetch from database
    conn = _get_conn(conn)

    with timed_db_operation("get_room_cached"):
        cursor = conn.execute(
            """SELECT room_id, ns, display_name, created_by, created_at
               FROM rooms WHERE room_id = ?""",
            (room_id,),
        )
        row = _row_to_dict(cursor.description, cursor.fetchone())

    # Cache the result (even if None)
    room_cache.set(f"room:{room_id}", row, ttl=60 if row is None else 300)
    return row


def get_identity_hash_cached(
    ns: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> str | None:
    """Get identity secret hash with caching.

    Args:
        ns: Namespace ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        Secret hash or None if identity not found
    """
    from .cache import identity_hash_cache
    from .metrics import timed_db_operation

    cache_key = f"identity:{ns}:{identity_id}"
    cache_hit, cached_hash = identity_hash_cache.get(cache_key)
    if cache_hit:
        return cached_hash

    conn = _get_conn(conn)

    with timed_db_operation("get_identity_hash_cached"):
        cursor = conn.execute(
            "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?",
            (ns, identity_id),
        )
        row = cursor.fetchone()

    secret_hash = row[0] if row else None
    identity_hash_cache.set(cache_key, secret_hash)
    return secret_hash


def is_room_member_cached(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Check if an identity is a member of a room with caching.

    Args:
        room_id: Room ID
        identity_id: Identity ID
        conn: Optional database connection

    Returns:
        True if member, False otherwise
    """
    from .cache import membership_cache
    from .metrics import timed_db_operation

    cache_key = f"member:{room_id}:{identity_id}"
    cache_hit, is_member = membership_cache.get(cache_key)
    if cache_hit:
        return is_member

    conn = _get_conn(conn)

    with timed_db_operation("is_room_member_cached"):
        cursor = conn.execute(
            "SELECT 1 FROM room_members WHERE room_id = ? AND identity_id = ?",
            (room_id, identity_id),
        )
        is_member = cursor.fetchone() is not None

    membership_cache.set(cache_key, is_member)
    return is_member
