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


# =============================================================================
# Custom Exceptions
# =============================================================================


class EpochMismatchError(ValueError):
    """Raised when message epoch doesn't match room's current epoch.

    This error provides information for clients to fetch the correct epoch key
    and retry their request.
    """

    def __init__(
        self,
        message: str,
        expected_epoch: int,
        provided_epoch: int,
        room_id: str,
    ):
        super().__init__(message)
        self.expected_epoch = expected_epoch
        self.provided_epoch = provided_epoch
        self.room_id = room_id


# Current schema version (increment when adding migrations)
# v1: Base schema
# v2: Add rooms tables for group communication
# v3: Add e2e encryption infrastructure (pubkeys table, encryption columns)
SCHEMA_VERSION = 4

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
        if _conn is None:
            import libsql_experimental as libsql  # type: ignore[import-not-found]

            _conn = libsql.connect(db_url, auth_token=os.environ.get("TURSO_AUTH_TOKEN", ""))
            _is_libsql = True
        return _conn

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


def _migrate_003_add_encryption(conn: sqlite3.Connection) -> None:
    """Migration 003: Add e2e encryption support.

    Adds:
    - pubkeys table for versioned public keys
    - identities.current_pubkey_id reference
    - messages.encrypted flag
    - messages.signature for Ed25519 signatures
    - messages.encryption_meta for encryption metadata (algorithm, pubkey_id)
    """
    conn.executescript("""
        -- Versioned public keys table
        CREATE TABLE IF NOT EXISTS pubkeys (
            pubkey_id TEXT PRIMARY KEY,
            ns TEXT NOT NULL,
            identity_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            signing_public_key TEXT NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'nacl-box',
            version INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP,
            FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE,
            UNIQUE(ns, identity_id, version)
        );
        
        CREATE INDEX IF NOT EXISTS idx_pubkeys_identity ON pubkeys(ns, identity_id);
        CREATE INDEX IF NOT EXISTS idx_pubkeys_active ON pubkeys(ns, identity_id, revoked_at) 
            WHERE revoked_at IS NULL;
    """)
    conn.commit()

    # Add columns to existing tables (SQLite requires separate ALTER statements)
    # Check if columns exist before adding (for idempotency)
    cursor = conn.execute("PRAGMA table_info(identities)")
    identity_columns = {row[1] for row in cursor.fetchall()}

    if "current_pubkey_id" not in identity_columns:
        conn.execute("ALTER TABLE identities ADD COLUMN current_pubkey_id TEXT")

    cursor = conn.execute("PRAGMA table_info(messages)")
    message_columns = {row[1] for row in cursor.fetchall()}

    if "encrypted" not in message_columns:
        conn.execute("ALTER TABLE messages ADD COLUMN encrypted BOOLEAN DEFAULT FALSE")
    if "signature" not in message_columns:
        conn.execute("ALTER TABLE messages ADD COLUMN signature TEXT")
    if "encryption_meta" not in message_columns:
        conn.execute("ALTER TABLE messages ADD COLUMN encryption_meta JSON")
    if "signature_meta" not in message_columns:
        conn.execute("ALTER TABLE messages ADD COLUMN signature_meta JSON")

    conn.commit()


def _migrate_004_add_room_encryption(conn: sqlite3.Connection) -> None:
    """Migration 004: Add room encryption support (epochs and encrypted messages).

    Adds:
    - room_epochs table for tracking encryption epochs
    - room_epoch_keys table for distributing encrypted keys to members (legacy, kept for compatibility)
    - rooms.encryption_enabled flag
    - rooms.current_epoch_number tracking
    - rooms.base_secret for key derivation (DEPRECATED - legacy server-mediated mode)
    - rooms.secret_version for tracking base secret rotations (true E2E mode)
    - room_messages encryption fields (epoch_number, encrypted, encryption_meta, signature)
    - room_member_secrets table for encrypted base secrets per member (true E2E mode)
    """
    # Create room_epochs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_epochs (
            epoch_id TEXT PRIMARY KEY,
            room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
            epoch_number INTEGER NOT NULL,
            membership_hash TEXT NOT NULL,
            reason TEXT NOT NULL,
            triggered_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(room_id, epoch_number)
        )
    """)

    # Create room_epoch_keys table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_epoch_keys (
            epoch_id TEXT NOT NULL REFERENCES room_epochs(epoch_id) ON DELETE CASCADE,
            identity_id TEXT NOT NULL,
            encrypted_epoch_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (epoch_id, identity_id)
        )
    """)

    # Create indexes
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_epochs_room ON room_epochs(room_id, epoch_number)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_epoch_keys_identity ON room_epoch_keys(identity_id)"
    )

    conn.commit()

    # Add columns to rooms table
    cursor = conn.execute("PRAGMA table_info(rooms)")
    room_columns = {row[1] for row in cursor.fetchall()}

    if "encryption_enabled" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN encryption_enabled BOOLEAN DEFAULT 0")
    if "current_epoch_number" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN current_epoch_number INTEGER DEFAULT 0")
    if "base_secret" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN base_secret TEXT")
    if "server_private_key" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN server_private_key TEXT")
    if "server_public_key" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN server_public_key TEXT")
    if "secret_version" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN secret_version INTEGER DEFAULT 0")
    if "pending_removal_id" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN pending_removal_id TEXT")
    if "pending_removal_at" not in room_columns:
        conn.execute("ALTER TABLE rooms ADD COLUMN pending_removal_at TIMESTAMP")

    # Create room_member_secrets table for true E2E mode
    conn.execute("""
        CREATE TABLE IF NOT EXISTS room_member_secrets (
            room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
            identity_id TEXT NOT NULL,
            encrypted_base_secret TEXT NOT NULL,
            inviter_public_key TEXT NOT NULL,
            secret_version INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (room_id, identity_id, secret_version)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_room_member_secrets_identity "
        "ON room_member_secrets(room_id, identity_id)"
    )

    # Add columns to room_messages table
    cursor = conn.execute("PRAGMA table_info(room_messages)")
    message_columns = {row[1] for row in cursor.fetchall()}

    if "epoch_number" not in message_columns:
        conn.execute("ALTER TABLE room_messages ADD COLUMN epoch_number INTEGER")
    if "encrypted" not in message_columns:
        conn.execute("ALTER TABLE room_messages ADD COLUMN encrypted BOOLEAN DEFAULT 0")
    if "encryption_meta" not in message_columns:
        conn.execute("ALTER TABLE room_messages ADD COLUMN encryption_meta TEXT")
    if "signature" not in message_columns:
        conn.execute("ALTER TABLE room_messages ADD COLUMN signature TEXT")

    conn.commit()


# Migration registry: (version, description, migration_function)
MIGRATIONS: list[tuple[int, str, Callable[[sqlite3.Connection], None]]] = [
    (1, "Add content_type column to messages", _migrate_001_add_content_type),
    (2, "Add rooms tables for group communication", _migrate_002_add_rooms),
    (3, "Add e2e encryption infrastructure", _migrate_003_add_encryption),
    (4, "Add room encryption support", _migrate_004_add_room_encryption),
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
        current_pubkey_id TEXT,
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
        encrypted BOOLEAN DEFAULT FALSE,
        signature TEXT,
        encryption_meta JSON,
        signature_meta JSON,
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        encryption_enabled BOOLEAN DEFAULT 0,
        current_epoch_number INTEGER DEFAULT 0,
        base_secret TEXT,
        server_private_key TEXT,
        server_public_key TEXT,
        secret_version INTEGER DEFAULT 0,
        pending_removal_id TEXT,
        pending_removal_at TIMESTAMP
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        epoch_number INTEGER,
        encrypted BOOLEAN DEFAULT 0,
        encryption_meta TEXT,
        signature TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id, created_at);
    
    -- Room encryption epochs
    CREATE TABLE IF NOT EXISTS room_epochs (
        epoch_id TEXT PRIMARY KEY,
        room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        epoch_number INTEGER NOT NULL,
        membership_hash TEXT NOT NULL,
        reason TEXT NOT NULL,
        triggered_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(room_id, epoch_number)
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_epochs_room ON room_epochs(room_id, epoch_number);
    
    -- Encrypted epoch keys per member
    CREATE TABLE IF NOT EXISTS room_epoch_keys (
        epoch_id TEXT NOT NULL REFERENCES room_epochs(epoch_id) ON DELETE CASCADE,
        identity_id TEXT NOT NULL,
        encrypted_epoch_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (epoch_id, identity_id)
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_epoch_keys_identity ON room_epoch_keys(identity_id);
    
    -- Encrypted base secrets per member (true E2E mode)
    CREATE TABLE IF NOT EXISTS room_member_secrets (
        room_id TEXT NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
        identity_id TEXT NOT NULL,
        encrypted_base_secret TEXT NOT NULL,
        inviter_public_key TEXT NOT NULL,
        secret_version INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (room_id, identity_id, secret_version)
    );
    
    CREATE INDEX IF NOT EXISTS idx_room_member_secrets_identity 
        ON room_member_secrets(room_id, identity_id);
    
    -- Public keys for e2e encryption
    CREATE TABLE IF NOT EXISTS pubkeys (
        pubkey_id TEXT PRIMARY KEY,
        ns TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        signing_public_key TEXT NOT NULL,
        algorithm TEXT NOT NULL DEFAULT 'nacl-box',
        version INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        revoked_at TIMESTAMP,
        FOREIGN KEY (ns, identity_id) REFERENCES identities(ns, id) ON DELETE CASCADE,
        UNIQUE(ns, identity_id, version)
    );
    
    CREATE INDEX IF NOT EXISTS idx_pubkeys_identity ON pubkeys(ns, identity_id);
    CREATE INDEX IF NOT EXISTS idx_pubkeys_active ON pubkeys(ns, identity_id, revoked_at) 
        WHERE revoked_at IS NULL;
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
        DROP TABLE IF EXISTS room_epoch_keys;
        DROP TABLE IF EXISTS room_epochs;
        DROP TABLE IF EXISTS room_messages;
        DROP TABLE IF EXISTS room_members;
        DROP TABLE IF EXISTS rooms;
        DROP TABLE IF EXISTS pubkeys;
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
    """Get identity by ID, including current pubkey info."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT i.id, i.metadata, i.created_at, i.current_pubkey_id,
                  p.public_key, p.signing_public_key, p.algorithm, p.version as pubkey_version
           FROM identities i
           LEFT JOIN pubkeys p ON i.current_pubkey_id = p.pubkey_id
           WHERE i.ns = ? AND i.id = ?""",
        (ns, identity_id),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        result = {
            "id": row["id"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "created_at": row["created_at"],
        }
        # Add pubkey info if present
        if row.get("current_pubkey_id"):
            result["pubkey_id"] = row["current_pubkey_id"]
            result["public_key"] = row["public_key"]
            result["signing_public_key"] = row["signing_public_key"]
            result["algorithm"] = row["algorithm"]
            result["pubkey_version"] = row["pubkey_version"]
        return result
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
    """List all identities in a namespace, including current pubkey info."""
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT i.id, i.metadata, i.created_at, i.current_pubkey_id,
                  p.public_key, p.signing_public_key, p.algorithm, p.version as pubkey_version
           FROM identities i
           LEFT JOIN pubkeys p ON i.current_pubkey_id = p.pubkey_id
           WHERE i.ns = ? 
           ORDER BY i.created_at""",
        (ns,),
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    result = []
    for row in rows:
        item = {
            "id": row["id"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "created_at": row["created_at"],
        }
        # Add pubkey info if present
        if row.get("current_pubkey_id"):
            item["pubkey_id"] = row["current_pubkey_id"]
            item["public_key"] = row["public_key"]
            item["signing_public_key"] = row["signing_public_key"]
            item["algorithm"] = row["algorithm"]
            item["pubkey_version"] = row["pubkey_version"]
        result.append(item)
    return result


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
    encrypted: bool = False,
    encryption_meta: dict | None = None,
    signature: str | None = None,
    signature_meta: dict | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Send a message. Returns message info.

    Args:
        ns: Namespace
        from_id: Sender identity
        to_id: Recipient identity
        body: Message body (plaintext or base64 ciphertext if encrypted)
        content_type: MIME type of the message content
        ttl_hours: Optional TTL override (for ephemeral messages that expire from creation)
        encrypted: Whether the body is encrypted
        encryption_meta: Encryption metadata (algorithm, recipient_pubkey_id)
        signature: Base64-encoded signature
        signature_meta: Signature metadata (algorithm, sender_pubkey_id)
        conn: Optional database connection
    """
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

    # Store signature in signature_meta if provided
    if signature and signature_meta:
        signature_meta = {**signature_meta, "value": signature}

    conn.execute(
        """INSERT INTO messages (mid, ns, to_id, from_id, body, content_type, created_at, expires_at,
                                 encrypted, encryption_meta, signature_meta)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            mid,
            ns,
            to_id,
            from_id,
            body,
            content_type,
            now,
            expires_at,
            encrypted,
            json.dumps(encryption_meta) if encryption_meta else None,
            json.dumps(signature_meta) if signature_meta else None,
        ),
    )
    conn.commit()

    return {
        "mid": mid,
        "from": from_id,
        "to": to_id,
        "content_type": content_type,
        "created_at": now,
        "encrypted": encrypted,
        "encryption_meta": encryption_meta,
        "signature_meta": signature_meta,
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
        SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at,
               encrypted, encryption_meta, signature_meta
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

    messages = []
    for row in rows:
        msg = {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row.get("archived_at"),
            "encrypted": bool(row.get("encrypted")),
        }
        # Parse JSON metadata fields
        if row.get("encryption_meta"):
            msg["encryption_meta"] = json.loads(row["encryption_meta"])
        if row.get("signature_meta"):
            msg["signature_meta"] = json.loads(row["signature_meta"])
        messages.append(msg)

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
        """SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at,
                  encrypted, encryption_meta, signature_meta
           FROM messages 
           WHERE ns = ? AND to_id = ? AND mid = ?
           AND (expires_at IS NULL OR expires_at > ?)""",
        (ns, identity_id, mid, now),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        msg = {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row.get("archived_at"),
            "encrypted": bool(row.get("encrypted")),
        }
        if row.get("encryption_meta"):
            msg["encryption_meta"] = json.loads(row["encryption_meta"])
        if row.get("signature_meta"):
            msg["signature_meta"] = json.loads(row["signature_meta"])
        return msg
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
        """SELECT mid, from_id, to_id, body, content_type, created_at, read_at, expires_at, archived_at,
                  encrypted, encryption_meta, signature_meta
           FROM messages 
           WHERE ns = ? AND to_id = ? AND archived_at IS NOT NULL
           ORDER BY archived_at DESC""",
        (ns, identity_id),
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    messages = []
    for row in rows:
        msg = {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
            "archived_at": row["archived_at"],
            "encrypted": bool(row.get("encrypted")),
        }
        if row.get("encryption_meta"):
            msg["encryption_meta"] = json.loads(row["encryption_meta"])
        if row.get("signature_meta"):
            msg["signature_meta"] = json.loads(row["signature_meta"])
        messages.append(msg)
    return messages


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
        List of room info dicts with member info including encryption status
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT r.room_id, r.ns, r.display_name, r.created_by, r.created_at,
                  m.joined_at, m.last_read_mid,
                  r.encryption_enabled, r.current_epoch_number
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
    trigger_rotation: bool = True,
) -> dict:
    """Add a member to a room.

    For encrypted rooms:
    - Identity must have a registered public key
    - Adding a member triggers epoch rotation (unless trigger_rotation=False)

    Args:
        room_id: Room ID
        identity_id: Identity ID to add
        conn: Optional database connection
        trigger_rotation: If True and room is encrypted, trigger epoch rotation

    Returns:
        Member info dict

    Raises:
        ValueError: If room not found, identity not in namespace, or
                   identity lacks pubkey for encrypted room
    """
    conn = _get_conn(conn)

    # Get room info including encryption status
    room = get_room_with_encryption(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    ns = room["ns"]

    # Verify identity exists in same namespace
    cursor = conn.execute(
        "SELECT id, current_pubkey_id FROM identities WHERE ns = ? AND id = ?",
        (ns, identity_id),
    )
    identity_row = cursor.fetchone()
    if not identity_row:
        raise ValueError(f"Identity {identity_id} not found in namespace {ns}")

    # For encrypted rooms, verify identity has a pubkey
    if room["encryption_enabled"]:
        current_pubkey_id = identity_row[1]
        if not current_pubkey_id:
            raise ValueError(
                f"Identity {identity_id} must have a registered pubkey to join encrypted room"
            )

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

    # Trigger epoch rotation for encrypted rooms (server-mediated mode only)
    # For E2E mode (no base_secret), the inviter must call rotate_room_secret_e2e separately
    is_e2e_mode = room["encryption_enabled"] and room.get("base_secret") is None
    if room["encryption_enabled"] and trigger_rotation and not is_e2e_mode:
        rotate_room_epoch(room_id, reason="member_joined", triggered_by=identity_id, conn=conn)

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
    trigger_rotation: bool = True,
    use_two_phase: bool | None = None,
) -> dict:
    """Remove a member from a room.

    For E2E encrypted rooms with true forward secrecy, this uses a two-phase
    protocol where the removal is "pending" until a remaining member rotates
    the secret with fresh randomness.

    For server-mediated encrypted rooms, immediate removal with HKDF rotation
    is used (less secure but simpler).

    Args:
        room_id: Room ID
        identity_id: Identity ID to remove
        conn: Optional database connection
        trigger_rotation: If True and room is encrypted, trigger epoch rotation
            (only applies to non-E2E rooms)
        use_two_phase: If True, use two-phase protocol. If None, auto-detect
            based on whether room uses E2E mode (has secret_version set)

    Returns:
        Dict with removal status:
        - For immediate removal: {"removed": True, "immediate": True}
        - For pending removal: {"removed": False, "pending": True, "pending_removal_id": ..., ...}
        - For not a member: {"removed": False, "immediate": False, "error": "not_member"}
    """
    conn = _get_conn(conn)

    # Get room encryption status before removal
    room = get_room_with_encryption(room_id, conn=conn)
    if not room:
        return {"removed": False, "immediate": False, "error": "room_not_found"}

    is_encrypted = room and room["encryption_enabled"]

    # Check if this room uses E2E mode (no plaintext base_secret stored)
    # E2E mode is indicated by encryption enabled but no base_secret
    # Server-mediated mode stores base_secret; E2E mode doesn't
    is_e2e_mode = is_encrypted and room.get("base_secret") is None

    # Decide whether to use two-phase protocol
    if use_two_phase is None:
        use_two_phase = bool(is_e2e_mode)

    # Two-phase protocol for E2E rooms
    if use_two_phase and is_encrypted:
        # Set as pending removal instead of immediate
        try:
            result = set_pending_removal(room_id, identity_id, conn=conn)
            return {
                "removed": False,
                "pending": True,
                "pending_removal_id": result["pending_removal_id"],
                "pending_removal_at": result["pending_removal_at"],
                "message": "Removal pending. A remaining member must rotate the secret.",
            }
        except ValueError as e:
            return {"removed": False, "pending": False, "error": str(e)}

    # Immediate removal for non-E2E rooms
    cursor = conn.execute(
        "DELETE FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
    )
    conn.commit()

    removed = cursor.rowcount > 0

    if not removed:
        return {"removed": False, "immediate": False, "error": "not_member"}

    # Trigger epoch rotation for encrypted rooms if member was actually removed
    # and there are still members left (server-mediated mode only)
    # For E2E mode, rotation must be done separately with fresh secrets
    if removed and is_encrypted and trigger_rotation and not use_two_phase and not is_e2e_mode:
        members = list_room_members(room_id, conn=conn)
        if members:  # Only rotate if there are remaining members
            rotate_room_epoch(room_id, reason="member_left", triggered_by=identity_id, conn=conn)

    return {"removed": True, "immediate": True}


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
    epoch_number: int | None = None,
    encrypted: bool = False,
    encryption_meta: str | None = None,
    signature: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Send a message to a room.

    For encrypted rooms, the message body should already be encrypted by the client.
    The server validates that epoch_number matches the current epoch.

    Args:
        room_id: Room ID
        from_id: Sender identity ID (must be a member)
        body: Message body (encrypted ciphertext for encrypted rooms)
        content_type: Content type (default: text/plain)
        epoch_number: Epoch number the message was encrypted with (for encrypted rooms)
        encrypted: Whether the message is encrypted
        encryption_meta: JSON string with encryption metadata (algorithm, nonce, etc.)
        signature: Base64-encoded signature
        conn: Optional database connection

    Returns:
        Message info dict

    Raises:
        ValueError: If room not found or sender not a member
        EpochMismatchError: If epoch_number doesn't match current room epoch
    """
    conn = _get_conn(conn)

    # Get room with encryption status
    room = get_room_with_encryption(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    # Verify sender is a member
    if not is_room_member(room_id, from_id, conn=conn):
        raise ValueError(f"Identity {from_id} is not a member of room {room_id}")

    # Validate epoch for encrypted messages
    if encrypted and epoch_number is not None:
        current_epoch = room["current_epoch_number"]
        if epoch_number != current_epoch:
            raise EpochMismatchError(
                f"Epoch mismatch: message epoch {epoch_number}, current epoch {current_epoch}",
                expected_epoch=current_epoch,
                provided_epoch=epoch_number,
                room_id=room_id,
            )

    mid = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO room_messages 
           (mid, room_id, from_id, body, content_type, created_at, epoch_number, encrypted, encryption_meta, signature)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            mid,
            room_id,
            from_id,
            body,
            content_type,
            now,
            epoch_number,
            encrypted,
            encryption_meta,
            signature,
        ),
    )
    conn.commit()

    result = {
        "mid": mid,
        "room_id": room_id,
        "from": from_id,
        "body": body,
        "content_type": content_type,
        "created_at": now,
    }

    if encrypted:
        result["encrypted"] = True
        result["epoch_number"] = epoch_number
        if encryption_meta:
            result["encryption_meta"] = encryption_meta
        if signature:
            result["signature"] = signature

    return result


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
        List of message dicts ordered by creation time.
        For encrypted messages, includes epoch_number, encrypted, encryption_meta, signature.
    """
    conn = _get_conn(conn)

    query = """
        SELECT mid, room_id, from_id, body, content_type, created_at,
               epoch_number, encrypted, encryption_meta, signature
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

    messages = []
    for row in rows:
        msg = {
            "mid": row["mid"],
            "room_id": row["room_id"],
            "from": row["from_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
        }
        # Include encryption fields if message is encrypted
        if row.get("encrypted"):
            msg["encrypted"] = True
            msg["epoch_number"] = row.get("epoch_number")
            if row.get("encryption_meta"):
                msg["encryption_meta"] = row["encryption_meta"]
            if row.get("signature"):
                msg["signature"] = row["signature"]
        messages.append(msg)

    return messages


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
        Message dict or None if not found.
        For encrypted messages, includes epoch_number, encrypted, encryption_meta, signature.
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT mid, room_id, from_id, body, content_type, created_at,
                  epoch_number, encrypted, encryption_meta, signature
           FROM room_messages WHERE room_id = ? AND mid = ?""",
        (room_id, mid),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        msg = {
            "mid": row["mid"],
            "room_id": row["room_id"],
            "from": row["from_id"],
            "body": row["body"],
            "content_type": row.get("content_type") or "text/plain",
            "created_at": row["created_at"],
        }
        # Include encryption fields if message is encrypted
        if row.get("encrypted"):
            msg["encrypted"] = True
            msg["epoch_number"] = row.get("epoch_number")
            if row.get("encryption_meta"):
                msg["encryption_meta"] = row["encryption_meta"]
            if row.get("signature"):
                msg["signature"] = row["signature"]
        return msg
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


# --- Public Key Operations ---


def create_pubkey(
    ns: str,
    identity_id: str,
    public_key: str,
    signing_public_key: str,
    algorithm: str = "nacl-box",
) -> dict:
    """
    Create a new public key for an identity.

    Automatically increments version and revokes any existing key.

    Args:
        ns: Namespace
        identity_id: Identity ID
        public_key: Base64-encoded X25519 public key
        signing_public_key: Base64-encoded Ed25519 public key
        algorithm: Encryption algorithm (default: nacl-box)

    Returns:
        Dict with pubkey_id, version, and other metadata
    """
    from .crypto import pubkey_id as compute_pubkey_id, base64url_to_bytes

    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    # Compute pubkey_id from the public key
    pk_bytes = base64url_to_bytes(public_key)
    pubkey_id = compute_pubkey_id(pk_bytes)

    # Get next version number
    cursor = conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM pubkeys WHERE ns = ? AND identity_id = ?",
        (ns, identity_id),
    )
    current_max = cursor.fetchone()[0]
    new_version = current_max + 1

    # Revoke any existing active keys
    conn.execute(
        "UPDATE pubkeys SET revoked_at = ? WHERE ns = ? AND identity_id = ? AND revoked_at IS NULL",
        (now, ns, identity_id),
    )

    # Insert new key
    conn.execute(
        """INSERT INTO pubkeys 
           (pubkey_id, ns, identity_id, public_key, signing_public_key, algorithm, version, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (pubkey_id, ns, identity_id, public_key, signing_public_key, algorithm, new_version, now),
    )

    # Update identity's current_pubkey_id
    conn.execute(
        "UPDATE identities SET current_pubkey_id = ? WHERE ns = ? AND id = ?",
        (pubkey_id, ns, identity_id),
    )

    conn.commit()

    return {
        "pubkey_id": pubkey_id,
        "ns": ns,
        "identity_id": identity_id,
        "public_key": public_key,
        "signing_public_key": signing_public_key,
        "algorithm": algorithm,
        "version": new_version,
        "created_at": now,
        "revoked_at": None,
    }


def get_pubkey(pubkey_id: str) -> dict | None:
    """Get a public key by its ID."""
    conn = get_connection()
    cursor = conn.execute(
        """SELECT pubkey_id, ns, identity_id, public_key, signing_public_key, 
                  algorithm, version, created_at, revoked_at
           FROM pubkeys WHERE pubkey_id = ?""",
        (pubkey_id,),
    )
    return _row_to_dict(cursor.description, cursor.fetchone())


def get_current_pubkey(ns: str, identity_id: str) -> dict | None:
    """Get the current (active) public key for an identity."""
    conn = get_connection()
    cursor = conn.execute(
        """SELECT pubkey_id, ns, identity_id, public_key, signing_public_key,
                  algorithm, version, created_at, revoked_at
           FROM pubkeys 
           WHERE ns = ? AND identity_id = ? AND revoked_at IS NULL
           ORDER BY version DESC LIMIT 1""",
        (ns, identity_id),
    )
    return _row_to_dict(cursor.description, cursor.fetchone())


def get_pubkey_history(ns: str, identity_id: str) -> list[dict]:
    """Get all public keys for an identity (for key rotation history)."""
    conn = get_connection()
    cursor = conn.execute(
        """SELECT pubkey_id, ns, identity_id, public_key, signing_public_key,
                  algorithm, version, created_at, revoked_at
           FROM pubkeys 
           WHERE ns = ? AND identity_id = ?
           ORDER BY version DESC""",
        (ns, identity_id),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def revoke_pubkey(pubkey_id: str) -> bool:
    """Revoke a public key (without setting a new one)."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE pubkeys SET revoked_at = ? WHERE pubkey_id = ? AND revoked_at IS NULL",
        (now, pubkey_id),
    )

    if cursor.rowcount > 0:
        # Clear current_pubkey_id on identity if this was the current key
        conn.execute(
            """UPDATE identities SET current_pubkey_id = NULL 
               WHERE current_pubkey_id = ?""",
            (pubkey_id,),
        )
        conn.commit()
        return True
    return False


# =============================================================================
# Room Epoch Management (for E2E encryption)
# =============================================================================


def create_room_epoch(
    room_id: str,
    epoch_number: int,
    membership_hash: str,
    reason: str,
    triggered_by: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Create a new room epoch record.

    Args:
        room_id: Room ID
        epoch_number: Sequential epoch number (0, 1, 2, ...)
        membership_hash: SHA256 hash of sorted member IDs
        reason: Why this epoch was created ('created', 'member_joined', 'member_left', 'manual')
        triggered_by: Identity ID that triggered this epoch (optional)
        conn: Optional database connection

    Returns:
        Dict with epoch info
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()
    epoch_id = str(make_uuid7())

    conn.execute(
        """INSERT INTO room_epochs 
           (epoch_id, room_id, epoch_number, membership_hash, reason, triggered_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (epoch_id, room_id, epoch_number, membership_hash, reason, triggered_by, now),
    )
    conn.commit()

    return {
        "epoch_id": epoch_id,
        "room_id": room_id,
        "epoch_number": epoch_number,
        "membership_hash": membership_hash,
        "reason": reason,
        "triggered_by": triggered_by,
        "created_at": now,
    }


def get_current_epoch(room_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get the current (highest numbered) epoch for a room.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Dict with epoch info or None if room has no epochs
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT epoch_id, room_id, epoch_number, membership_hash, reason, triggered_by, created_at
           FROM room_epochs 
           WHERE room_id = ?
           ORDER BY epoch_number DESC LIMIT 1""",
        (room_id,),
    )
    return _row_to_dict(cursor.description, cursor.fetchone())


def get_epoch_by_number(
    room_id: str, epoch_number: int, conn: sqlite3.Connection | None = None
) -> dict | None:
    """Get a specific epoch by room and epoch number.

    Args:
        room_id: Room ID
        epoch_number: The epoch number to fetch
        conn: Optional database connection

    Returns:
        Dict with epoch info or None if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT epoch_id, room_id, epoch_number, membership_hash, reason, triggered_by, created_at
           FROM room_epochs 
           WHERE room_id = ? AND epoch_number = ?""",
        (room_id, epoch_number),
    )
    return _row_to_dict(cursor.description, cursor.fetchone())


def store_epoch_key(
    epoch_id: str,
    identity_id: str,
    encrypted_epoch_key: str,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Store an encrypted epoch key for a room member.

    Args:
        epoch_id: The epoch this key belongs to
        identity_id: The member who can decrypt this key
        encrypted_epoch_key: Base64-encoded encrypted key
        conn: Optional database connection

    Returns:
        Dict with stored key info
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO room_epoch_keys (epoch_id, identity_id, encrypted_epoch_key, created_at)
           VALUES (?, ?, ?, ?)""",
        (epoch_id, identity_id, encrypted_epoch_key, now),
    )
    conn.commit()

    return {
        "epoch_id": epoch_id,
        "identity_id": identity_id,
        "encrypted_epoch_key": encrypted_epoch_key,
        "created_at": now,
    }


def get_epoch_key_for_identity(
    room_id: str, epoch_number: int, identity_id: str, conn: sqlite3.Connection | None = None
) -> dict | None:
    """Get the encrypted epoch key for a specific member.

    Args:
        room_id: Room ID
        epoch_number: The epoch number
        identity_id: The member's identity ID
        conn: Optional database connection

    Returns:
        Dict with epoch_id, identity_id, encrypted_epoch_key, created_at or None
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT ek.epoch_id, ek.identity_id, ek.encrypted_epoch_key, ek.created_at
           FROM room_epoch_keys ek
           JOIN room_epochs e ON ek.epoch_id = e.epoch_id
           WHERE e.room_id = ? AND e.epoch_number = ? AND ek.identity_id = ?""",
        (room_id, epoch_number, identity_id),
    )
    return _row_to_dict(cursor.description, cursor.fetchone())


def list_epoch_keys(epoch_id: str, conn: sqlite3.Connection | None = None) -> list[dict]:
    """List all encrypted keys for an epoch.

    Args:
        epoch_id: The epoch ID
        conn: Optional database connection

    Returns:
        List of dicts with epoch_id, identity_id, encrypted_epoch_key, created_at
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT epoch_id, identity_id, encrypted_epoch_key, created_at
           FROM room_epoch_keys
           WHERE epoch_id = ?
           ORDER BY created_at""",
        (epoch_id,),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def get_room_with_encryption(room_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Get room info including encryption status.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Dict with room_id, ns, display_name, created_by, created_at,
        encryption_enabled, current_epoch_number, base_secret,
        server_private_key, server_public_key, secret_version,
        pending_removal_id, pending_removal_at, or None if not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT room_id, ns, display_name, created_by, created_at,
                  encryption_enabled, current_epoch_number, base_secret,
                  server_private_key, server_public_key, secret_version,
                  pending_removal_id, pending_removal_at
           FROM rooms WHERE room_id = ?""",
        (room_id,),
    )
    return _row_to_dict(cursor.description, cursor.fetchone())


def update_room_epoch_number(
    room_id: str, epoch_number: int, conn: sqlite3.Connection | None = None
) -> bool:
    """Update the current epoch number for a room.

    Args:
        room_id: Room ID
        epoch_number: New epoch number
        conn: Optional database connection

    Returns:
        True if updated, False if room not found
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "UPDATE rooms SET current_epoch_number = ? WHERE room_id = ?",
        (epoch_number, room_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def list_room_epochs(
    room_id: str, limit: int | None = None, conn: sqlite3.Connection | None = None
) -> list[dict]:
    """List epochs for a room (most recent first).

    Args:
        room_id: Room ID
        limit: Maximum number of epochs to return
        conn: Optional database connection

    Returns:
        List of epoch dicts
    """
    conn = _get_conn(conn)
    query = """SELECT epoch_id, room_id, epoch_number, membership_hash, reason, triggered_by, created_at
               FROM room_epochs 
               WHERE room_id = ?
               ORDER BY epoch_number DESC"""
    params: list = [room_id]

    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    cursor = conn.execute(query, params)
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def get_room_members_with_pubkeys(
    room_id: str, conn: sqlite3.Connection | None = None
) -> list[dict]:
    """Get all room members along with their current pubkeys.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        List of dicts with identity_id, ns, public_key, signing_public_key.
        Members without pubkeys will have None for the key fields.
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        """SELECT rm.identity_id, rm.ns,
                  p.public_key, p.signing_public_key
           FROM room_members rm
           LEFT JOIN identities i ON rm.ns = i.ns AND rm.identity_id = i.id
           LEFT JOIN pubkeys p ON p.pubkey_id = i.current_pubkey_id
           WHERE rm.room_id = ?""",
        (room_id,),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def rotate_room_epoch(
    room_id: str,
    reason: str,
    triggered_by: str | None = None,
    server_keypair: tuple[bytes, bytes] | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Rotate the room's encryption epoch.

    This function:
    1. Gets current members with their pubkeys
    2. Computes new membership hash
    3. Derives new epoch key from previous key (or base secret for epoch 0)
    4. Creates epoch record
    5. Encrypts epoch key for each member (using stored server keypair)
    6. Updates room's current_epoch_number

    Args:
        room_id: Room ID
        reason: Why rotation is happening ('created', 'member_joined', 'member_left', 'manual')
        triggered_by: Identity ID that triggered this rotation (optional)
        server_keypair: (private_key, public_key) bytes for encrypting keys to members.
                       If None, uses the keypair stored in the room (from initialization).
                       Falls back to testing mode (unencrypted) if neither is available.
        conn: Optional database connection

    Returns:
        Dict with epoch info, list of member keys, and server_public_key

    Raises:
        ValueError: If room doesn't exist or encryption not enabled
        ValueError: If any member lacks a pubkey (when encryption is required)
    """
    from deadrop.crypto import (
        compute_membership_hash,
        derive_epoch_key,
        encrypt_epoch_key_for_member,
        bytes_to_base64url,
        base64url_to_bytes,
    )

    conn = _get_conn(conn)

    # Get room info
    room = get_room_with_encryption(room_id, conn)
    if room is None:
        raise ValueError(f"Room {room_id} not found")
    if not room["encryption_enabled"]:
        raise ValueError(f"Room {room_id} does not have encryption enabled")

    # Use provided server_keypair, or fall back to stored keypair
    if server_keypair is None and room.get("server_private_key") and room.get("server_public_key"):
        server_keypair = (
            base64url_to_bytes(room["server_private_key"]),
            base64url_to_bytes(room["server_public_key"]),
        )

    # Get members with their pubkeys
    members = get_room_members_with_pubkeys(room_id, conn)
    if not members:
        raise ValueError(f"Room {room_id} has no members")

    # Check all members have pubkeys (if we need to encrypt)
    if server_keypair is not None:
        for member in members:
            if member["public_key"] is None:
                raise ValueError(
                    f"Member {member['identity_id']} does not have a registered pubkey"
                )

    # Compute membership hash
    member_ids = [m["identity_id"] for m in members]
    membership_hash = compute_membership_hash(member_ids)

    # Determine new epoch number
    current_epoch_number = room["current_epoch_number"]
    new_epoch_number = current_epoch_number + 1

    # Derive the new epoch key
    # For epoch 1+, we need the previous epoch's key
    # But we don't store raw keys - only encrypted versions
    # So we need to re-derive from base_secret
    if room["base_secret"] is None:
        raise ValueError(f"Room {room_id} has no base_secret set")

    base_secret = base64url_to_bytes(room["base_secret"])

    # Derive keys from base_secret through the chain
    # epoch 0 -> epoch 1 -> ... -> epoch N
    epoch_key = base_secret
    for i in range(new_epoch_number + 1):
        # Get the membership hash for epoch i
        if i < new_epoch_number:
            old_epoch = get_epoch_by_number(room_id, i, conn)
            if old_epoch is None:
                raise ValueError(f"Missing epoch {i} for room {room_id}")
            old_membership_hash = old_epoch["membership_hash"]
        else:
            old_membership_hash = membership_hash

        epoch_key = derive_epoch_key(epoch_key, i, room_id, old_membership_hash)

    # Create epoch record
    epoch = create_room_epoch(
        room_id=room_id,
        epoch_number=new_epoch_number,
        membership_hash=membership_hash,
        reason=reason,
        triggered_by=triggered_by,
        conn=conn,
    )

    # Encrypt and store keys for each member
    member_keys = []
    for member in members:
        if server_keypair is not None and member["public_key"] is not None:
            member_pubkey = base64url_to_bytes(member["public_key"])
            encrypted_key = encrypt_epoch_key_for_member(
                epoch_key, member_pubkey, server_keypair[0]
            )
            encrypted_key_b64 = bytes_to_base64url(encrypted_key)
        else:
            # Testing mode or member lacks pubkey
            encrypted_key_b64 = bytes_to_base64url(epoch_key)  # Store raw for testing

        key_record = store_epoch_key(
            epoch_id=epoch["epoch_id"],
            identity_id=member["identity_id"],
            encrypted_epoch_key=encrypted_key_b64,
            conn=conn,
        )
        member_keys.append(key_record)

    # Update room's current epoch number
    update_room_epoch_number(room_id, new_epoch_number, conn)

    # Get server public key for response
    server_public_key_b64 = room.get("server_public_key")

    return {
        "epoch": epoch,
        "member_keys": member_keys,
        "membership_hash": membership_hash,
        "server_public_key": server_public_key_b64,
    }


def initialize_room_encryption(
    room_id: str,
    base_secret: bytes,
    triggered_by: str | None = None,
    server_keypair: tuple[bytes, bytes] | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Initialize encryption for a room (create epoch 0).

    This sets up the base secret, server keypair, and creates the first epoch.
    Should be called when creating an encrypted room.

    Args:
        room_id: Room ID
        base_secret: 32-byte base secret for key derivation
        triggered_by: Identity ID that created the room
        server_keypair: (private_key, public_key) for encrypting keys.
                       This keypair is stored and used for all future rotations.
        conn: Optional database connection

    Returns:
        Dict with epoch info, member keys, and server_public_key

    Raises:
        ValueError: If room doesn't exist
    """
    from deadrop.crypto import (
        compute_membership_hash,
        derive_epoch_key,
        encrypt_epoch_key_for_member,
        bytes_to_base64url,
        base64url_to_bytes,
    )

    conn = _get_conn(conn)

    # Set encryption_enabled, base_secret, and server keypair on room
    base_secret_b64 = bytes_to_base64url(base_secret)
    server_private_key_b64 = None
    server_public_key_b64 = None
    if server_keypair is not None:
        server_private_key_b64 = bytes_to_base64url(server_keypair[0])
        server_public_key_b64 = bytes_to_base64url(server_keypair[1])

    cursor = conn.execute(
        """UPDATE rooms SET encryption_enabled = 1, base_secret = ?, 
           current_epoch_number = 0, server_private_key = ?, server_public_key = ?
           WHERE room_id = ?""",
        (base_secret_b64, server_private_key_b64, server_public_key_b64, room_id),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"Room {room_id} not found")
    conn.commit()

    # Get members with their pubkeys
    members = get_room_members_with_pubkeys(room_id, conn)

    # Check all members have pubkeys (if we need to encrypt)
    if server_keypair is not None:
        for member in members:
            if member["public_key"] is None:
                raise ValueError(
                    f"Member {member['identity_id']} does not have a registered pubkey"
                )

    # Compute membership hash
    member_ids = [m["identity_id"] for m in members]
    membership_hash = compute_membership_hash(member_ids)

    # Derive epoch 0 key
    epoch_key = derive_epoch_key(base_secret, 0, room_id, membership_hash)

    # Create epoch 0 record
    epoch = create_room_epoch(
        room_id=room_id,
        epoch_number=0,
        membership_hash=membership_hash,
        reason="created",
        triggered_by=triggered_by,
        conn=conn,
    )

    # Encrypt and store keys for each member
    member_keys = []
    for member in members:
        if server_keypair is not None and member["public_key"] is not None:
            member_pubkey = base64url_to_bytes(member["public_key"])
            encrypted_key = encrypt_epoch_key_for_member(
                epoch_key, member_pubkey, server_keypair[0]
            )
            encrypted_key_b64 = bytes_to_base64url(encrypted_key)
        else:
            # Testing mode
            encrypted_key_b64 = bytes_to_base64url(epoch_key)

        key_record = store_epoch_key(
            epoch_id=epoch["epoch_id"],
            identity_id=member["identity_id"],
            encrypted_epoch_key=encrypted_key_b64,
            conn=conn,
        )
        member_keys.append(key_record)

    return {
        "epoch": epoch,
        "member_keys": member_keys,
        "membership_hash": membership_hash,
        "server_public_key": server_public_key_b64,
    }


# =============================================================================
# Pending Removal State Management (Two-Phase Exit Protocol)
# =============================================================================


def set_pending_removal(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Set a member as pending removal (two-phase exit protocol).

    In E2E encrypted rooms, member removal requires a remaining member to
    rotate the secret before the removal is finalized. This function marks
    the member as "pending removal" without actually removing them.

    Args:
        room_id: Room ID
        identity_id: Member to mark as pending removal
        conn: Optional database connection

    Returns:
        Dict with room_id, pending_removal_id, pending_removal_at

    Raises:
        ValueError: If room not found or already has pending removal
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    # Check current state
    room = get_room_with_encryption(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    if room.get("pending_removal_id"):
        raise ValueError(
            f"Room already has pending removal: {room['pending_removal_id']}. "
            "Complete or cancel that first."
        )

    # Verify member exists
    if not is_room_member(room_id, identity_id, conn=conn):
        raise ValueError(f"Identity {identity_id} is not a member of room {room_id}")

    cursor = conn.execute(
        "UPDATE rooms SET pending_removal_id = ?, pending_removal_at = ? WHERE room_id = ?",
        (identity_id, now, room_id),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"Room {room_id} not found")
    conn.commit()

    return {
        "room_id": room_id,
        "pending_removal_id": identity_id,
        "pending_removal_at": now,
    }


def clear_pending_removal(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Clear the pending removal state (cancel exit or after finalization).

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        True if cleared, False if no pending removal
    """
    conn = _get_conn(conn)

    cursor = conn.execute(
        "UPDATE rooms SET pending_removal_id = NULL, pending_removal_at = NULL WHERE room_id = ?",
        (room_id,),
    )
    conn.commit()
    return cursor.rowcount > 0


def get_pending_removal(
    room_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get pending removal info for a room.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Dict with pending_removal_id and pending_removal_at, or None if no pending
    """
    conn = _get_conn(conn)

    cursor = conn.execute(
        "SELECT pending_removal_id, pending_removal_at FROM rooms WHERE room_id = ?",
        (room_id,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row and row.get("pending_removal_id"):
        return {
            "pending_removal_id": row["pending_removal_id"],
            "pending_removal_at": row["pending_removal_at"],
        }
    return None


def finalize_pending_removal(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Finalize a pending removal (actually remove the member).

    This should be called after a successful secret rotation that excludes
    the pending member.

    Args:
        room_id: Room ID
        identity_id: Identity to finalize removal for (must match pending)
        conn: Optional database connection

    Returns:
        True if removed, False if not found or mismatch

    Raises:
        ValueError: If identity doesn't match pending removal
    """
    conn = _get_conn(conn)

    # Verify pending removal matches
    pending = get_pending_removal(room_id, conn=conn)
    if not pending:
        raise ValueError(f"Room {room_id} has no pending removal")
    if pending["pending_removal_id"] != identity_id:
        raise ValueError(
            f"Pending removal mismatch: expected {pending['pending_removal_id']}, got {identity_id}"
        )

    # Remove the member (bypass rotation since we just did one)
    cursor = conn.execute(
        "DELETE FROM room_members WHERE room_id = ? AND identity_id = ?",
        (room_id, identity_id),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"Member {identity_id} not found in room {room_id}")

    # Clear pending state
    clear_pending_removal(room_id, conn=conn)

    conn.commit()
    return True


def validate_message_epoch(
    room_id: str,
    epoch_number: int,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Validate that the given epoch matches the room's current epoch.

    Args:
        room_id: Room ID
        epoch_number: Epoch number to validate
        conn: Optional database connection

    Returns:
        True if epoch matches

    Raises:
        ValueError: If room not found
        EpochMismatchError: If epoch doesn't match current room epoch
    """
    conn = _get_conn(conn)

    room = get_room_with_encryption(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")

    current_epoch = room["current_epoch_number"]
    if epoch_number != current_epoch:
        raise EpochMismatchError(
            f"Epoch mismatch: expected {current_epoch}, got {epoch_number}",
            expected_epoch=current_epoch,
            provided_epoch=epoch_number,
            room_id=room_id,
        )

    return True


# =============================================================================
# True E2E Room Encryption (Client-side key management)
# =============================================================================


def store_member_secret(
    room_id: str,
    identity_id: str,
    encrypted_base_secret: str,
    inviter_public_key: str,
    secret_version: int,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Store an encrypted base secret for a room member.

    In true E2E mode, the server stores encrypted secrets that only
    members can decrypt with their private keys.

    Args:
        room_id: Room ID
        identity_id: Member's identity ID
        encrypted_base_secret: Base64-encoded encrypted secret
        inviter_public_key: Base64-encoded public key of inviter (for decryption)
        secret_version: Version of the secret (0 for initial, increments on rotation)
        conn: Optional database connection

    Returns:
        Dict with stored record info
    """
    conn = _get_conn(conn)
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT OR REPLACE INTO room_member_secrets 
           (room_id, identity_id, encrypted_base_secret, inviter_public_key, secret_version, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (room_id, identity_id, encrypted_base_secret, inviter_public_key, secret_version, now),
    )
    conn.commit()

    return {
        "room_id": room_id,
        "identity_id": identity_id,
        "encrypted_base_secret": encrypted_base_secret,
        "inviter_public_key": inviter_public_key,
        "secret_version": secret_version,
        "created_at": now,
    }


def get_member_secret(
    room_id: str,
    identity_id: str,
    secret_version: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict | None:
    """Get an encrypted base secret for a room member.

    Args:
        room_id: Room ID
        identity_id: Member's identity ID
        secret_version: Specific version to fetch, or None for latest
        conn: Optional database connection

    Returns:
        Dict with encrypted_base_secret, inviter_public_key, secret_version, or None
    """
    conn = _get_conn(conn)

    if secret_version is not None:
        cursor = conn.execute(
            """SELECT room_id, identity_id, encrypted_base_secret, inviter_public_key, 
                      secret_version, created_at
               FROM room_member_secrets
               WHERE room_id = ? AND identity_id = ? AND secret_version = ?""",
            (room_id, identity_id, secret_version),
        )
    else:
        # Get latest version
        cursor = conn.execute(
            """SELECT room_id, identity_id, encrypted_base_secret, inviter_public_key,
                      secret_version, created_at
               FROM room_member_secrets
               WHERE room_id = ? AND identity_id = ?
               ORDER BY secret_version DESC LIMIT 1""",
            (room_id, identity_id),
        )

    return _row_to_dict(cursor.description, cursor.fetchone())


def list_member_secrets(
    room_id: str,
    identity_id: str,
    conn: sqlite3.Connection | None = None,
) -> list[dict]:
    """List all secret versions for a member (for catching up after being offline).

    Args:
        room_id: Room ID
        identity_id: Member's identity ID
        conn: Optional database connection

    Returns:
        List of dicts with encrypted secrets, ordered by version ascending
    """
    conn = _get_conn(conn)

    cursor = conn.execute(
        """SELECT room_id, identity_id, encrypted_base_secret, inviter_public_key,
                  secret_version, created_at
           FROM room_member_secrets
           WHERE room_id = ? AND identity_id = ?
           ORDER BY secret_version ASC""",
        (room_id, identity_id),
    )

    return _rows_to_dicts(cursor.description, cursor.fetchall())


def get_current_secret_version(room_id: str, conn: sqlite3.Connection | None = None) -> int:
    """Get the current secret version for a room.

    Args:
        room_id: Room ID
        conn: Optional database connection

    Returns:
        Current secret version number (0 if not set)
    """
    conn = _get_conn(conn)
    cursor = conn.execute(
        "SELECT secret_version FROM rooms WHERE room_id = ?",
        (room_id,),
    )
    row = cursor.fetchone()
    return row[0] if row and row[0] is not None else 0


def update_secret_version(
    room_id: str,
    secret_version: int,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update the current secret version for a room.

    Args:
        room_id: Room ID
        secret_version: New secret version
        conn: Optional database connection

    Returns:
        True if updated, False if room not found
    """
    conn = _get_conn(conn)
    # Update both secret_version and current_epoch_number to keep them in sync
    cursor = conn.execute(
        "UPDATE rooms SET secret_version = ?, current_epoch_number = ? WHERE room_id = ?",
        (secret_version, secret_version, room_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def initialize_room_encryption_e2e(
    room_id: str,
    creator_id: str,
    encrypted_base_secret: str,
    creator_public_key: str,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Initialize encryption for a room in true E2E mode.

    The server only stores encrypted secrets - it never sees the plaintext.

    Args:
        room_id: Room ID
        creator_id: Creator's identity ID
        encrypted_base_secret: Base64-encoded encrypted secret for creator
        creator_public_key: Base64-encoded public key (creator is own inviter)
        conn: Optional database connection

    Returns:
        Dict with initialization info

    Raises:
        ValueError: If room doesn't exist
    """
    conn = _get_conn(conn)

    # Enable encryption on room (without storing plaintext secret)
    cursor = conn.execute(
        """UPDATE rooms SET encryption_enabled = 1, secret_version = 0, 
           current_epoch_number = 0, base_secret = NULL
           WHERE room_id = ?""",
        (room_id,),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"Room {room_id} not found")
    conn.commit()

    # Store creator's encrypted secret
    store_member_secret(
        room_id=room_id,
        identity_id=creator_id,
        encrypted_base_secret=encrypted_base_secret,
        inviter_public_key=creator_public_key,
        secret_version=0,
        conn=conn,
    )

    return {
        "room_id": room_id,
        "encryption_enabled": True,
        "secret_version": 0,
        "current_epoch_number": 0,
    }


def rotate_room_secret_e2e(
    room_id: str,
    new_secret_version: int,
    member_secrets: list[dict],
    triggered_by: str | None = None,
    finalize_removal: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Rotate the room's base secret in true E2E mode.

    The caller provides pre-encrypted secrets for each remaining member.
    The server validates and stores them without seeing plaintext.

    If finalize_removal is provided, this completes a two-phase exit by:
    1. Validating the pending removal matches
    2. Storing new secrets for remaining members (excluding removed member)
    3. Finalizing the removal (actually deleting membership)

    Args:
        room_id: Room ID
        new_secret_version: New version number (must be current + 1)
        member_secrets: List of dicts with identity_id, encrypted_base_secret, inviter_public_key
        triggered_by: Identity ID that triggered rotation (optional)
        finalize_removal: Identity ID to finalize removal for (completes two-phase exit)
        conn: Optional database connection

    Returns:
        Dict with rotation info, including removed_member if finalize_removal was used

    Raises:
        ValueError: If room not found, version mismatch, missing members, or removal mismatch
    """
    conn = _get_conn(conn)

    # Verify room exists and get current version
    room = get_room_with_encryption(room_id, conn=conn)
    if not room:
        raise ValueError(f"Room {room_id} not found")
    if not room["encryption_enabled"]:
        raise ValueError(f"Room {room_id} does not have encryption enabled")

    current_version = room.get("secret_version", 0) or 0
    if new_secret_version != current_version + 1:
        raise ValueError(
            f"Invalid secret version: expected {current_version + 1}, got {new_secret_version}"
        )

    # If finalizing removal, validate pending removal matches
    if finalize_removal:
        pending = get_pending_removal(room_id, conn=conn)
        if not pending:
            raise ValueError(f"No pending removal to finalize for room {room_id}")
        if pending["pending_removal_id"] != finalize_removal:
            raise ValueError(
                f"Pending removal mismatch: expected {pending['pending_removal_id']}, "
                f"got {finalize_removal}"
            )

    # Verify all current members are included (excluding pending removal if applicable)
    members = list_room_members(room_id, conn=conn)
    member_ids = {m["identity_id"] for m in members}

    # If finalizing removal, the removed member should NOT be in member_secrets
    if finalize_removal:
        member_ids.discard(finalize_removal)

    provided_ids = {s["identity_id"] for s in member_secrets}

    if member_ids != provided_ids:
        missing = member_ids - provided_ids
        extra = provided_ids - member_ids
        raise ValueError(f"Member mismatch: missing={missing}, extra={extra}")

    # Store new secrets for each member
    for secret in member_secrets:
        store_member_secret(
            room_id=room_id,
            identity_id=secret["identity_id"],
            encrypted_base_secret=secret["encrypted_base_secret"],
            inviter_public_key=secret["inviter_public_key"],
            secret_version=new_secret_version,
            conn=conn,
        )

    # Update room's secret version
    update_secret_version(room_id, new_secret_version, conn=conn)

    result = {
        "room_id": room_id,
        "secret_version": new_secret_version,
        "member_count": len(member_secrets),
        "triggered_by": triggered_by,
    }

    # Finalize pending removal if specified
    if finalize_removal:
        finalize_pending_removal(room_id, finalize_removal, conn=conn)
        result["removed_member"] = finalize_removal

    return result
