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
SCHEMA_VERSION = 1

# Global connection singleton (for backward compatibility)
_conn: sqlite3.Connection | None = None
_is_libsql: bool = False


# --- Connection Management ---


def get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Get or create database connection.

    Args:
        db_path: Optional explicit database path. If None, uses global singleton.
                 Special value ":memory:" creates an in-memory database.

    Returns:
        SQLite connection with row_factory set to sqlite3.Row.
    """
    global _conn, _is_libsql

    # If explicit path provided, create a new connection (not singleton)
    if db_path is not None:
        if str(db_path) == ":memory:":
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # Global singleton behavior (backward compatible)
    if _conn is None:
        db_url = os.environ.get("TURSO_URL", "")

        if db_url.startswith("libsql://"):
            # Turso connection (optional dependency)
            import libsql_experimental as libsql  # type: ignore[import-not-found]

            _conn = libsql.connect(db_url, auth_token=os.environ.get("TURSO_AUTH_TOKEN", ""))
            _is_libsql = True
        else:
            # Local SQLite
            db_path_env = os.environ.get("DEADROP_DB", "deadrop.db")
            _conn = sqlite3.connect(db_path_env, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _is_libsql = False

    return _conn


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
    """Close the global database connection."""
    global _conn, _is_libsql
    if _conn:
        _conn.close()
        _conn = None
        _is_libsql = False


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


# Migration registry: (version, description, migration_function)
MIGRATIONS: list[tuple[int, str, Callable[[sqlite3.Connection], None]]] = [
    (1, "Add content_type column to messages", _migrate_001_add_content_type),
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
