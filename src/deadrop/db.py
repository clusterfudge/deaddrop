"""Database layer for deadrop - supports SQLite and Turso."""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from uuid_extensions import uuid7 as make_uuid7

from .auth import derive_id, generate_secret, hash_secret

# Default TTL in hours when messages are read
DEFAULT_TTL_HOURS = 24

# Connection singleton
_conn: sqlite3.Connection | None = None
_is_libsql: bool = False


def get_connection() -> sqlite3.Connection:
    """Get or create database connection."""
    global _conn, _is_libsql
    if _conn is None:
        db_url = os.environ.get("TURSO_URL", "")

        if db_url.startswith("libsql://"):
            # Turso connection
            import libsql_experimental as libsql  # type: ignore[import-not-found]

            _conn = libsql.connect(db_url, auth_token=os.environ.get("TURSO_AUTH_TOKEN", ""))
            _is_libsql = True
        else:
            # Local SQLite
            db_path = os.environ.get("DEADROP_DB", "deadrop.db")
            _conn = sqlite3.connect(db_path, check_same_thread=False)
            _conn.row_factory = sqlite3.Row
            _is_libsql = False

    return _conn


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


def close_db():
    """Close database connection."""
    global _conn, _is_libsql
    if _conn:
        _conn.close()
        _conn = None
        _is_libsql = False


def init_db():
    """Initialize database schema."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS namespaces (
            ns TEXT PRIMARY KEY,
            secret_hash TEXT NOT NULL,
            metadata JSON DEFAULT '{}',
            ttl_hours INTEGER DEFAULT 24,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            archived_at TIMESTAMP
        );
        
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (ns, to_id) REFERENCES identities(ns, id) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_messages_inbox 
            ON messages(ns, to_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_expires 
            ON messages(expires_at) WHERE expires_at IS NOT NULL;
        
        CREATE TABLE IF NOT EXISTS archive_batches (
            batch_id TEXT PRIMARY KEY,
            ns TEXT NOT NULL,
            archive_path TEXT NOT NULL,
            message_count INTEGER NOT NULL,
            min_created_at TIMESTAMP,
            max_created_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()


def reset_db():
    """Reset database (for testing)."""
    conn = get_connection()
    conn.executescript("""
        DROP TABLE IF EXISTS archive_batches;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS identities;
        DROP TABLE IF EXISTS namespaces;
    """)
    conn.commit()
    init_db()


# --- Namespace Operations ---


def create_namespace(
    metadata: dict[str, Any] | None = None, ttl_hours: int = DEFAULT_TTL_HOURS
) -> dict[str, str]:
    """Create a new namespace. Returns {ns, secret}."""
    secret = generate_secret()
    ns = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    conn = get_connection()
    conn.execute(
        "INSERT INTO namespaces (ns, secret_hash, metadata, ttl_hours) VALUES (?, ?, ?, ?)",
        (ns, secret_hash, metadata_json, ttl_hours),
    )
    conn.commit()

    return {"ns": ns, "secret": secret}


def get_namespace(ns: str) -> dict | None:
    """Get namespace by ID."""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT ns, metadata, ttl_hours, created_at, archived_at FROM namespaces WHERE ns = ?",
        (ns,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        return {
            "ns": row["ns"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
    return None


def is_namespace_archived(ns: str) -> bool:
    """Check if namespace is archived (read-only)."""
    conn = get_connection()
    cursor = conn.execute("SELECT archived_at FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row is not None and row["archived_at"] is not None


def archive_namespace(ns: str) -> bool:
    """Archive a namespace (soft-delete, rejects future writes)."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE namespaces SET archived_at = ? WHERE ns = ? AND archived_at IS NULL", (now, ns)
    )
    conn.commit()
    return cursor.rowcount > 0


def get_namespace_ttl_hours(ns: str) -> int:
    """Get the TTL hours for a namespace."""
    conn = get_connection()
    cursor = conn.execute("SELECT ttl_hours FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row["ttl_hours"] if row else DEFAULT_TTL_HOURS


def list_namespaces() -> list[dict]:
    """List all namespaces."""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT ns, metadata, ttl_hours, created_at, archived_at FROM namespaces ORDER BY created_at"
    )
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    return [
        {
            "ns": row["ns"],
            "metadata": json.loads(row["metadata"] or "{}"),
            "ttl_hours": row["ttl_hours"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
        }
        for row in rows
    ]


def verify_namespace_secret(ns: str, secret: str) -> bool:
    """Verify a namespace secret."""
    # First check: does the secret derive to this ns ID?
    if derive_id(secret) != ns:
        return False

    # Second check: does the hash match what's stored?
    conn = get_connection()
    cursor = conn.execute("SELECT secret_hash FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return False

    from .auth import verify_secret

    return verify_secret(secret, row["secret_hash"])


def delete_namespace(ns: str) -> bool:
    """Delete a namespace and all its data."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM namespaces WHERE ns = ?", (ns,))
    conn.commit()
    return cursor.rowcount > 0


def update_namespace_metadata(ns: str, metadata: dict[str, Any]) -> bool:
    """Update namespace metadata."""
    conn = get_connection()
    cursor = conn.execute(
        "UPDATE namespaces SET metadata = ? WHERE ns = ?", (json.dumps(metadata), ns)
    )
    conn.commit()
    return cursor.rowcount > 0


# --- Identity Operations ---


def create_identity(ns: str, metadata: dict[str, Any] | None = None) -> dict[str, str]:
    """Create a new identity in a namespace. Returns {id, secret}."""
    secret = generate_secret()
    identity_id = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    conn = get_connection()
    conn.execute(
        "INSERT INTO identities (id, ns, secret_hash, metadata) VALUES (?, ?, ?, ?)",
        (identity_id, ns, secret_hash, metadata_json),
    )
    conn.commit()

    return {"id": identity_id, "secret": secret}


def get_identity(ns: str, identity_id: str) -> dict | None:
    """Get identity by ID."""
    conn = get_connection()
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


def list_identities(ns: str) -> list[dict]:
    """List all identities in a namespace."""
    conn = get_connection()
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


def verify_identity_secret(ns: str, identity_id: str, secret: str) -> bool:
    """Verify an identity secret."""
    # First check: does the secret derive to this identity ID?
    if derive_id(secret) != identity_id:
        return False

    # Second check: does the hash match what's stored?
    conn = get_connection()
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?", (ns, identity_id)
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return False

    from .auth import verify_secret

    return verify_secret(secret, row["secret_hash"])


def verify_identity_in_namespace(ns: str, secret: str) -> str | None:
    """Verify a secret belongs to some identity in the namespace. Returns identity ID or None."""
    identity_id = derive_id(secret)

    conn = get_connection()
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


def delete_identity(ns: str, identity_id: str) -> bool:
    """Delete an identity and all its messages."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM identities WHERE ns = ? AND id = ?", (ns, identity_id))
    conn.commit()
    return cursor.rowcount > 0


def update_identity_metadata(ns: str, identity_id: str, metadata: dict[str, Any]) -> bool:
    """Update identity metadata."""
    conn = get_connection()
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
    ttl_hours: int | None = None,
) -> dict:
    """Send a message. Returns message info.

    Args:
        ns: Namespace
        from_id: Sender identity
        to_id: Recipient identity
        body: Message body
        ttl_hours: Optional TTL override (for ephemeral messages that expire from creation)
    """
    # Verify recipient exists
    conn = get_connection()
    cursor = conn.execute(
        "SELECT id FROM identities WHERE ns = ? AND id = ?", (ns, to_id)
    )
    row = cursor.fetchone()

    if not row:
        raise ValueError(f"Recipient {to_id} not found in namespace {ns}")

    mid = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    # If sender specifies TTL, message expires from creation (ephemeral)
    expires_at = None
    if ttl_hours is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

    conn.execute(
        """INSERT INTO messages (mid, ns, to_id, from_id, body, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (mid, ns, to_id, from_id, body, now, expires_at),
    )
    conn.commit()

    return {"mid": mid, "from": from_id, "to": to_id, "created_at": now}


def get_messages(
    ns: str,
    identity_id: str,
    unread_only: bool = False,
    after_mid: str | None = None,
    mark_as_read: bool = True,
) -> list[dict]:
    """Get messages for an identity, optionally marking unread messages as read.

    Args:
        ns: Namespace
        identity_id: Identity to fetch messages for
        unread_only: Only return unread messages
        after_mid: Only return messages after this message ID (cursor)
        mark_as_read: If True (default), marks unread messages as read and starts TTL

    Returns:
        List of messages, sorted by created_at
    """
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    # Get namespace TTL for setting expiration on read
    ttl_hours = get_namespace_ttl_hours(ns)

    # Build query
    query = """
        SELECT mid, from_id, to_id, body, created_at, read_at, expires_at
        FROM messages 
        WHERE ns = ? AND to_id = ?
        AND (expires_at IS NULL OR expires_at > ?)
    """
    params: list[Any] = [ns, identity_id, now]

    if unread_only:
        query += " AND read_at IS NULL"

    if after_mid:
        # UUIDv7 is timestamp-ordered, so we can use string comparison
        query += " AND mid > ?"
        params.append(after_mid)

    query += " ORDER BY mid"  # UUIDv7 ordering = chronological

    cursor = conn.execute(query, tuple(params))
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    messages = [
        {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
        }
        for row in rows
    ]

    # Mark unread messages as read and set expiration (if requested)
    if mark_as_read:
        unread_mids = [m["mid"] for m in messages if m["read_at"] is None]
        if unread_mids:
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
            placeholders = ",".join("?" * len(unread_mids))
            conn.execute(
                f"UPDATE messages SET read_at = ?, expires_at = ? WHERE mid IN ({placeholders})",
                tuple([now, expires_at] + unread_mids),
            )
            conn.commit()

            # Update return values
            for m in messages:
                if m["read_at"] is None:
                    m["read_at"] = now
                    m["expires_at"] = expires_at

    return messages


def get_message(ns: str, identity_id: str, mid: str) -> dict | None:
    """Get a single message."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, body, created_at, read_at, expires_at
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
            "created_at": row["created_at"],
            "read_at": row["read_at"],
            "expires_at": row["expires_at"],
        }
    return None


def delete_message(ns: str, identity_id: str, mid: str) -> bool:
    """Immediately delete a message."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM messages WHERE ns = ? AND to_id = ? AND mid = ?", (ns, identity_id, mid)
    )
    conn.commit()
    return cursor.rowcount > 0


# --- TTL and Archive Operations ---


def get_expired_messages(limit: int = 1000) -> list[dict]:
    """Get messages past their expiration time."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, ns, to_id, from_id, body, created_at, read_at, expires_at
           FROM messages 
           WHERE expires_at IS NOT NULL AND expires_at <= ?
           ORDER BY expires_at
           LIMIT ?""",
        (now, limit),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def delete_expired_messages() -> int:
    """Delete all expired messages. Returns count deleted."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,)
    )
    conn.commit()
    return cursor.rowcount


def mark_messages_archived(mids: list[str], archive_key: str) -> int:
    """Mark messages as archived with a reference key."""
    if not mids:
        return 0

    # For now, we just delete after archiving
    # In the future, could add an archive_key column
    return len(mids)


def create_archive_batch(
    ns: str,
    archive_path: str,
    message_count: int,
    min_created_at: str,
    max_created_at: str,
) -> str:
    """Record an archive batch."""
    batch_id = str(make_uuid7())
    conn = get_connection()
    conn.execute(
        """INSERT INTO archive_batches 
           (batch_id, ns, archive_path, message_count, min_created_at, max_created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (batch_id, ns, archive_path, message_count, min_created_at, max_created_at),
    )
    conn.commit()
    return batch_id


def get_archive_batches(ns: str | None = None) -> list[dict]:
    """Get archive batch records, optionally filtered by namespace."""
    conn = get_connection()

    if ns:
        cursor = conn.execute(
            "SELECT * FROM archive_batches WHERE ns = ? ORDER BY created_at", (ns,)
        )
    else:
        cursor = conn.execute("SELECT * FROM archive_batches ORDER BY created_at")

    return _rows_to_dicts(cursor.description, cursor.fetchall())
