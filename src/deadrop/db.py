"""Database layer for deadrop - supports SQLite and Turso."""

import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from uuid_extensions import uuid7 as make_uuid7

from .auth import derive_id, generate_secret, hash_secret

# Default TTL in hours when messages are read
DEFAULT_TTL_HOURS = 24

# Current schema version
SCHEMA_VERSION = 2

# Connection singleton
_conn: sqlite3.Connection | None = None
_is_libsql: bool = False


def get_connection() -> sqlite3.Connection:
    """Get or create database connection."""
    global _conn, _is_libsql
    if _conn is None:
        db_url = os.environ.get("TURSO_URL", "")

        if db_url.startswith("libsql://"):
            # Turso connection (optional dependency)
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


def _get_schema_version(conn: sqlite3.Connection) -> int:
    """Get current schema version from database."""
    try:
        cursor = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    """Set schema version in database."""
    conn.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)", (version,)
    )
    conn.commit()


def _migrate_v0_to_v1(conn: sqlite3.Connection) -> None:
    """Initial schema (v1)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
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
    """)
    conn.commit()


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """Add e2e encryption support (v2).

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


# Migration registry: version -> migration function
_MIGRATIONS = {
    1: _migrate_v0_to_v1,
    2: _migrate_v1_to_v2,
}


def init_db():
    """Initialize database schema and run any pending migrations."""
    conn = get_connection()

    # Check if this is a fresh database
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    has_schema_table = cursor.fetchone() is not None

    # Get current version (0 if fresh database)
    current_version = _get_schema_version(conn) if has_schema_table else 0

    # Run migrations
    for version in sorted(_MIGRATIONS.keys()):
        if version > current_version:
            _MIGRATIONS[version](conn)
            _set_schema_version(conn, version)

    conn.commit()


def reset_db():
    """Reset database (for testing)."""
    conn = get_connection()
    conn.executescript("""
        DROP TABLE IF EXISTS schema_version;
        DROP TABLE IF EXISTS archive_batches;
        DROP TABLE IF EXISTS pubkeys;
        DROP TABLE IF EXISTS invites;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS identities;
        DROP TABLE IF EXISTS namespaces;
    """)
    conn.commit()
    init_db()


# --- Slug Utilities ---


def slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    if not text:
        return ""
    # Lowercase, replace spaces/underscores with hyphens
    slug = text.lower().strip()
    slug = re.sub(r"[\s_]+", "-", slug)
    # Remove non-alphanumeric chars (except hyphens)
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    # Remove multiple consecutive hyphens
    slug = re.sub(r"-+", "-", slug)
    # Remove leading/trailing hyphens
    slug = slug.strip("-")
    return slug


def make_unique_slug(base_slug: str, exclude_ns: str | None = None) -> str:
    """Generate a unique slug, appending a number if necessary."""
    conn = get_connection()
    slug = base_slug or "namespace"

    # Check if slug exists
    query = "SELECT COUNT(*) FROM namespaces WHERE slug = ?"
    params: list[Any] = [slug]
    if exclude_ns:
        query += " AND ns != ?"
        params.append(exclude_ns)

    cursor = conn.execute(query, tuple(params))
    count = cursor.fetchone()[0]

    if count == 0:
        return slug

    # Append numbers until unique
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
) -> dict[str, str | None]:
    """Create a new namespace. Returns {ns, secret, slug}."""
    secret = generate_secret()
    ns = derive_id(secret)
    secret_hash = hash_secret(secret)
    metadata_json = json.dumps(metadata or {})

    # Generate slug from display_name if not provided
    if not slug and metadata and metadata.get("display_name"):
        slug = slugify(metadata["display_name"])
    if slug:
        slug = make_unique_slug(slug)

    conn = get_connection()
    conn.execute(
        "INSERT INTO namespaces (ns, secret_hash, slug, metadata, ttl_hours) VALUES (?, ?, ?, ?, ?)",
        (ns, secret_hash, slug, metadata_json, ttl_hours),
    )
    conn.commit()

    return {"ns": ns, "secret": secret, "slug": slug}


def get_namespace(ns: str) -> dict | None:
    """Get namespace by ID."""
    conn = get_connection()
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


def get_namespace_by_slug(slug: str) -> dict | None:
    """Get namespace by slug."""
    conn = get_connection()
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


def get_or_create_namespace_slug(ns: str, suggested_slug: str | None = None) -> str | None:
    """Get existing slug or create one for namespace."""
    conn = get_connection()

    # Check if already has slug
    cursor = conn.execute("SELECT slug, metadata FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if not row:
        return None

    if row["slug"]:
        return row["slug"]

    # Generate slug from display_name or use suggested
    metadata = json.loads(row["metadata"] or "{}")
    base_slug = suggested_slug or slugify(metadata.get("display_name", "")) or ns[:8]
    slug = make_unique_slug(base_slug, exclude_ns=ns)

    conn.execute("UPDATE namespaces SET slug = ? WHERE ns = ?", (slug, ns))
    conn.commit()
    return slug


def set_namespace_slug(ns: str, slug: str) -> bool:
    """Set a namespace's slug. Returns False if slug already taken or ns not found."""
    conn = get_connection()

    # Validate slug format
    clean_slug = slugify(slug)
    if not clean_slug:
        return False

    # Check if slug is already taken by another namespace
    cursor = conn.execute("SELECT ns FROM namespaces WHERE slug = ? AND ns != ?", (clean_slug, ns))
    if cursor.fetchone():
        return False

    cursor = conn.execute("UPDATE namespaces SET slug = ? WHERE ns = ?", (clean_slug, ns))
    conn.commit()
    return cursor.rowcount > 0


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
    """Get the TTL hours for a namespace. Returns 0 for persistent namespaces."""
    conn = get_connection()
    cursor = conn.execute("SELECT ttl_hours FROM namespaces WHERE ns = ?", (ns,))
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row["ttl_hours"] if row else DEFAULT_TTL_HOURS


def list_namespaces() -> list[dict]:
    """List all namespaces."""
    conn = get_connection()
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
    """Get identity by ID, including current pubkey info."""
    conn = get_connection()
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


def get_identity_secret_hash(ns: str, identity_id: str) -> str | None:
    """Get the secret hash for an identity (used for invite creation)."""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?", (ns, identity_id)
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row["secret_hash"] if row else None


def list_identities(ns: str) -> list[dict]:
    """List all identities in a namespace, including current pubkey info."""
    conn = get_connection()
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
    encrypted: bool = False,
    encryption_meta: dict | None = None,
    signature: str | None = None,
    signature_meta: dict | None = None,
) -> dict:
    """Send a message. Returns message info.

    Args:
        ns: Namespace
        from_id: Sender identity
        to_id: Recipient identity
        body: Message body (plaintext or base64 ciphertext if encrypted)
        ttl_hours: Optional TTL override (for ephemeral messages that expire from creation)
        encrypted: Whether the body is encrypted
        encryption_meta: Encryption metadata (algorithm, recipient_pubkey_id)
        signature: Base64-encoded signature
        signature_meta: Signature metadata (algorithm, sender_pubkey_id)
    """
    # Verify recipient exists
    conn = get_connection()
    cursor = conn.execute("SELECT id FROM identities WHERE ns = ? AND id = ?", (ns, to_id))
    row = cursor.fetchone()

    if not row:
        raise ValueError(f"Recipient {to_id} not found in namespace {ns}")

    mid = str(make_uuid7())
    now = datetime.now(timezone.utc).isoformat()

    # If sender specifies TTL, message expires from creation (ephemeral)
    expires_at = None
    if ttl_hours is not None and ttl_hours > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

    # Store signature in signature_meta if provided
    if signature and signature_meta:
        signature_meta = {**signature_meta, "value": signature}

    conn.execute(
        """INSERT INTO messages (mid, ns, to_id, from_id, body, created_at, expires_at,
                                 encrypted, encryption_meta, signature_meta)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            mid,
            ns,
            to_id,
            from_id,
            body,
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
        "created_at": now,
        "encrypted": encrypted,
        "encryption_meta": encryption_meta,
        "signature_meta": signature_meta,
    }


def get_messages(
    ns: str,
    identity_id: str,
    unread_only: bool = False,
    after_mid: str | None = None,
    mark_as_read: bool = True,
    include_archived: bool = False,
) -> list[dict]:
    """Get messages for an identity, optionally marking unread messages as read.

    Args:
        ns: Namespace
        identity_id: Identity to fetch messages for
        unread_only: Only return unread messages
        after_mid: Only return messages after this message ID (cursor)
        mark_as_read: If True (default), marks unread messages as read and starts TTL
        include_archived: If True, include archived messages

    Returns:
        List of messages, sorted by created_at
    """
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    # Get namespace TTL for setting expiration on read
    ttl_hours = get_namespace_ttl_hours(ns)

    # Build query
    query = """
        SELECT mid, from_id, to_id, body, created_at, read_at, expires_at, archived_at,
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
        # UUIDv7 is timestamp-ordered, so we can use string comparison
        query += " AND mid > ?"
        params.append(after_mid)

    query += " ORDER BY mid"  # UUIDv7 ordering = chronological

    cursor = conn.execute(query, tuple(params))
    rows = _rows_to_dicts(cursor.description, cursor.fetchall())

    messages = []
    for row in rows:
        msg = {
            "mid": row["mid"],
            "from": row["from_id"],
            "to": row["to_id"],
            "body": row["body"],
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

    # Mark unread messages as read and set expiration (if requested and namespace has TTL)
    if mark_as_read:
        unread_mids = [m["mid"] for m in messages if m["read_at"] is None]
        if unread_mids:
            # Only set expires_at if namespace has TTL (ttl_hours > 0)
            if ttl_hours > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
            else:
                expires_at = None  # Persistent namespace - no expiration

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
        """SELECT mid, from_id, to_id, body, created_at, read_at, expires_at, archived_at,
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


def delete_message(ns: str, identity_id: str, mid: str) -> bool:
    """Immediately delete a message."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM messages WHERE ns = ? AND to_id = ? AND mid = ?", (ns, identity_id, mid)
    )
    conn.commit()
    return cursor.rowcount > 0


def archive_message(ns: str, identity_id: str, mid: str) -> bool:
    """Archive a message (hide from inbox but preserve)."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """UPDATE messages SET archived_at = ?, expires_at = NULL 
           WHERE ns = ? AND to_id = ? AND mid = ? AND archived_at IS NULL""",
        (now, ns, identity_id, mid),
    )
    conn.commit()
    return cursor.rowcount > 0


def unarchive_message(ns: str, identity_id: str, mid: str) -> bool:
    """Unarchive a message (restore to inbox)."""
    conn = get_connection()
    # Note: We don't restore the original expires_at - message becomes permanent
    # unless namespace TTL kicks in on next read
    cursor = conn.execute(
        "UPDATE messages SET archived_at = NULL WHERE ns = ? AND to_id = ? AND mid = ?",
        (ns, identity_id, mid),
    )
    conn.commit()
    return cursor.rowcount > 0


def get_archived_messages(ns: str, identity_id: str) -> list[dict]:
    """Get archived messages for an identity."""
    conn = get_connection()
    cursor = conn.execute(
        """SELECT mid, from_id, to_id, body, created_at, read_at, expires_at, archived_at,
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
) -> dict:
    """Create an invite record."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT INTO invites 
           (invite_id, ns, identity_id, encrypted_secret, display_name, created_by, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            invite_id,
            ns,
            identity_id,
            encrypted_secret,
            display_name,
            created_by,
            now,
            expires_at,
        ),
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


def get_invite(invite_id: str) -> dict | None:
    """Get an invite by ID."""
    conn = get_connection()
    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, encrypted_secret, display_name,
                  created_by, created_at, expires_at, claimed_at, claimed_by
           FROM invites WHERE invite_id = ?""",
        (invite_id,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())
    return row


def get_invite_info(invite_id: str) -> dict | None:
    """Get public invite info (without secrets)."""
    conn = get_connection()
    cursor = conn.execute(
        """SELECT invite_id, ns, identity_id, display_name, created_at, expires_at, claimed_at
           FROM invites WHERE invite_id = ?""",
        (invite_id,),
    )
    row = _row_to_dict(cursor.description, cursor.fetchone())

    if row:
        # Add namespace info
        ns_info = get_namespace(row["ns"])
        if ns_info:
            row["namespace_slug"] = ns_info.get("slug")
            row["namespace_display_name"] = ns_info.get("metadata", {}).get("display_name")
            row["namespace_ttl_hours"] = ns_info.get("ttl_hours")

        # Add identity info
        identity_info = get_identity(row["ns"], row["identity_id"])
        if identity_info:
            row["identity_display_name"] = identity_info.get("metadata", {}).get("display_name")

    return row


def claim_invite(invite_id: str, claimed_by: str | None = None) -> dict | None:
    """
    Claim an invite (mark as used and return encrypted secret).

    Returns the invite record including encrypted_secret,
    or None if invite doesn't exist, is already claimed, or is expired.
    """
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    # Get invite and check validity
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

    # Mark as claimed
    conn.execute(
        "UPDATE invites SET claimed_at = ?, claimed_by = ? WHERE invite_id = ?",
        (now, claimed_by, invite_id),
    )
    conn.commit()

    # Add namespace info
    ns_info = get_namespace(row["ns"])
    if ns_info:
        row["namespace_slug"] = ns_info.get("slug") or get_or_create_namespace_slug(row["ns"])
        row["namespace_display_name"] = ns_info.get("metadata", {}).get("display_name")
        row["namespace_ttl_hours"] = ns_info.get("ttl_hours")

    # Add identity info
    identity_info = get_identity(row["ns"], row["identity_id"])
    if identity_info:
        row["identity_display_name"] = identity_info.get("metadata", {}).get("display_name")

    row["claimed_at"] = now
    row["claimed_by"] = claimed_by

    return row


def list_invites(ns: str, include_claimed: bool = False) -> list[dict]:
    """List invites for a namespace."""
    conn = get_connection()

    query = """SELECT invite_id, ns, identity_id, display_name, created_by, 
                      created_at, expires_at, claimed_at, claimed_by
               FROM invites WHERE ns = ?"""

    if not include_claimed:
        query += " AND claimed_at IS NULL"

    query += " ORDER BY created_at DESC"

    cursor = conn.execute(query, (ns,))
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def revoke_invite(invite_id: str) -> bool:
    """Revoke (delete) an invite."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM invites WHERE invite_id = ?", (invite_id,))
    conn.commit()
    return cursor.rowcount > 0


def cleanup_expired_invites() -> int:
    """Delete expired unclaimed invites. Returns count deleted."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at <= ? AND claimed_at IS NULL",
        (now,),
    )
    conn.commit()
    return cursor.rowcount


# --- TTL and Archive Operations ---


def get_expired_messages(limit: int = 1000) -> list[dict]:
    """Get messages past their expiration time."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """SELECT mid, ns, to_id, from_id, body, created_at, read_at, expires_at
           FROM messages 
           WHERE expires_at IS NOT NULL AND expires_at <= ? AND archived_at IS NULL
           ORDER BY expires_at
           LIMIT ?""",
        (now, limit),
    )
    return _rows_to_dicts(cursor.description, cursor.fetchall())


def delete_expired_messages() -> int:
    """Delete all expired messages (excluding archived). Returns count deleted."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ? AND archived_at IS NULL",
        (now,),
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
