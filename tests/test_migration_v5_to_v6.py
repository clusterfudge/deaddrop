"""Test schema migration from v5 (current deployed) to v6 (attachments).

Simulates the real migration path:
1. Create a v5 database with realistic data (50 room msgs, 20 DMs)
2. Run the v6 migration
3. Verify all existing data is intact
4. Verify new attachment CRUD operations work
"""

import sqlite3
import uuid
import base64
import hashlib
from datetime import datetime, timezone

import pytest

from deadrop.db import (
    get_schema_version,
    run_migrations,
    add_attachment,
    get_attachment,
    get_message_attachments,
)


@pytest.fixture
def v5_database(tmp_path):
    """Create a database at schema version 5 with realistic data."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript("""
        CREATE TABLE namespaces (
            id TEXT PRIMARY KEY, display_name TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE identities (
            pubkey TEXT PRIMARY KEY, namespace_id TEXT NOT NULL,
            display_name TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, namespace_id TEXT NOT NULL,
            sender_pubkey TEXT NOT NULL, mid TEXT UNIQUE, body TEXT NOT NULL,
            created_at TEXT NOT NULL, content_type TEXT NOT NULL DEFAULT 'text/plain'
        );
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY, description TEXT,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE rooms (
            id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL,
            name TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL
        );
        CREATE TABLE room_members (
            room_id TEXT NOT NULL, pubkey TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member', joined_at TEXT NOT NULL,
            PRIMARY KEY (room_id, pubkey)
        );
        CREATE TABLE room_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT NOT NULL,
            sender_pubkey TEXT NOT NULL, mid TEXT UNIQUE, body TEXT NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'text/markdown',
            created_at TEXT NOT NULL, reference_mid TEXT, content_hash TEXT
        );
        CREATE INDEX idx_room_messages_mid ON room_messages(mid);
        CREATE INDEX idx_messages_mid ON messages(mid);
        CREATE INDEX idx_room_messages_content_hash
            ON room_messages(room_id, content_hash);
    """)

    for v in range(1, 6):
        conn.execute(
            "INSERT INTO schema_version (version, description) VALUES (?, ?)",
            (v, f"Migration {v}"),
        )

    now = datetime.now(timezone.utc).isoformat()
    ns_id = "test-ns"
    conn.execute("INSERT INTO namespaces VALUES (?, ?, ?)", (ns_id, "Test", now))

    pubkeys = [f"pk_{uuid.uuid4().hex[:16]}" for _ in range(3)]
    for i, pk in enumerate(pubkeys):
        conn.execute(
            "INSERT INTO identities VALUES (?, ?, ?, ?)",
            (pk, ns_id, f"User {i}", now),
        )

    room_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO rooms VALUES (?, ?, ?, ?, ?)",
        (room_id, ns_id, "twin", now, pubkeys[0]),
    )
    for pk in pubkeys:
        conn.execute(
            "INSERT INTO room_members VALUES (?, ?, ?, ?)",
            (room_id, pk, "member", now),
        )

    mids = []
    for i in range(50):
        mid = f"069df{i:03x}-test-{uuid.uuid4().hex[:4]}"
        mids.append(mid)
        body = f"Test message {i}: {'x' * (100 + i * 10)}"
        ch = hashlib.sha256(body.encode()).hexdigest()[:16]
        conn.execute(
            """INSERT INTO room_messages
               (room_id, sender_pubkey, mid, body, content_type,
                created_at, content_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (room_id, pubkeys[i % 3], mid, body, "text/markdown", now, ch),
        )

    for i in range(20):
        conn.execute(
            """INSERT INTO messages
               (namespace_id, sender_pubkey, mid, body, created_at, content_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                ns_id,
                pubkeys[0],
                f"dm_{uuid.uuid4().hex[:8]}",
                f"DM {i}",
                now,
                "text/plain",
            ),
        )

    conn.commit()
    yield {
        "conn": conn,
        "db_path": str(db_path),
        "ns": ns_id,
        "room": room_id,
        "pubkeys": pubkeys,
        "mids": mids,
        "room_msg_count": 50,
        "dm_count": 20,
    }
    conn.close()


class TestMigrationV5ToV6:
    """Test the v5 to v6 schema migration (add attachments table)."""

    def test_pre_migration_version(self, v5_database):
        assert get_schema_version(v5_database["conn"]) == 5

    def test_migration_runs(self, v5_database):
        run_migrations(v5_database["conn"])
        assert get_schema_version(v5_database["conn"]) == 6

    def test_existing_room_messages_intact(self, v5_database):
        run_migrations(v5_database["conn"])
        count = v5_database["conn"].execute("SELECT COUNT(*) FROM room_messages").fetchone()[0]
        assert count == v5_database["room_msg_count"]

    def test_existing_dms_intact(self, v5_database):
        run_migrations(v5_database["conn"])
        count = v5_database["conn"].execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        assert count == v5_database["dm_count"]

    def test_attachments_table_created_empty(self, v5_database):
        run_migrations(v5_database["conn"])
        count = v5_database["conn"].execute("SELECT COUNT(*) FROM attachments").fetchone()[0]
        assert count == 0

    def test_attachment_index_created(self, v5_database):
        run_migrations(v5_database["conn"])
        indexes = (
            v5_database["conn"]
            .execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='attachments'")
            .fetchall()
        )
        names = [i[0] for i in indexes]
        assert "idx_attachments_mid" in names

    def test_add_attachment_after_migration(self, v5_database):
        conn = v5_database["conn"]
        run_migrations(conn)
        data = base64.b64encode(b"fake png" * 100).decode()
        result = add_attachment(
            message_mid=v5_database["mids"][0],
            content_type="image/png",
            data=data,
            size=len(b"fake png" * 100),
            filename="test.png",
            conn=conn,
        )
        assert "id" in result
        assert result["filename"] == "test.png"

    def test_get_attachment_with_data(self, v5_database):
        conn = v5_database["conn"]
        run_migrations(conn)
        data = base64.b64encode(b"test data" * 50).decode()
        result = add_attachment(
            message_mid=v5_database["mids"][0],
            content_type="image/png",
            data=data,
            size=len(b"test data" * 50),
            conn=conn,
        )
        fetched = get_attachment(result["id"], include_data=True, conn=conn)
        assert fetched is not None
        assert fetched["data"] == data

    def test_get_attachment_metadata_only(self, v5_database):
        conn = v5_database["conn"]
        run_migrations(conn)
        data = base64.b64encode(b"x" * 100).decode()
        result = add_attachment(
            message_mid=v5_database["mids"][0],
            content_type="image/png",
            data=data,
            size=100,
            conn=conn,
        )
        fetched = get_attachment(result["id"], include_data=False, conn=conn)
        assert fetched is not None
        assert fetched.get("data") is None

    def test_get_message_attachments(self, v5_database):
        conn = v5_database["conn"]
        run_migrations(conn)
        mid = v5_database["mids"][0]
        data = base64.b64encode(b"x" * 50).decode()
        add_attachment(
            message_mid=mid,
            content_type="image/png",
            data=data,
            size=50,
            conn=conn,
        )
        add_attachment(
            message_mid=mid,
            content_type="image/jpeg",
            data=data,
            size=50,
            conn=conn,
        )
        atts = get_message_attachments(mid, conn=conn)
        assert len(atts) == 2

    def test_original_messages_unchanged(self, v5_database):
        conn = v5_database["conn"]
        mid = v5_database["mids"][0]
        original = conn.execute(
            "SELECT body, content_hash FROM room_messages WHERE mid=?", (mid,)
        ).fetchone()
        run_migrations(conn)
        after = conn.execute(
            "SELECT body, content_hash FROM room_messages WHERE mid=?", (mid,)
        ).fetchone()
        assert original == after
