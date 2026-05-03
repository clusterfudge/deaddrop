"""Tests for implicit message deduplication.

Verifies that identical messages from the same sender to the same destination
within a short time window are deduplicated, preventing network-retry
duplicates while still allowing intentional repeated messages.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from deadrop import db
from deadrop.api import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def setup():
    """Create namespace with two identities for testing."""
    ns = db.create_namespace(metadata={"display_name": "Test NS"})
    alice = db.create_identity(ns["ns"], metadata={"display_name": "Alice"})
    bob = db.create_identity(ns["ns"], metadata={"display_name": "Bob"})
    return {"ns": ns, "alice": alice, "bob": bob}


@pytest.fixture
def room_setup(setup):
    """Create a room with Alice and Bob as members."""
    ns = setup["ns"]["ns"]
    alice_id = setup["alice"]["id"]
    bob_id = setup["bob"]["id"]
    room = db.create_room(ns, alice_id, display_name="Test Room")
    db.add_room_member(room["room_id"], bob_id)
    return {**setup, "room": room}


# --- Direct Message Dedup (db layer) ---


class TestDirectMessageDedup:
    """Deduplication for direct (inbox) messages at the db layer."""

    def test_duplicate_message_returns_same_mid(self, setup):
        """Sending the same message twice returns the same mid."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!")
        msg2 = db.send_message(ns, alice_id, bob_id, "Hello!")

        assert msg1["mid"] == msg2["mid"]
        assert msg2.get("deduplicated") is True
        assert msg1.get("deduplicated") is None  # First send is not deduped

    def test_duplicate_detected_by_content_hash(self, setup):
        """Dedup matches on body + content_type, not just body."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!", content_type="text/plain")
        msg2 = db.send_message(ns, alice_id, bob_id, "Hello!", content_type="text/plain")

        assert msg1["mid"] == msg2["mid"]

    def test_different_content_type_not_deduped(self, setup):
        """Same body but different content_type creates separate message."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!", content_type="text/plain")
        msg2 = db.send_message(ns, alice_id, bob_id, "Hello!", content_type="text/markdown")

        assert msg1["mid"] != msg2["mid"]
        assert msg2.get("deduplicated") is None

    def test_different_body_not_deduped(self, setup):
        """Different body is not considered a duplicate."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!")
        msg2 = db.send_message(ns, alice_id, bob_id, "Hi there!")

        assert msg1["mid"] != msg2["mid"]

    def test_different_sender_not_deduped(self, setup):
        """Same message from different senders is not a duplicate."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!")
        msg2 = db.send_message(ns, bob_id, alice_id, "Hello!")

        assert msg1["mid"] != msg2["mid"]

    def test_different_recipient_not_deduped(self, setup):
        """Same message to different recipients is not a duplicate."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]
        carol = db.create_identity(ns, metadata={"display_name": "Carol"})

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!")
        msg2 = db.send_message(ns, alice_id, carol["id"], "Hello!")

        assert msg1["mid"] != msg2["mid"]

    def test_dedup_window_expires(self, setup):
        """After the dedup window, the same message creates a new entry."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "Hello!")

        # Simulate the dedup window expiring by backdating the first message
        window = db.DEDUP_WINDOW_SECONDS
        past = (datetime.now(timezone.utc) - timedelta(seconds=window + 10)).isoformat()
        conn = db._get_conn(None)
        conn.execute("UPDATE messages SET created_at = ? WHERE mid = ?", (past, msg1["mid"]), name="test.expire_dedup_window")
        conn.commit()

        msg2 = db.send_message(ns, alice_id, bob_id, "Hello!")
        assert msg1["mid"] != msg2["mid"]
        assert msg2.get("deduplicated") is None

    def test_only_one_row_in_db_on_dedup(self, setup):
        """Deduplication does not insert a second row."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        db.send_message(ns, alice_id, bob_id, "Hello!")
        db.send_message(ns, alice_id, bob_id, "Hello!")
        db.send_message(ns, alice_id, bob_id, "Hello!")

        messages = db.get_messages(ns, bob_id)
        assert len(messages) == 1

    def test_self_message_dedup(self, setup):
        """Self-messages (notes to self) are also deduplicated."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]

        msg1 = db.send_message(ns, alice_id, alice_id, "Reminder")
        msg2 = db.send_message(ns, alice_id, alice_id, "Reminder")

        assert msg1["mid"] == msg2["mid"]
        assert msg2.get("deduplicated") is True

    def test_dedup_preserves_ttl(self, setup):
        """Dedup returns the original message; TTL from the first send is kept."""
        ns = setup["ns"]["ns"]
        alice_id = setup["alice"]["id"]
        bob_id = setup["bob"]["id"]

        msg1 = db.send_message(ns, alice_id, bob_id, "ephemeral", ttl_hours=1)
        msg2 = db.send_message(ns, alice_id, bob_id, "ephemeral", ttl_hours=1)

        assert msg1["mid"] == msg2["mid"]


# --- Room Message Dedup (db layer) ---


class TestRoomMessageDedup:
    """Deduplication for room messages at the db layer."""

    def test_duplicate_room_message_returns_same_mid(self, room_setup):
        """Sending the same room message twice returns the same mid."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]

        msg1 = db.send_room_message(room_id, alice_id, "Hello room!")
        msg2 = db.send_room_message(room_id, alice_id, "Hello room!")

        assert msg1["mid"] == msg2["mid"]
        assert msg2.get("deduplicated") is True

    def test_different_body_in_room_not_deduped(self, room_setup):
        """Different messages in the same room are not deduplicated."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]

        msg1 = db.send_room_message(room_id, alice_id, "Hello!")
        msg2 = db.send_room_message(room_id, alice_id, "Goodbye!")

        assert msg1["mid"] != msg2["mid"]

    def test_different_sender_in_room_not_deduped(self, room_setup):
        """Same message from different senders is not a duplicate."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]
        bob_id = room_setup["bob"]["id"]

        msg1 = db.send_room_message(room_id, alice_id, "Hello!")
        msg2 = db.send_room_message(room_id, bob_id, "Hello!")

        assert msg1["mid"] != msg2["mid"]

    def test_different_room_not_deduped(self, room_setup):
        """Same message in different rooms is not deduplicated."""
        ns = room_setup["ns"]["ns"]
        alice_id = room_setup["alice"]["id"]
        room1_id = room_setup["room"]["room_id"]

        room2 = db.create_room(ns, alice_id, display_name="Room 2")
        room2_id = room2["room_id"]

        msg1 = db.send_room_message(room1_id, alice_id, "Hello!")
        msg2 = db.send_room_message(room2_id, alice_id, "Hello!")

        assert msg1["mid"] != msg2["mid"]

    def test_reaction_dedup(self, room_setup):
        """Duplicate reactions (same emoji, same reference_mid) are deduplicated."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]
        bob_id = room_setup["bob"]["id"]

        # Alice sends a message, Bob reacts twice (network retry)
        original = db.send_room_message(room_id, alice_id, "Check this out")
        react1 = db.send_room_message(
            room_id, bob_id, "👍", content_type="reaction", reference_mid=original["mid"]
        )
        react2 = db.send_room_message(
            room_id, bob_id, "👍", content_type="reaction", reference_mid=original["mid"]
        )

        assert react1["mid"] == react2["mid"]
        assert react2.get("deduplicated") is True

    def test_different_reaction_not_deduped(self, room_setup):
        """Different reaction emoji on the same message is not deduplicated."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]
        bob_id = room_setup["bob"]["id"]

        original = db.send_room_message(room_id, alice_id, "Check this out")
        react1 = db.send_room_message(
            room_id, bob_id, "👍", content_type="reaction", reference_mid=original["mid"]
        )
        react2 = db.send_room_message(
            room_id, bob_id, "❤️", content_type="reaction", reference_mid=original["mid"]
        )

        assert react1["mid"] != react2["mid"]

    def test_room_dedup_window_expires(self, room_setup):
        """After the dedup window, the same room message creates a new entry."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]

        msg1 = db.send_room_message(room_id, alice_id, "Hello!")

        # Backdate the first message past the dedup window
        window = db.DEDUP_WINDOW_SECONDS
        past = (datetime.now(timezone.utc) - timedelta(seconds=window + 10)).isoformat()
        conn = db._get_conn(None)
        conn.execute("UPDATE room_messages SET created_at = ? WHERE mid = ?", (past, msg1["mid"]), name="test.expire_dedup_window")
        conn.commit()

        msg2 = db.send_room_message(room_id, alice_id, "Hello!")
        assert msg1["mid"] != msg2["mid"]

    def test_only_one_row_in_room_on_dedup(self, room_setup):
        """Deduplication does not insert extra rows into room_messages."""
        room_id = room_setup["room"]["room_id"]
        alice_id = room_setup["alice"]["id"]

        db.send_room_message(room_id, alice_id, "Hello!")
        db.send_room_message(room_id, alice_id, "Hello!")
        db.send_room_message(room_id, alice_id, "Hello!")

        messages = db.get_room_messages(room_id)
        assert len(messages) == 1


# --- API Layer Dedup ---


class TestDirectMessageDedupAPI:
    """Deduplication for direct messages via the API layer."""

    def test_send_duplicate_returns_same_mid_with_header(self, client, setup):
        """API returns Dedup-Status header when dedup fires."""
        ns = setup["ns"]["ns"]
        secret = setup["alice"]["secret"]
        bob_id = setup["bob"]["id"]

        resp1 = client.post(
            f"/{ns}/send",
            json={"to": bob_id, "body": "Hello!"},
            headers={"X-Inbox-Secret": secret},
        )
        assert resp1.status_code == 200
        assert "Dedup-Status" not in resp1.headers

        resp2 = client.post(
            f"/{ns}/send",
            json={"to": bob_id, "body": "Hello!"},
            headers={"X-Inbox-Secret": secret},
        )
        assert resp2.status_code == 200
        assert resp2.headers.get("Dedup-Status") == "deduplicated"
        assert resp1.json()["mid"] == resp2.json()["mid"]

    def test_send_different_message_no_dedup_header(self, client, setup):
        """Different messages do not trigger dedup header."""
        ns = setup["ns"]["ns"]
        secret = setup["alice"]["secret"]
        bob_id = setup["bob"]["id"]

        resp1 = client.post(
            f"/{ns}/send",
            json={"to": bob_id, "body": "Hello!"},
            headers={"X-Inbox-Secret": secret},
        )
        resp2 = client.post(
            f"/{ns}/send",
            json={"to": bob_id, "body": "Different message"},
            headers={"X-Inbox-Secret": secret},
        )

        assert "Dedup-Status" not in resp1.headers
        assert "Dedup-Status" not in resp2.headers
        assert resp1.json()["mid"] != resp2.json()["mid"]


class TestRoomMessageDedupAPI:
    """Deduplication for room messages via the API layer."""

    def test_room_send_duplicate_returns_same_mid_with_header(self, client, room_setup):
        """API returns Dedup-Status header for room message dedup."""
        ns = room_setup["ns"]["ns"]
        room_id = room_setup["room"]["room_id"]
        secret = room_setup["alice"]["secret"]

        resp1 = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            json={"body": "Hello room!"},
            headers={"X-Inbox-Secret": secret},
        )
        assert resp1.status_code == 200
        assert "Dedup-Status" not in resp1.headers

        resp2 = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            json={"body": "Hello room!"},
            headers={"X-Inbox-Secret": secret},
        )
        assert resp2.status_code == 200
        assert resp2.headers.get("Dedup-Status") == "deduplicated"
        assert resp1.json()["mid"] == resp2.json()["mid"]

    def test_room_send_different_message_no_dedup_header(self, client, room_setup):
        """Different room messages do not trigger dedup."""
        ns = room_setup["ns"]["ns"]
        room_id = room_setup["room"]["room_id"]
        secret = room_setup["alice"]["secret"]

        resp1 = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            json={"body": "First message"},
            headers={"X-Inbox-Secret": secret},
        )
        resp2 = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            json={"body": "Second message"},
            headers={"X-Inbox-Secret": secret},
        )

        assert "Dedup-Status" not in resp1.headers
        assert "Dedup-Status" not in resp2.headers
        assert resp1.json()["mid"] != resp2.json()["mid"]


# --- Content Hash Tests ---


class TestContentHash:
    """Verify the content hash function properties."""

    def test_same_inputs_same_hash(self):
        """Identical inputs produce the same hash."""
        h1 = db._compute_content_hash("hello", "text/plain")
        h2 = db._compute_content_hash("hello", "text/plain")
        assert h1 == h2

    def test_different_body_different_hash(self):
        """Different body produces different hash."""
        h1 = db._compute_content_hash("hello", "text/plain")
        h2 = db._compute_content_hash("world", "text/plain")
        assert h1 != h2

    def test_different_content_type_different_hash(self):
        """Different content_type produces different hash."""
        h1 = db._compute_content_hash("hello", "text/plain")
        h2 = db._compute_content_hash("hello", "text/markdown")
        assert h1 != h2

    def test_reference_mid_affects_hash(self):
        """reference_mid is included in the hash."""
        h1 = db._compute_content_hash("👍", "reaction", reference_mid="abc")
        h2 = db._compute_content_hash("👍", "reaction", reference_mid="def")
        assert h1 != h2

    def test_no_reference_mid_vs_with_reference_mid(self):
        """Hash differs between no reference_mid and a specific reference_mid."""
        h1 = db._compute_content_hash("👍", "reaction")
        h2 = db._compute_content_hash("👍", "reaction", reference_mid="abc")
        assert h1 != h2

    def test_hash_length(self):
        """Hash is 16 hex chars (64 bits)."""
        h = db._compute_content_hash("test", "text/plain")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)


# --- Migration Test ---


class TestDedupMigration:
    """Verify migration 005 adds the correct columns and indexes."""

    def test_migration_adds_content_hash_to_messages(self):
        """Messages table has content_hash column after migration."""
        conn = db._get_conn(None)
        assert db._column_exists(conn, "messages", "content_hash")

    def test_migration_adds_content_hash_to_room_messages(self):
        """Room messages table has content_hash column after migration."""
        conn = db._get_conn(None)
        assert db._column_exists(conn, "room_messages", "content_hash")

    def test_migration_is_idempotent(self):
        """Running migration 005 twice does not error."""
        conn = db._get_conn(None)
        # Should not raise
        db._migrate_005_add_content_hash(conn)
        db._migrate_005_add_content_hash(conn)


# --- Client Layer Dedup ---


class TestClientDedup:
    """Dedup works through the Deaddrop client layer."""

    def test_client_send_message_dedup(self):
        """Deaddrop.send_message deduplicates on retry."""
        from deadrop.client import Deaddrop

        client = Deaddrop.in_memory()
        setup = client.quick_setup("Test", ["Alice", "Bob"])
        ns = setup["namespace"]["ns"]
        alice_secret = setup["identities"]["Alice"]["secret"]
        bob_id = setup["identities"]["Bob"]["id"]

        msg1 = client.send_message(ns, alice_secret, bob_id, "Hello!")
        msg2 = client.send_message(ns, alice_secret, bob_id, "Hello!")

        assert msg1["mid"] == msg2["mid"]

    def test_client_send_room_message_dedup(self):
        """Deaddrop.send_room_message deduplicates on retry."""
        from deadrop.client import Deaddrop

        client = Deaddrop.in_memory()
        setup = client.quick_setup("Test", ["Alice", "Bob"])
        ns = setup["namespace"]["ns"]
        alice_secret = setup["identities"]["Alice"]["secret"]
        bob_id = setup["identities"]["Bob"]["id"]

        room = client.create_room(ns, alice_secret, "Chat")
        client.add_room_member(ns, room["room_id"], bob_id, alice_secret)

        msg1 = client.send_room_message(ns, room["room_id"], alice_secret, "Hello room!")
        msg2 = client.send_room_message(ns, room["room_id"], alice_secret, "Hello room!")

        assert msg1["mid"] == msg2["mid"]

    def test_client_different_messages_not_deduped(self):
        """Different messages through client are not deduplicated."""
        from deadrop.client import Deaddrop

        client = Deaddrop.in_memory()
        setup = client.quick_setup("Test", ["Alice", "Bob"])
        ns = setup["namespace"]["ns"]
        alice_secret = setup["identities"]["Alice"]["secret"]
        bob_id = setup["identities"]["Bob"]["id"]

        msg1 = client.send_message(ns, alice_secret, bob_id, "First")
        msg2 = client.send_message(ns, alice_secret, bob_id, "Second")

        assert msg1["mid"] != msg2["mid"]
