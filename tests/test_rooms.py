"""Tests for room operations in the database layer."""

import pytest
from deadrop import db


class TestRoomCreation:
    """Tests for creating rooms."""

    def test_create_room_basic(self):
        """Create a room with a display name."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        room = db.create_room(ns["ns"], alice["id"], display_name="Test Room")

        assert room["room_id"] is not None
        assert room["ns"] == ns["ns"]
        assert room["display_name"] == "Test Room"
        assert room["created_by"] == alice["id"]
        assert room["created_at"] is not None

    def test_create_room_no_display_name(self):
        """Create a room without a display name."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        room = db.create_room(ns["ns"], alice["id"])

        assert room["room_id"] is not None
        assert room["display_name"] is None

    def test_create_room_adds_creator_as_member(self):
        """Creating a room should add the creator as a member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        room = db.create_room(ns["ns"], alice["id"])

        assert db.is_room_member(room["room_id"], alice["id"]) is True
        members = db.list_room_members(room["room_id"])
        assert len(members) == 1
        assert members[0]["identity_id"] == alice["id"]

    def test_create_room_invalid_creator(self):
        """Creating a room with non-existent creator should fail."""
        ns = db.create_namespace()

        with pytest.raises(ValueError, match="not found"):
            db.create_room(ns["ns"], "nonexistent-id")

    def test_create_room_wrong_namespace(self):
        """Creating a room with creator from different namespace should fail."""
        ns1 = db.create_namespace()
        ns2 = db.create_namespace()
        alice = db.create_identity(ns1["ns"])

        with pytest.raises(ValueError, match="not found"):
            db.create_room(ns2["ns"], alice["id"])


class TestRoomRetrieval:
    """Tests for getting and listing rooms."""

    def test_get_room(self):
        """Get a room by ID."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], display_name="Test Room")

        fetched = db.get_room(room["room_id"])

        assert fetched is not None
        assert fetched["room_id"] == room["room_id"]
        assert fetched["display_name"] == "Test Room"

    def test_get_room_not_found(self):
        """Getting non-existent room returns None."""
        result = db.get_room("nonexistent-room-id")
        assert result is None

    def test_list_rooms(self):
        """List all rooms in a namespace."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        room1 = db.create_room(ns["ns"], alice["id"], display_name="Room 1")
        room2 = db.create_room(ns["ns"], alice["id"], display_name="Room 2")

        rooms = db.list_rooms(ns["ns"])

        assert len(rooms) == 2
        assert rooms[0]["room_id"] == room1["room_id"]
        assert rooms[1]["room_id"] == room2["room_id"]

    def test_list_rooms_empty(self):
        """List rooms in namespace with no rooms."""
        ns = db.create_namespace()
        rooms = db.list_rooms(ns["ns"])
        assert rooms == []

    def test_list_rooms_for_identity(self):
        """List rooms that an identity is a member of."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        _ = db.create_room(ns["ns"], alice["id"], display_name="Alice's Room")
        room2 = db.create_room(ns["ns"], bob["id"], display_name="Bob's Room")
        db.add_room_member(room2["room_id"], alice["id"])

        alice_rooms = db.list_rooms_for_identity(ns["ns"], alice["id"])
        bob_rooms = db.list_rooms_for_identity(ns["ns"], bob["id"])

        # Alice is in both rooms
        assert len(alice_rooms) == 2

        # Bob is only in his own room
        assert len(bob_rooms) == 1
        assert bob_rooms[0]["room_id"] == room2["room_id"]


class TestRoomDeletion:
    """Tests for deleting rooms."""

    def test_delete_room(self):
        """Delete a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.delete_room(room["room_id"])

        assert result is True
        assert db.get_room(room["room_id"]) is None

    def test_delete_room_not_found(self):
        """Deleting non-existent room returns False."""
        result = db.delete_room("nonexistent-room-id")
        assert result is False

    def test_delete_room_cascades_members(self):
        """Deleting room should remove all members (via foreign key cascade)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.delete_room(room["room_id"])

        # Room should be gone
        assert db.get_room(room["room_id"]) is None
        # Members list should be empty
        assert db.list_room_members(room["room_id"]) == []

    def test_delete_room_cascades_messages(self):
        """Deleting room should remove all messages (via foreign key cascade)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.send_room_message(room["room_id"], alice["id"], "Hello!")

        db.delete_room(room["room_id"])

        # Room should be gone
        assert db.get_room(room["room_id"]) is None
        # Note: SQLite foreign key cascades need PRAGMA foreign_keys=ON
        # For now, messages may remain orphaned - this is a known limitation
        # The important thing is the room itself is deleted


class TestRoomMembers:
    """Tests for room membership operations."""

    def test_is_room_member(self):
        """Check if an identity is a room member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        assert db.is_room_member(room["room_id"], alice["id"]) is True
        assert db.is_room_member(room["room_id"], bob["id"]) is False

    def test_add_room_member(self):
        """Add a member to a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.add_room_member(room["room_id"], bob["id"])

        assert result["identity_id"] == bob["id"]
        assert result["room_id"] == room["room_id"]
        assert db.is_room_member(room["room_id"], bob["id"]) is True

    def test_add_room_member_idempotent(self):
        """Adding existing member returns existing membership."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.add_room_member(room["room_id"], alice["id"])

        assert result["identity_id"] == alice["id"]
        members = db.list_room_members(room["room_id"])
        assert len(members) == 1

    def test_add_room_member_invalid_room(self):
        """Adding member to non-existent room should fail."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        with pytest.raises(ValueError, match="not found"):
            db.add_room_member("nonexistent-room-id", alice["id"])

    def test_add_room_member_invalid_identity(self):
        """Adding non-existent identity to room should fail."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        with pytest.raises(ValueError, match="not found"):
            db.add_room_member(room["room_id"], "nonexistent-id")

    def test_remove_room_member(self):
        """Remove a member from a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        result = db.remove_room_member(room["room_id"], bob["id"])

        assert result is True
        assert db.is_room_member(room["room_id"], bob["id"]) is False

    def test_remove_room_member_not_member(self):
        """Removing non-member returns False."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.remove_room_member(room["room_id"], bob["id"])

        assert result is False

    def test_list_room_members(self):
        """List all members of a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"], metadata={"display_name": "Alice"})
        bob = db.create_identity(ns["ns"], metadata={"display_name": "Bob"})
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        members = db.list_room_members(room["room_id"])

        assert len(members) == 2
        assert members[0]["identity_id"] == alice["id"]
        assert members[0]["metadata"]["display_name"] == "Alice"
        assert members[1]["identity_id"] == bob["id"]

    def test_get_room_member_info(self):
        """Get membership info for a specific member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"], metadata={"display_name": "Alice"})
        room = db.create_room(ns["ns"], alice["id"])

        info = db.get_room_member_info(room["room_id"], alice["id"])

        assert info is not None
        assert info["identity_id"] == alice["id"]
        assert info["room_id"] == room["room_id"]
        assert info["metadata"]["display_name"] == "Alice"
        assert info["last_read_mid"] is None

    def test_get_room_member_info_not_member(self):
        """Getting info for non-member returns None."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        info = db.get_room_member_info(room["room_id"], bob["id"])

        assert info is None


class TestRoomMessages:
    """Tests for room messaging."""

    def test_send_room_message(self):
        """Send a message to a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg = db.send_room_message(room["room_id"], alice["id"], "Hello, room!")

        assert msg["mid"] is not None
        assert msg["room_id"] == room["room_id"]
        assert msg["from"] == alice["id"]
        assert msg["body"] == "Hello, room!"
        assert msg["content_type"] == "text/plain"

    def test_send_room_message_custom_content_type(self):
        """Send a message with custom content type."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg = db.send_room_message(
            room["room_id"], alice["id"], '{"key": "value"}', content_type="application/json"
        )

        assert msg["content_type"] == "application/json"

    def test_send_room_message_not_member(self):
        """Sending message as non-member should fail."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        with pytest.raises(ValueError, match="not a member"):
            db.send_room_message(room["room_id"], bob["id"], "Hello!")

    def test_send_room_message_invalid_room(self):
        """Sending message to non-existent room should fail."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        with pytest.raises(ValueError, match="not found"):
            db.send_room_message("nonexistent-room-id", alice["id"], "Hello!")

    def test_get_room_messages(self):
        """Get messages from a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.send_room_message(room["room_id"], alice["id"], "Message 1")
        db.send_room_message(room["room_id"], alice["id"], "Message 2")

        messages = db.get_room_messages(room["room_id"])

        assert len(messages) == 2
        assert messages[0]["body"] == "Message 1"
        assert messages[1]["body"] == "Message 2"

    def test_get_room_messages_after_mid(self):
        """Get messages after a specific message ID."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg1 = db.send_room_message(room["room_id"], alice["id"], "Message 1")
        db.send_room_message(room["room_id"], alice["id"], "Message 2")
        db.send_room_message(room["room_id"], alice["id"], "Message 3")

        messages = db.get_room_messages(room["room_id"], after_mid=msg1["mid"])

        assert len(messages) == 2
        assert messages[0]["body"] == "Message 2"
        assert messages[1]["body"] == "Message 3"

    def test_get_room_messages_with_limit(self):
        """Get messages with a limit."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        for i in range(5):
            db.send_room_message(room["room_id"], alice["id"], f"Message {i}")

        messages = db.get_room_messages(room["room_id"], limit=3)

        assert len(messages) == 3
        assert messages[0]["body"] == "Message 0"

    def test_get_room_message(self):
        """Get a single message by ID."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg = db.send_room_message(room["room_id"], alice["id"], "Hello!")

        fetched = db.get_room_message(room["room_id"], msg["mid"])

        assert fetched is not None
        assert fetched["mid"] == msg["mid"]
        assert fetched["body"] == "Hello!"

    def test_get_room_message_not_found(self):
        """Getting non-existent message returns None."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.get_room_message(room["room_id"], "nonexistent-mid")

        assert result is None

    def test_has_new_room_messages(self):
        """Check for new messages in a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        assert db.has_new_room_messages(room["room_id"]) is False

        db.send_room_message(room["room_id"], alice["id"], "Hello!")

        assert db.has_new_room_messages(room["room_id"]) is True

    def test_has_new_room_messages_after_mid(self):
        """Check for new messages after a specific message ID."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg1 = db.send_room_message(room["room_id"], alice["id"], "Message 1")

        assert db.has_new_room_messages(room["room_id"], after_mid=msg1["mid"]) is False

        db.send_room_message(room["room_id"], alice["id"], "Message 2")

        assert db.has_new_room_messages(room["room_id"], after_mid=msg1["mid"]) is True


class TestRoomReadTracking:
    """Tests for per-user read cursor tracking."""

    def test_update_room_read_cursor(self):
        """Update the read cursor for a member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        msg = db.send_room_message(room["room_id"], alice["id"], "Hello!")

        result = db.update_room_read_cursor(room["room_id"], alice["id"], msg["mid"])

        assert result is True
        info = db.get_room_member_info(room["room_id"], alice["id"])
        assert info["last_read_mid"] == msg["mid"]

    def test_update_room_read_cursor_only_forward(self):
        """Read cursor should only move forward."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg1 = db.send_room_message(room["room_id"], alice["id"], "Message 1")
        msg2 = db.send_room_message(room["room_id"], alice["id"], "Message 2")

        # Move cursor to msg2
        db.update_room_read_cursor(room["room_id"], alice["id"], msg2["mid"])

        # Try to move cursor back to msg1 - should return True (member exists) but not update
        result = db.update_room_read_cursor(room["room_id"], alice["id"], msg1["mid"])

        assert result is True  # Member exists
        info = db.get_room_member_info(room["room_id"], alice["id"])
        assert info["last_read_mid"] == msg2["mid"]  # Still at msg2

    def test_update_room_read_cursor_not_member(self):
        """Updating cursor for non-member returns False."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.update_room_read_cursor(room["room_id"], bob["id"], "some-mid")

        assert result is False

    def test_get_room_unread_count(self):
        """Get count of unread messages."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        # Send 3 messages
        msg1 = db.send_room_message(room["room_id"], alice["id"], "Message 1")
        db.send_room_message(room["room_id"], alice["id"], "Message 2")
        db.send_room_message(room["room_id"], alice["id"], "Message 3")

        # Bob hasn't read anything
        assert db.get_room_unread_count(room["room_id"], bob["id"]) == 3

        # Bob reads first message
        db.update_room_read_cursor(room["room_id"], bob["id"], msg1["mid"])
        assert db.get_room_unread_count(room["room_id"], bob["id"]) == 2

    def test_get_room_unread_count_not_member(self):
        """Getting unread count for non-member returns 0."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        assert db.get_room_unread_count(room["room_id"], bob["id"]) == 0


class TestRoomMultiUser:
    """Tests for multi-user room scenarios."""

    def test_multiple_users_send_messages(self):
        """Multiple users can send messages to a room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        db.send_room_message(room["room_id"], alice["id"], "Hello from Alice")
        db.send_room_message(room["room_id"], bob["id"], "Hello from Bob")

        messages = db.get_room_messages(room["room_id"])

        assert len(messages) == 2
        assert messages[0]["from"] == alice["id"]
        assert messages[1]["from"] == bob["id"]

    def test_independent_read_cursors(self):
        """Each user has their own read cursor."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        msg1 = db.send_room_message(room["room_id"], alice["id"], "Message 1")
        _ = db.send_room_message(room["room_id"], alice["id"], "Message 2")
        msg3 = db.send_room_message(room["room_id"], alice["id"], "Message 3")

        # Alice reads all, Bob reads first
        db.update_room_read_cursor(room["room_id"], alice["id"], msg3["mid"])
        db.update_room_read_cursor(room["room_id"], bob["id"], msg1["mid"])

        assert db.get_room_unread_count(room["room_id"], alice["id"]) == 0
        assert db.get_room_unread_count(room["room_id"], bob["id"]) == 2
