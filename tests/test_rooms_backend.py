"""Tests for room operations in backends and client."""

import pytest

from deadrop import Deaddrop
from deadrop.backends import InMemoryBackend


class TestInMemoryBackendRooms:
    """Test room operations on InMemoryBackend."""

    @pytest.fixture
    def backend(self):
        """Create in-memory backend."""
        return InMemoryBackend()

    @pytest.fixture
    def setup(self, backend):
        """Create namespace with two identities."""
        ns = backend.create_namespace(display_name="Test NS")
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        bob = backend.create_identity(ns["ns"], display_name="Bob")
        return {
            "backend": backend,
            "ns": ns["ns"],
            "ns_secret": ns["secret"],
            "alice": alice,
            "bob": bob,
        }

    def test_create_room(self, setup):
        """Create a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"], display_name="Test Room")

        assert room["room_id"] is not None
        assert room["display_name"] == "Test Room"
        assert room["created_by"] == setup["alice"]["id"]

    def test_list_rooms(self, setup):
        """List rooms I'm a member of."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        # Alice should see the room
        alice_rooms = b.list_rooms(setup["ns"], setup["alice"]["secret"])
        assert len(alice_rooms) == 1
        assert alice_rooms[0]["room_id"] == room["room_id"]

        # Bob shouldn't see it (not a member)
        bob_rooms = b.list_rooms(setup["ns"], setup["bob"]["secret"])
        assert len(bob_rooms) == 0

    def test_get_room(self, setup):
        """Get room details."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        fetched = b.get_room(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert fetched is not None
        assert fetched["room_id"] == room["room_id"]

    def test_get_room_not_member(self, setup):
        """Cannot get room if not a member."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        with pytest.raises(PermissionError):
            b.get_room(setup["ns"], room["room_id"], setup["bob"]["secret"])

    def test_delete_room(self, setup):
        """Delete a room with namespace secret."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        result = b.delete_room(setup["ns"], room["room_id"], setup["ns_secret"])
        assert result is True

        # Room should be gone
        alice_rooms = b.list_rooms(setup["ns"], setup["alice"]["secret"])
        assert len(alice_rooms) == 0

    def test_add_room_member(self, setup):
        """Add a member to a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        # Alice adds Bob
        member = b.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )
        assert member["identity_id"] == setup["bob"]["id"]

        # Bob can now see the room
        bob_rooms = b.list_rooms(setup["ns"], setup["bob"]["secret"])
        assert len(bob_rooms) == 1

    def test_remove_room_member(self, setup):
        """Remove a member from a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])
        b.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        # Remove Bob
        result = b.remove_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )
        assert result is True

        # Bob can no longer see the room
        bob_rooms = b.list_rooms(setup["ns"], setup["bob"]["secret"])
        assert len(bob_rooms) == 0

    def test_leave_room(self, setup):
        """Member can leave a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])
        b.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        # Bob leaves
        result = b.remove_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["bob"]["secret"]
        )
        assert result is True

    def test_list_room_members(self, setup):
        """List members of a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])
        b.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        members = b.list_room_members(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert len(members) == 2

    def test_send_room_message(self, setup):
        """Send a message to a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        msg = b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Hello!")
        assert msg["body"] == "Hello!"
        assert msg["from"] == setup["alice"]["id"]

    def test_send_room_message_not_member(self, setup):
        """Cannot send message if not a member."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        with pytest.raises(PermissionError):
            b.send_room_message(setup["ns"], room["room_id"], setup["bob"]["secret"], "Hello!")

    def test_get_room_messages(self, setup):
        """Get messages from a room."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Message 1")
        b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Message 2")

        messages = b.get_room_messages(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert len(messages) == 2
        assert messages[0]["body"] == "Message 1"

    def test_get_room_messages_after(self, setup):
        """Get messages after a specific ID."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])

        msg1 = b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 1")
        b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 2")

        messages = b.get_room_messages(
            setup["ns"], room["room_id"], setup["alice"]["secret"], after_mid=msg1["mid"]
        )
        assert len(messages) == 1
        assert messages[0]["body"] == "Msg 2"

    def test_update_read_cursor(self, setup):
        """Update read cursor."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])
        msg = b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Hello!")

        result = b.update_room_read_cursor(
            setup["ns"], room["room_id"], setup["alice"]["secret"], msg["mid"]
        )
        assert result is True

    def test_get_unread_count(self, setup):
        """Get unread message count."""
        b = setup["backend"]
        room = b.create_room(setup["ns"], setup["alice"]["secret"])
        b.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        # Send messages
        msg1 = b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 1")
        b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 2")
        b.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 3")

        # Bob has 3 unread
        count = b.get_room_unread_count(setup["ns"], room["room_id"], setup["bob"]["secret"])
        assert count == 3

        # Bob reads first message
        b.update_room_read_cursor(setup["ns"], room["room_id"], setup["bob"]["secret"], msg1["mid"])

        # Bob has 2 unread
        count = b.get_room_unread_count(setup["ns"], room["room_id"], setup["bob"]["secret"])
        assert count == 2


class TestInMemoryBackendThreading:
    """Test threading on InMemoryBackend."""

    @pytest.fixture
    def backend(self):
        return InMemoryBackend()

    @pytest.fixture
    def setup(self, backend):
        ns = backend.create_namespace(display_name="Test NS")
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        room = backend.create_room(ns["ns"], alice["secret"])
        return {
            "backend": backend,
            "ns": ns["ns"],
            "alice": alice,
            "room_id": room["room_id"],
        }

    def test_send_reply(self, setup):
        """Send a thread reply via backend."""
        b = setup["backend"]
        root = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Root")
        reply = b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            "Reply",
            reference_mid=root["mid"],
        )
        assert reply["reference_mid"] == root["mid"]

    def test_get_thread(self, setup):
        """Get a thread via backend."""
        b = setup["backend"]
        root = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Root")
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            "Reply 1",
            reference_mid=root["mid"],
        )
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            "Reply 2",
            reference_mid=root["mid"],
        )

        thread = b.get_thread(setup["ns"], setup["room_id"], setup["alice"]["secret"], root["mid"])
        assert thread is not None
        assert thread["root"]["mid"] == root["mid"]
        assert thread["reply_count"] == 2
        assert len(thread["replies"]) == 2

    def test_get_thread_not_found(self, setup):
        """Get thread for non-existent message."""
        b = setup["backend"]
        thread = b.get_thread(
            setup["ns"], setup["room_id"], setup["alice"]["secret"], "nonexistent"
        )
        assert thread is None

    def test_get_messages_exclude_replies(self, setup):
        """Filter out replies from room messages."""
        b = setup["backend"]
        b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Top level")
        root = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Root")
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            "Reply",
            reference_mid=root["mid"],
        )

        all_msgs = b.get_room_messages(setup["ns"], setup["room_id"], setup["alice"]["secret"])
        assert len(all_msgs) == 3

        top_only = b.get_room_messages(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            include_replies=False,
        )
        assert len(top_only) == 2
        bodies = [m["body"] for m in top_only]
        assert "Reply" not in bodies

    def test_get_messages_thread_metadata(self, setup):
        """Thread metadata included when filtering replies."""
        b = setup["backend"]
        root = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Root")
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            "Reply",
            reference_mid=root["mid"],
        )

        top_only = b.get_room_messages(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            include_replies=False,
        )
        root_msg = next(m for m in top_only if m["body"] == "Root")
        assert root_msg["reply_count"] == 1
        assert root_msg["last_reply_at"] is not None


class TestDeaddropClientRooms:
    """Test room operations on Deaddrop client."""

    @pytest.fixture
    def client(self):
        """Create in-memory client."""
        return Deaddrop.in_memory()

    @pytest.fixture
    def setup(self, client):
        """Create namespace with two identities."""
        ns = client.create_namespace(display_name="Test NS")
        alice = client.create_identity(ns["ns"], display_name="Alice")
        bob = client.create_identity(ns["ns"], display_name="Bob")
        return {
            "client": client,
            "ns": ns["ns"],
            "ns_secret": ns["secret"],
            "alice": alice,
            "bob": bob,
        }

    def test_create_room(self, setup):
        """Create a room via client."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"], display_name="Test Room")

        assert room["room_id"] is not None
        assert room["display_name"] == "Test Room"

    def test_list_rooms(self, setup):
        """List rooms via client."""
        c = setup["client"]
        c.create_room(setup["ns"], setup["alice"]["secret"])

        rooms = c.list_rooms(setup["ns"], setup["alice"]["secret"])
        assert len(rooms) == 1

    def test_send_and_get_room_messages(self, setup):
        """Send and get room messages via client."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"])
        c.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        # Alice sends
        c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Hello Bob!")

        # Bob sends
        c.send_room_message(setup["ns"], room["room_id"], setup["bob"]["secret"], "Hello Alice!")

        # Both can see all messages
        alice_msgs = c.get_room_messages(setup["ns"], room["room_id"], setup["alice"]["secret"])
        bob_msgs = c.get_room_messages(setup["ns"], room["room_id"], setup["bob"]["secret"])

        assert len(alice_msgs) == 2
        assert len(bob_msgs) == 2

    def test_room_unread_tracking(self, setup):
        """Test per-user unread tracking."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"])
        c.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        # Send messages
        msg1 = c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 1")
        msg2 = c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Msg 2")

        # Both have unread messages
        alice_unread = c.get_room_unread_count(
            setup["ns"], room["room_id"], setup["alice"]["secret"]
        )
        bob_unread = c.get_room_unread_count(setup["ns"], room["room_id"], setup["bob"]["secret"])

        assert alice_unread == 2
        assert bob_unread == 2

        # Alice reads all
        c.update_room_read_cursor(
            setup["ns"], room["room_id"], setup["alice"]["secret"], msg2["mid"]
        )

        # Bob reads first
        c.update_room_read_cursor(setup["ns"], room["room_id"], setup["bob"]["secret"], msg1["mid"])

        alice_unread = c.get_room_unread_count(
            setup["ns"], room["room_id"], setup["alice"]["secret"]
        )
        bob_unread = c.get_room_unread_count(setup["ns"], room["room_id"], setup["bob"]["secret"])

        assert alice_unread == 0
        assert bob_unread == 1

    def test_room_member_workflow(self, setup):
        """Test full member workflow."""
        c = setup["client"]

        # Alice creates room
        room = c.create_room(setup["ns"], setup["alice"]["secret"], display_name="Team Chat")

        # Check members (just Alice)
        members = c.list_room_members(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert len(members) == 1

        # Alice adds Bob
        c.add_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["alice"]["secret"]
        )

        # Both are members
        members = c.list_room_members(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert len(members) == 2

        # Bob leaves
        c.remove_room_member(
            setup["ns"], room["room_id"], setup["bob"]["id"], setup["bob"]["secret"]
        )

        # Only Alice remains
        members = c.list_room_members(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert len(members) == 1

    def test_delete_room_via_client(self, setup):
        """Delete room via client."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"])

        result = c.delete_room(setup["ns"], room["room_id"], setup["ns_secret"])
        assert result is True

        rooms = c.list_rooms(setup["ns"], setup["alice"]["secret"])
        assert len(rooms) == 0

    def test_send_thread_reply(self, setup):
        """Send a thread reply via client."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"])
        root = c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Root")
        reply = c.send_room_message(
            setup["ns"],
            room["room_id"],
            setup["alice"]["secret"],
            "Reply",
            reference_mid=root["mid"],
        )
        assert reply["reference_mid"] == root["mid"]

    def test_get_thread(self, setup):
        """Get a thread via client."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"])
        root = c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Root")
        c.send_room_message(
            setup["ns"],
            room["room_id"],
            setup["alice"]["secret"],
            "Reply",
            reference_mid=root["mid"],
        )

        thread = c.get_thread(setup["ns"], room["room_id"], setup["alice"]["secret"], root["mid"])
        assert thread is not None
        assert thread["root"]["mid"] == root["mid"]
        assert thread["reply_count"] == 1

    def test_get_messages_filter_replies(self, setup):
        """Filter replies from room messages via client."""
        c = setup["client"]
        room = c.create_room(setup["ns"], setup["alice"]["secret"])
        c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Top")
        root = c.send_room_message(setup["ns"], room["room_id"], setup["alice"]["secret"], "Root")
        c.send_room_message(
            setup["ns"],
            room["room_id"],
            setup["alice"]["secret"],
            "Reply",
            reference_mid=root["mid"],
        )

        all_msgs = c.get_room_messages(setup["ns"], room["room_id"], setup["alice"]["secret"])
        assert len(all_msgs) == 3

        top_only = c.get_room_messages(
            setup["ns"],
            room["room_id"],
            setup["alice"]["secret"],
            include_replies=False,
        )
        assert len(top_only) == 2
