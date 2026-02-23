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


class TestReactions:
    """Test reactions through the backend and client SDK."""

    @pytest.fixture
    def backend(self):
        """Create in-memory backend."""
        return InMemoryBackend()

    @pytest.fixture
    def setup(self, backend):
        """Create namespace, two identities, and a room with both as members."""
        ns = backend.create_namespace(display_name="Test NS")
        alice = backend.create_identity(ns["ns"], display_name="Alice")
        bob = backend.create_identity(ns["ns"], display_name="Bob")
        room = backend.create_room(ns["ns"], alice["secret"], display_name="Chat")
        backend.add_room_member(ns["ns"], room["room_id"], bob["id"], alice["secret"])
        return {
            "backend": backend,
            "ns": ns["ns"],
            "ns_secret": ns["secret"],
            "alice": alice,
            "bob": bob,
            "room_id": room["room_id"],
        }

    def test_send_reaction(self, setup):
        """Send a reaction to a message."""
        b = setup["backend"]
        msg = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Hello!")

        reaction = b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["bob"]["secret"],
            body="👍",
            content_type="reaction",
            reference_mid=msg["mid"],
        )

        assert reaction["body"] == "👍"
        assert reaction["content_type"] == "reaction"
        assert reaction["reference_mid"] == msg["mid"]

    def test_reactions_appear_in_messages(self, setup):
        """Reactions appear in the message stream with reference_mid."""
        b = setup["backend"]
        msg = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Hello!")
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["bob"]["secret"],
            body="👍",
            content_type="reaction",
            reference_mid=msg["mid"],
        )

        messages = b.get_room_messages(setup["ns"], setup["room_id"], setup["alice"]["secret"])

        # Should have 2 messages: the original + the reaction
        assert len(messages) == 2

        regular = [m for m in messages if m.get("content_type") != "reaction"]
        reactions = [m for m in messages if m.get("content_type") == "reaction"]

        assert len(regular) == 1
        assert len(reactions) == 1
        assert reactions[0]["reference_mid"] == msg["mid"]
        assert reactions[0]["body"] == "👍"

    def test_multiple_reactions_on_same_message(self, setup):
        """Multiple users can react to the same message."""
        b = setup["backend"]
        msg = b.send_room_message(
            setup["ns"], setup["room_id"], setup["alice"]["secret"], "Great idea!"
        )

        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["alice"]["secret"],
            body="👍",
            content_type="reaction",
            reference_mid=msg["mid"],
        )
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["bob"]["secret"],
            body="❤️",
            content_type="reaction",
            reference_mid=msg["mid"],
        )

        messages = b.get_room_messages(setup["ns"], setup["room_id"], setup["alice"]["secret"])
        reactions = [m for m in messages if m.get("content_type") == "reaction"]
        assert len(reactions) == 2
        assert all(r["reference_mid"] == msg["mid"] for r in reactions)

    def test_reference_mid_in_message_response(self, setup):
        """reference_mid is returned in message dicts (not silently dropped)."""
        b = setup["backend"]
        msg = b.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Test")

        # Regular messages have reference_mid=None
        messages = b.get_room_messages(setup["ns"], setup["room_id"], setup["alice"]["secret"])
        assert messages[0].get("reference_mid") is None

        # Reactions have reference_mid set
        b.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["bob"]["secret"],
            body="🎉",
            content_type="reaction",
            reference_mid=msg["mid"],
        )
        messages = b.get_room_messages(setup["ns"], setup["room_id"], setup["alice"]["secret"])
        reaction = [m for m in messages if m.get("content_type") == "reaction"][0]
        assert reaction["reference_mid"] == msg["mid"]


class TestReactionsClient:
    """Test reactions through the Deaddrop client (high-level SDK)."""

    @pytest.fixture
    def setup(self):
        """Create client with namespace, identities, and a room."""
        client = Deaddrop.in_memory()
        ns = client.create_namespace(display_name="Test NS")
        alice = client.create_identity(ns["ns"], display_name="Alice")
        bob = client.create_identity(ns["ns"], display_name="Bob")
        room = client.create_room(ns["ns"], alice["secret"], display_name="Chat")
        client.add_room_member(ns["ns"], room["room_id"], bob["id"], alice["secret"])
        return {
            "client": client,
            "ns": ns["ns"],
            "alice": alice,
            "bob": bob,
            "room_id": room["room_id"],
        }

    def test_send_reaction_via_client(self, setup):
        """Send a reaction using the Deaddrop client."""
        c = setup["client"]
        msg = c.send_room_message(setup["ns"], setup["room_id"], setup["alice"]["secret"], "Hello!")

        reaction = c.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["bob"]["secret"],
            body="👍",
            content_type="reaction",
            reference_mid=msg["mid"],
        )

        assert reaction["content_type"] == "reaction"
        assert reaction["reference_mid"] == msg["mid"]
        assert reaction["body"] == "👍"

    def test_reaction_roundtrip(self, setup):
        """Send a reaction and read it back — full roundtrip."""
        c = setup["client"]

        # Alice sends a message
        msg = c.send_room_message(
            setup["ns"], setup["room_id"], setup["alice"]["secret"], "What do you think?"
        )

        # Bob reacts
        c.send_room_message(
            setup["ns"],
            setup["room_id"],
            setup["bob"]["secret"],
            body="👍",
            content_type="reaction",
            reference_mid=msg["mid"],
        )

        # Both can read the reaction
        messages = c.get_room_messages(setup["ns"], setup["room_id"], setup["alice"]["secret"])
        reactions = [m for m in messages if m.get("content_type") == "reaction"]
        assert len(reactions) == 1
        assert reactions[0]["reference_mid"] == msg["mid"]
        assert reactions[0]["from"] == setup["bob"]["id"]


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
