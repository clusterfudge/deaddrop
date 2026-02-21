"""Tests for room API endpoints."""

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def admin_headers():
    """Admin auth headers."""
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def setup_namespace(client, admin_headers):
    """Create a namespace and return its info."""
    response = client.post("/admin/namespaces", headers=admin_headers)
    return response.json()


@pytest.fixture
def setup_identities(client, setup_namespace):
    """Create namespace with two identities."""
    ns = setup_namespace
    ns_secret = ns["secret"]

    alice = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Alice"}},
    ).json()

    bob = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Bob"}},
    ).json()

    return {
        "ns": ns["ns"],
        "ns_secret": ns_secret,
        "alice": alice,
        "bob": bob,
    }


class TestRoomCreation:
    """Tests for room creation endpoint."""

    def test_create_room(self, client, setup_identities):
        """Create a room successfully."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Test Room"},
        )

        assert response.status_code == 200
        room = response.json()
        assert room["room_id"] is not None
        assert room["display_name"] == "Test Room"
        assert room["created_by"] == data["alice"]["id"]
        assert room["ns"] == data["ns"]

    def test_create_room_no_display_name(self, client, setup_identities):
        """Create a room without display name."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200
        room = response.json()
        assert room["display_name"] is None

    def test_create_room_unauthorized(self, client, setup_identities):
        """Creating room without auth fails."""
        data = setup_identities
        response = client.post(f"/{data['ns']}/rooms")

        assert response.status_code == 401

    def test_create_room_wrong_namespace(self, client, admin_headers, setup_identities):
        """Cannot create room with identity from different namespace."""
        data = setup_identities

        # Create a second namespace
        ns2 = client.post("/admin/namespaces", headers=admin_headers).json()

        # Try to create room in ns2 with alice's secret (from ns1)
        response = client.post(
            f"/{ns2['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 403


class TestRoomListing:
    """Tests for room listing endpoints."""

    def test_list_my_rooms(self, client, setup_identities):
        """List rooms I'm a member of."""
        data = setup_identities

        # Create two rooms - Alice creates both
        room1 = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Room 1"},
        ).json()

        room2 = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Room 2"},
        ).json()

        # Alice should see both
        response = client.get(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200
        rooms = response.json()
        assert len(rooms) == 2
        room_ids = {r["room_id"] for r in rooms}
        assert room1["room_id"] in room_ids
        assert room2["room_id"] in room_ids

    def test_list_my_rooms_only_joined(self, client, setup_identities):
        """Only see rooms I've joined."""
        data = setup_identities

        # Alice creates a room (auto-joins)
        client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Alice's Room"},
        )

        # Bob lists rooms (should be empty - not a member)
        response = client.get(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.status_code == 200
        rooms = response.json()
        assert len(rooms) == 0

    def test_get_room(self, client, setup_identities):
        """Get room details."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Test Room"},
        ).json()

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200
        fetched = response.json()
        assert fetched["room_id"] == room["room_id"]
        assert fetched["display_name"] == "Test Room"

    def test_get_room_not_member(self, client, setup_identities):
        """Cannot get room if not a member."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Bob tries to get room details
        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.status_code == 403


class TestRoomMembers:
    """Tests for room member management."""

    def test_list_room_members(self, client, setup_identities):
        """List members of a room."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200
        members = response.json()
        assert len(members) == 1
        assert members[0]["identity_id"] == data["alice"]["id"]

    def test_add_room_member(self, client, setup_identities):
        """Add a member to a room."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Alice adds Bob
        response = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        assert response.status_code == 200
        member = response.json()
        assert member["identity_id"] == data["bob"]["id"]

        # Verify Bob is now a member
        members = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()
        assert len(members) == 2

    def test_add_member_not_authorized(self, client, setup_identities):
        """Non-member cannot add members."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Bob (not a member) tries to add himself
        response = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        assert response.status_code == 403

    def test_remove_room_member(self, client, setup_identities):
        """Remove a member from a room."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Add Bob
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        # Remove Bob
        response = client.delete(
            f"/{data['ns']}/rooms/{room['room_id']}/members/{data['bob']['id']}",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200

        # Verify Bob is no longer a member
        members = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()
        assert len(members) == 1

    def test_leave_room(self, client, setup_identities):
        """Member can remove themselves."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Add Bob
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        # Bob leaves
        response = client.delete(
            f"/{data['ns']}/rooms/{room['room_id']}/members/{data['bob']['id']}",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.status_code == 200


class TestRoomMessages:
    """Tests for room messaging."""

    def test_send_room_message(self, client, setup_identities):
        """Send a message to a room."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        response = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Hello, room!"},
        )

        assert response.status_code == 200
        msg = response.json()
        assert msg["body"] == "Hello, room!"
        assert msg["from_id"] == data["alice"]["id"]
        assert msg["room_id"] == room["room_id"]

    def test_send_message_not_member(self, client, setup_identities):
        """Non-member cannot send messages."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        response = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={"body": "Hello!"},
        )

        assert response.status_code == 403

    def test_get_room_messages(self, client, setup_identities):
        """Get messages from a room."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Send some messages
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 1"},
        )
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 2"},
        )

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200
        result = response.json()
        assert len(result["messages"]) == 2
        assert result["messages"][0]["body"] == "Message 1"
        assert result["messages"][1]["body"] == "Message 2"

    def test_get_messages_after(self, client, setup_identities):
        """Get messages after a specific message ID."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Send messages
        msg1 = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 1"},
        ).json()

        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 2"},
        )

        # Get messages after first one
        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            params={"after": msg1["mid"]},
        )

        assert response.status_code == 200
        result = response.json()
        assert len(result["messages"]) == 1
        assert result["messages"][0]["body"] == "Message 2"

    def test_get_messages_with_limit(self, client, setup_identities):
        """Get messages with a limit."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Send 5 messages
        for i in range(5):
            client.post(
                f"/{data['ns']}/rooms/{room['room_id']}/messages",
                headers={"X-Inbox-Secret": data["alice"]["secret"]},
                json={"body": f"Message {i}"},
            )

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            params={"limit": 3},
        )

        assert response.status_code == 200
        result = response.json()
        assert len(result["messages"]) == 3

    def test_get_messages_not_member(self, client, setup_identities):
        """Non-member cannot get messages."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.status_code == 403


class TestRoomReadTracking:
    """Tests for read cursor tracking."""

    def test_update_read_cursor(self, client, setup_identities):
        """Update read cursor."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        msg = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Hello"},
        ).json()

        response = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/read",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"last_read_mid": msg["mid"]},
        )

        assert response.status_code == 200
        result = response.json()
        assert result["ok"] is True
        assert result["last_read_mid"] == msg["mid"]

    def test_get_unread_count(self, client, setup_identities):
        """Get unread message count."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Add Bob
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        # Alice sends messages
        msg1 = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 1"},
        ).json()

        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 2"},
        )

        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 3"},
        )

        # Bob's unread count
        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/unread",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.status_code == 200
        assert response.json()["unread_count"] == 3

        # Bob reads first message
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/read",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={"last_read_mid": msg1["mid"]},
        )

        # Bob's unread count should be 2
        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/unread",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.json()["unread_count"] == 2


class TestRoomThreading:
    """Tests for thread API endpoints."""

    def _create_room(self, client, data):
        """Helper to create a room."""
        return client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Test Room"},
        ).json()

    def _send_msg(self, client, data, room_id, body, reference_mid=None):
        """Helper to send a message."""
        payload = {"body": body}
        if reference_mid:
            payload["reference_mid"] = reference_mid
        return client.post(
            f"/{data['ns']}/rooms/{room_id}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json=payload,
        ).json()

    def test_send_thread_reply(self, client, setup_identities):
        """Send a reply via API sets reference_mid."""
        data = setup_identities
        room = self._create_room(client, data)
        root = self._send_msg(client, data, room["room_id"], "Root message")
        reply = self._send_msg(client, data, room["room_id"], "Reply", reference_mid=root["mid"])

        assert reply["reference_mid"] == root["mid"]

    def test_send_reply_to_reply_redirects(self, client, setup_identities):
        """Replying to a reply redirects to root (flat threading)."""
        data = setup_identities
        room = self._create_room(client, data)
        root = self._send_msg(client, data, room["room_id"], "Root")
        reply1 = self._send_msg(client, data, room["room_id"], "Reply 1", reference_mid=root["mid"])
        reply2 = self._send_msg(
            client, data, room["room_id"], "Reply 2", reference_mid=reply1["mid"]
        )

        assert reply2["reference_mid"] == root["mid"]

    def test_get_thread(self, client, setup_identities):
        """GET thread endpoint returns root + replies."""
        data = setup_identities
        room = self._create_room(client, data)
        root = self._send_msg(client, data, room["room_id"], "Root message")
        self._send_msg(client, data, room["room_id"], "Reply 1", reference_mid=root["mid"])
        self._send_msg(client, data, room["room_id"], "Reply 2", reference_mid=root["mid"])

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/threads/{root['mid']}",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 200
        thread = response.json()
        assert thread["root"]["mid"] == root["mid"]
        assert thread["reply_count"] == 2
        assert len(thread["replies"]) == 2
        assert thread["replies"][0]["body"] == "Reply 1"
        assert thread["replies"][1]["body"] == "Reply 2"

    def test_get_thread_not_found(self, client, setup_identities):
        """GET thread for non-existent root returns 404."""
        data = setup_identities
        room = self._create_room(client, data)

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/threads/nonexistent-mid",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 404

    def test_get_thread_not_member(self, client, setup_identities):
        """Non-member cannot get thread."""
        data = setup_identities
        room = self._create_room(client, data)
        root = self._send_msg(client, data, room["room_id"], "Root")

        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/threads/{root['mid']}",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        )

        assert response.status_code == 403

    def test_get_messages_exclude_replies(self, client, setup_identities):
        """include_replies=false filters out thread replies."""
        data = setup_identities
        room = self._create_room(client, data)
        self._send_msg(client, data, room["room_id"], "Top level 1")
        root = self._send_msg(client, data, room["room_id"], "Thread root")
        self._send_msg(client, data, room["room_id"], "Reply", reference_mid=root["mid"])
        self._send_msg(client, data, room["room_id"], "Top level 2")

        # With replies
        all_resp = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )
        assert len(all_resp.json()["messages"]) == 4

        # Without replies
        top_resp = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            params={"include_replies": "false"},
        )
        messages = top_resp.json()["messages"]
        assert len(messages) == 3
        bodies = [m["body"] for m in messages]
        assert "Reply" not in bodies

    def test_get_messages_thread_metadata(self, client, setup_identities):
        """include_replies=false includes reply_count and last_reply_at."""
        data = setup_identities
        room = self._create_room(client, data)
        self._send_msg(client, data, room["room_id"], "No thread")
        root = self._send_msg(client, data, room["room_id"], "Has thread")
        self._send_msg(client, data, room["room_id"], "Reply 1", reference_mid=root["mid"])
        self._send_msg(client, data, room["room_id"], "Reply 2", reference_mid=root["mid"])

        resp = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            params={"include_replies": "false"},
        )
        messages = resp.json()["messages"]

        no_thread = next(m for m in messages if m["body"] == "No thread")
        has_thread = next(m for m in messages if m["body"] == "Has thread")

        assert no_thread["reply_count"] == 0
        assert no_thread["last_reply_at"] is None
        assert has_thread["reply_count"] == 2
        assert has_thread["last_reply_at"] is not None

    def test_message_response_has_reply_count_field(self, client, setup_identities):
        """All message responses include reply_count field (default 0)."""
        data = setup_identities
        room = self._create_room(client, data)
        msg = self._send_msg(client, data, room["room_id"], "Hello")

        assert "reply_count" in msg
        assert msg["reply_count"] == 0


class TestRoomDeletion:
    """Tests for room deletion."""

    def test_delete_room(self, client, setup_identities):
        """Namespace owner can delete a room."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Delete with namespace secret
        response = client.delete(
            f"/{data['ns']}/rooms/{room['room_id']}",
            headers={"X-Namespace-Secret": data["ns_secret"]},
        )

        assert response.status_code == 200

        # Room should be gone
        response = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )
        assert response.status_code == 404

    def test_delete_room_unauthorized(self, client, setup_identities):
        """Non-namespace-owner cannot delete rooms."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Try to delete with inbox secret (not authorized)
        response = client.delete(
            f"/{data['ns']}/rooms/{room['room_id']}",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        )

        assert response.status_code == 401


class TestRoomMultiUser:
    """Tests for multi-user scenarios."""

    def test_multiple_users_can_message(self, client, setup_identities):
        """Multiple users can send and receive messages."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Add Bob
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        # Both send messages
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Hello from Alice"},
        )

        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={"body": "Hello from Bob"},
        )

        # Both can read all messages
        alice_msgs = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()["messages"]

        bob_msgs = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        ).json()["messages"]

        assert len(alice_msgs) == 2
        assert len(bob_msgs) == 2
        assert alice_msgs == bob_msgs

    def test_independent_read_cursors(self, client, setup_identities):
        """Each user has independent read tracking."""
        data = setup_identities

        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()

        # Add Bob
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"identity_id": data["bob"]["id"]},
        )

        # Send messages
        msg1 = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 1"},
        ).json()

        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 2"},
        )

        msg3 = client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Message 3"},
        ).json()

        # Alice reads all
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/read",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"last_read_mid": msg3["mid"]},
        )

        # Bob reads first
        client.post(
            f"/{data['ns']}/rooms/{room['room_id']}/read",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={"last_read_mid": msg1["mid"]},
        )

        # Check unread counts
        alice_unread = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/unread",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
        ).json()["unread_count"]

        bob_unread = client.get(
            f"/{data['ns']}/rooms/{room['room_id']}/unread",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
        ).json()["unread_count"]

        assert alice_unread == 0
        assert bob_unread == 2
