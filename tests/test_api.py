"""Tests for deadrop API."""

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app


@pytest.fixture
def client():
    """Create test client."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def admin_headers():
    """Admin auth headers."""
    return {"X-Admin-Token": "test-admin-token"}


class TestHealth:
    def test_health_check(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestNamespaces:
    def test_create_namespace(self, client, admin_headers):
        response = client.post(
            "/admin/namespaces",
            json={"metadata": {"display_name": "Test Namespace"}},
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "ns" in data
        assert "secret" in data
        assert len(data["ns"]) == 16  # hash-derived ID
        assert len(data["secret"]) == 64  # full secret
        assert data["metadata"] == {"display_name": "Test Namespace"}
        assert data["ttl_hours"] == 24  # default

    def test_create_namespace_with_custom_ttl(self, client, admin_headers):
        response = client.post(
            "/admin/namespaces",
            json={"metadata": {"display_name": "Short TTL"}, "ttl_hours": 1},
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["ttl_hours"] == 1

    def test_create_namespace_requires_admin(self, client):
        response = client.post("/admin/namespaces", json={})
        assert response.status_code == 401

    def test_create_namespace_no_auth_mode(self, client):
        """In no-auth mode, admin endpoints don't require authentication."""
        import os

        # Enable no-auth mode
        os.environ["DEADROP_NO_AUTH"] = "1"
        try:
            response = client.post(
                "/admin/namespaces",
                json={"metadata": {"display_name": "No Auth Test"}},
                # No auth headers!
            )
            assert response.status_code == 200
            data = response.json()
            assert data["metadata"]["display_name"] == "No Auth Test"
        finally:
            # Clean up
            os.environ.pop("DEADROP_NO_AUTH", None)

    def test_list_namespaces(self, client, admin_headers):
        # Create two namespaces
        client.post(
            "/admin/namespaces", json={"metadata": {"display_name": "NS1"}}, headers=admin_headers
        )
        client.post(
            "/admin/namespaces", json={"metadata": {"display_name": "NS2"}}, headers=admin_headers
        )

        response = client.get("/admin/namespaces", headers=admin_headers)
        assert response.status_code == 200
        namespaces = response.json()
        assert len(namespaces) == 2
        assert namespaces[0]["metadata"]["display_name"] == "NS1"
        assert namespaces[1]["metadata"]["display_name"] == "NS2"

    def test_delete_namespace(self, client, admin_headers):
        # Create namespace
        response = client.post("/admin/namespaces", json={}, headers=admin_headers)
        ns = response.json()["ns"]

        # Delete it
        response = client.delete(f"/admin/namespaces/{ns}", headers=admin_headers)
        assert response.status_code == 200

        # Verify gone
        response = client.get("/admin/namespaces", headers=admin_headers)
        assert len(response.json()) == 0

    def test_archive_namespace(self, client, admin_headers):
        # Create namespace
        response = client.post("/admin/namespaces", json={}, headers=admin_headers)
        ns = response.json()["ns"]
        ns_secret = response.json()["secret"]

        # Create an identity first
        response = client.post(
            f"/{ns}/identities",
            json={"metadata": {"display_name": "Agent 1"}},
            headers={"X-Namespace-Secret": ns_secret},
        )
        assert response.status_code == 200

        # Archive the namespace
        response = client.post(
            f"/{ns}/archive",
            headers={"X-Namespace-Secret": ns_secret},
        )
        assert response.status_code == 200

        # Verify can't create new identities
        response = client.post(
            f"/{ns}/identities",
            json={},
            headers={"X-Namespace-Secret": ns_secret},
        )
        assert response.status_code == 410  # Gone


class TestIdentities:
    @pytest.fixture
    def namespace(self, client, admin_headers):
        """Create a namespace and return ns + secret."""
        response = client.post(
            "/admin/namespaces",
            json={"metadata": {"display_name": "Test"}},
            headers=admin_headers,
        )
        data = response.json()
        return {"ns": data["ns"], "secret": data["secret"]}

    def test_create_identity(self, client, namespace):
        response = client.post(
            f"/{namespace['ns']}/identities",
            json={"metadata": {"display_name": "Agent 1", "role": "worker"}},
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert "secret" in data
        assert len(data["id"]) == 16  # hash-derived
        assert len(data["secret"]) == 64
        assert data["metadata"]["display_name"] == "Agent 1"

    def test_create_identity_requires_namespace_secret(self, client, namespace):
        response = client.post(
            f"/{namespace['ns']}/identities",
            json={},
        )
        assert response.status_code == 401

    def test_list_identities_as_namespace_owner(self, client, namespace):
        # Create identities
        client.post(
            f"/{namespace['ns']}/identities",
            json={"metadata": {"display_name": "Agent 1"}},
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        client.post(
            f"/{namespace['ns']}/identities",
            json={"metadata": {"display_name": "Agent 2"}},
            headers={"X-Namespace-Secret": namespace["secret"]},
        )

        # List as namespace owner
        response = client.get(
            f"/{namespace['ns']}/identities",
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        assert response.status_code == 200
        identities = response.json()
        assert len(identities) == 2

    def test_list_identities_as_mailbox_owner(self, client, namespace):
        # Create identities
        r1 = client.post(
            f"/{namespace['ns']}/identities",
            json={"metadata": {"display_name": "Agent 1"}},
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        agent1_secret = r1.json()["secret"]

        client.post(
            f"/{namespace['ns']}/identities",
            json={"metadata": {"display_name": "Agent 2"}},
            headers={"X-Namespace-Secret": namespace["secret"]},
        )

        # List as mailbox owner (Agent 1 can see Agent 2)
        response = client.get(
            f"/{namespace['ns']}/identities",
            headers={"X-Inbox-Secret": agent1_secret},
        )
        assert response.status_code == 200
        identities = response.json()
        assert len(identities) == 2

    def test_delete_identity(self, client, namespace):
        # Create identity
        response = client.post(
            f"/{namespace['ns']}/identities",
            json={},
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        identity_id = response.json()["id"]

        # Delete it
        response = client.delete(
            f"/{namespace['ns']}/identities/{identity_id}",
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        assert response.status_code == 200

        # Verify gone
        response = client.get(
            f"/{namespace['ns']}/identities",
            headers={"X-Namespace-Secret": namespace["secret"]},
        )
        assert len(response.json()) == 0


class TestMessaging:
    @pytest.fixture
    def setup_agents(self, client, admin_headers):
        """Create namespace with two agents."""
        # Create namespace
        ns_response = client.post(
            "/admin/namespaces",
            json={"metadata": {"display_name": "Test"}},
            headers=admin_headers,
        )
        ns_data = ns_response.json()

        # Create two agents
        a1_response = client.post(
            f"/{ns_data['ns']}/identities",
            json={"metadata": {"display_name": "Agent 1"}},
            headers={"X-Namespace-Secret": ns_data["secret"]},
        )
        a1_data = a1_response.json()

        a2_response = client.post(
            f"/{ns_data['ns']}/identities",
            json={"metadata": {"display_name": "Agent 2"}},
            headers={"X-Namespace-Secret": ns_data["secret"]},
        )
        a2_data = a2_response.json()

        return {
            "ns": ns_data["ns"],
            "ns_secret": ns_data["secret"],
            "agent1": {"id": a1_data["id"], "secret": a1_data["secret"]},
            "agent2": {"id": a2_data["id"], "secret": a2_data["secret"]},
        }

    def test_send_and_receive_message(self, client, setup_agents):
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Agent 1 sends to Agent 2
        response = client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Hello Agent 2!"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        assert response.status_code == 200
        assert response.json()["from"] == agent1["id"]
        assert response.json()["to"] == agent2["id"]

        # Verify mid is UUIDv7 format (starts with timestamp-like chars)
        mid = response.json()["mid"]
        assert len(mid) == 36  # UUID format

        # Agent 2 reads inbox
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        assert response.status_code == 200
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["body"] == "Hello Agent 2!"
        assert messages[0]["from"] == agent1["id"]
        assert messages[0]["read_at"] is not None  # Marked as read
        assert messages[0]["expires_at"] is not None  # TTL started

    def test_cannot_read_others_inbox(self, client, setup_agents):
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Agent 1 tries to read Agent 2's inbox
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        assert response.status_code == 403

    def test_namespace_owner_cannot_read_inbox(self, client, setup_agents):
        """Namespace owner has no access to message contents."""
        ns = setup_agents["ns"]
        ns_secret = setup_agents["ns_secret"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Agent 1 sends to Agent 2
        client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Secret message"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )

        # Namespace owner tries to read Agent 2's inbox - should fail
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Namespace-Secret": ns_secret},
        )
        assert response.status_code == 401  # No inbox secret provided

    def test_reading_starts_ttl(self, client, setup_agents):
        """Reading a message marks it as read and sets expiration."""
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Send message
        client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Test"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )

        # Message should have no read_at or expires_at yet
        # (We can't check this without peeking, but we trust the DB)

        # Read inbox - this marks as read and starts TTL
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["read_at"] is not None
        assert messages[0]["expires_at"] is not None

    def test_immediate_delete(self, client, setup_agents):
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Send message
        send_response = client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Test"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        mid = send_response.json()["mid"]

        # Read it first
        client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )

        # Delete immediately
        response = client.delete(
            f"/{ns}/inbox/{agent2['id']}/{mid}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        assert response.status_code == 200

        # Verify gone
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}/{mid}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        assert response.status_code == 404

    def test_unread_filter(self, client, setup_agents):
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Send two messages
        client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Message 1"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Message 2"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )

        # Read all (marks as read)
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        assert len(response.json()["messages"]) == 2

        # Send another
        client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Message 3"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )

        # Get only unread
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}?unread=true",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["body"] == "Message 3"

    def test_after_cursor(self, client, setup_agents):
        """Test pagination with after cursor."""
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Send three messages
        mids = []
        for i in range(3):
            response = client.post(
                f"/{ns}/send",
                json={"to": agent2["id"], "body": f"Message {i + 1}"},
                headers={"X-Inbox-Secret": agent1["secret"]},
            )
            mids.append(response.json()["mid"])

        # Get all
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        assert len(response.json()["messages"]) == 3

        # Get messages after the first one
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}?after={mids[0]}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        messages = response.json()["messages"]
        assert len(messages) == 2
        assert messages[0]["body"] == "Message 2"
        assert messages[1]["body"] == "Message 3"

        # Get messages after the second one
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}?after={mids[1]}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["body"] == "Message 3"

    def test_cannot_send_to_archived_namespace(self, client, setup_agents):
        ns = setup_agents["ns"]
        ns_secret = setup_agents["ns_secret"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Archive the namespace
        client.post(f"/{ns}/archive", headers={"X-Namespace-Secret": ns_secret})

        # Try to send - should fail
        response = client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Should fail"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        assert response.status_code == 410  # Gone

    def test_send_message_to_self(self, client, setup_agents):
        """Inbox owner can send messages to themselves."""
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]

        # Agent 1 sends to themselves
        response = client.post(
            f"/{ns}/send",
            json={"to": agent1["id"], "body": "Note to self"},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        assert response.status_code == 200
        assert response.json()["from"] == agent1["id"]
        assert response.json()["to"] == agent1["id"]

        # Agent 1 reads their own inbox and sees the self-sent message
        response = client.get(
            f"/{ns}/inbox/{agent1['id']}",
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        assert response.status_code == 200
        messages = response.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["from"] == agent1["id"]
        assert messages[0]["to"] == agent1["id"]
        assert messages[0]["body"] == "Note to self"

    def test_ephemeral_message_with_ttl(self, client, setup_agents):
        """Sender can set TTL for ephemeral messages."""
        ns = setup_agents["ns"]
        agent1 = setup_agents["agent1"]
        agent2 = setup_agents["agent2"]

        # Send ephemeral message with 1 hour TTL
        response = client.post(
            f"/{ns}/send",
            json={"to": agent2["id"], "body": "Ephemeral!", "ttl_hours": 1},
            headers={"X-Inbox-Secret": agent1["secret"]},
        )
        assert response.status_code == 200

        # Check it has expiration set from creation (not read time)
        response = client.get(
            f"/{ns}/inbox/{agent2['id']}",
            headers={"X-Inbox-Secret": agent2["secret"]},
        )
        messages = response.json()["messages"]
        assert len(messages) == 1
        # expires_at should be set even though we just read it
        assert messages[0]["expires_at"] is not None
