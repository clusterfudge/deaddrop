"""Tests for room encryption API endpoints."""

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app
from deadrop.crypto import bytes_to_base64url, generate_keypair


ADMIN_HEADERS = {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def setup_encrypted_room(client):
    """Create an encrypted room with an identity that has a pubkey."""
    # Create namespace
    resp = client.post("/admin/namespaces", headers=ADMIN_HEADERS)
    ns_data = resp.json()
    ns = ns_data["ns"]
    ns_secret = ns_data["secret"]

    # Create identity
    resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
    identity = resp.json()
    inbox_secret = identity["secret"]

    # Register pubkey for creator
    kp = generate_keypair()
    client.put(
        f"/{ns}/inbox/{identity['id']}/pubkey",
        json={
            "public_key": bytes_to_base64url(kp.public_key),
            "signing_public_key": bytes_to_base64url(kp.signing_public_key),
        },
        headers={"X-Inbox-Secret": inbox_secret},
    )

    # Create encrypted room
    resp = client.post(
        f"/{ns}/rooms",
        json={"display_name": "Encrypted Room", "encryption_enabled": True},
        headers={"X-Inbox-Secret": inbox_secret},
    )
    room = resp.json()

    return {
        "ns": ns,
        "ns_secret": ns_secret,
        "identity": identity,
        "inbox_secret": inbox_secret,
        "keypair": kp,
        "room": room,
    }


class TestCreateEncryptedRoom:
    """Tests for creating encrypted rooms."""

    def test_create_encrypted_room(self, client):
        """Create room with encryption enabled."""
        # Create namespace
        resp = client.post("/admin/namespaces", headers=ADMIN_HEADERS)
        ns = resp.json()["ns"]
        ns_secret = resp.json()["secret"]

        # Create identity
        resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
        identity = resp.json()

        # Register pubkey (required for encrypted room)
        kp = generate_keypair()
        client.put(
            f"/{ns}/inbox/{identity['id']}/pubkey",
            json={
                "public_key": bytes_to_base64url(kp.public_key),
                "signing_public_key": bytes_to_base64url(kp.signing_public_key),
            },
            headers={"X-Inbox-Secret": identity["secret"]},
        )

        # Create encrypted room
        resp = client.post(
            f"/{ns}/rooms",
            json={"display_name": "Secret Room", "encryption_enabled": True},
            headers={"X-Inbox-Secret": identity["secret"]},
        )

        assert resp.status_code == 200
        room = resp.json()
        assert room["encryption_enabled"] is True
        assert room["current_epoch_number"] == 0

    def test_create_encrypted_room_without_pubkey_fails(self, client):
        """Creating encrypted room without pubkey fails."""
        # Create namespace
        resp = client.post("/admin/namespaces", headers=ADMIN_HEADERS)
        ns = resp.json()["ns"]
        ns_secret = resp.json()["secret"]

        # Create identity (no pubkey)
        resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
        identity = resp.json()

        # Try to create encrypted room
        resp = client.post(
            f"/{ns}/rooms",
            json={"encryption_enabled": True},
            headers={"X-Inbox-Secret": identity["secret"]},
        )

        assert resp.status_code == 400
        assert "pubkey" in resp.json()["detail"].lower()

    def test_create_unencrypted_room_default(self, client):
        """Rooms are unencrypted by default."""
        # Create namespace
        resp = client.post("/admin/namespaces", headers=ADMIN_HEADERS)
        ns = resp.json()["ns"]
        ns_secret = resp.json()["secret"]

        # Create identity
        resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
        identity = resp.json()

        # Create room (no encryption flag)
        resp = client.post(
            f"/{ns}/rooms",
            headers={"X-Inbox-Secret": identity["secret"]},
        )

        assert resp.status_code == 200
        room = resp.json()
        assert room["encryption_enabled"] is False


class TestEpochEndpoints:
    """Tests for epoch API endpoints."""

    def test_get_current_epoch(self, client, setup_encrypted_room):
        """Get current epoch for encrypted room."""
        data = setup_encrypted_room

        resp = client.get(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/epoch",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        result = resp.json()
        assert result["epoch"]["epoch_number"] == 0
        assert result["epoch"]["reason"] == "created"
        assert result["encrypted_epoch_key"] is not None

    def test_get_epoch_by_number(self, client, setup_encrypted_room):
        """Get specific epoch by number."""
        data = setup_encrypted_room

        resp = client.get(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/epoch/0",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        result = resp.json()
        assert result["epoch"]["epoch_number"] == 0
        assert result["encrypted_epoch_key"] is not None

    def test_get_epoch_not_found(self, client, setup_encrypted_room):
        """Get nonexistent epoch returns 404."""
        data = setup_encrypted_room

        resp = client.get(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/epoch/999",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 404

    def test_get_epoch_unencrypted_room_fails(self, client):
        """Get epoch on unencrypted room fails."""
        # Create namespace and identity
        resp = client.post("/admin/namespaces", headers=ADMIN_HEADERS)
        ns = resp.json()["ns"]
        ns_secret = resp.json()["secret"]

        resp = client.post(f"/{ns}/identities", headers={"X-Namespace-Secret": ns_secret})
        identity = resp.json()

        # Create unencrypted room
        resp = client.post(
            f"/{ns}/rooms",
            headers={"X-Inbox-Secret": identity["secret"]},
        )
        room = resp.json()

        # Try to get epoch
        resp = client.get(
            f"/{ns}/rooms/{room['room_id']}/epoch",
            headers={"X-Inbox-Secret": identity["secret"]},
        )

        assert resp.status_code == 400
        assert "encryption" in resp.json()["detail"].lower()

    def test_manual_rotation(self, client, setup_encrypted_room):
        """Room creator can trigger manual rotation."""
        data = setup_encrypted_room

        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/rotate",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        result = resp.json()
        assert result["epoch"]["epoch_number"] == 1
        assert result["epoch"]["reason"] == "manual"
        assert result["encrypted_epoch_key"] is not None

    def test_manual_rotation_non_creator_fails(self, client, setup_encrypted_room):
        """Non-creator cannot trigger manual rotation."""
        data = setup_encrypted_room

        # Create second identity with pubkey
        resp = client.post(
            f"/{data['ns']}/identities",
            headers={"X-Namespace-Secret": data["ns_secret"]},
        )
        bob = resp.json()

        bob_kp = generate_keypair()
        client.put(
            f"/{data['ns']}/inbox/{bob['id']}/pubkey",
            json={
                "public_key": bytes_to_base64url(bob_kp.public_key),
                "signing_public_key": bytes_to_base64url(bob_kp.signing_public_key),
            },
            headers={"X-Inbox-Secret": bob["secret"]},
        )

        # Add Bob to room
        client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/members",
            json={"identity_id": bob["id"]},
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        # Bob tries to rotate
        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/rotate",
            headers={"X-Inbox-Secret": bob["secret"]},
        )

        assert resp.status_code == 403


class TestEncryptedRoomMembership:
    """Tests for membership changes in encrypted rooms."""

    def test_add_member_with_pubkey_rotates(self, client, setup_encrypted_room):
        """Adding member with pubkey triggers rotation."""
        data = setup_encrypted_room

        # Create second identity with pubkey
        resp = client.post(
            f"/{data['ns']}/identities",
            headers={"X-Namespace-Secret": data["ns_secret"]},
        )
        bob = resp.json()

        bob_kp = generate_keypair()
        client.put(
            f"/{data['ns']}/inbox/{bob['id']}/pubkey",
            json={
                "public_key": bytes_to_base64url(bob_kp.public_key),
                "signing_public_key": bytes_to_base64url(bob_kp.signing_public_key),
            },
            headers={"X-Inbox-Secret": bob["secret"]},
        )

        # Add Bob to room
        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/members",
            json={"identity_id": bob["id"]},
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        result = resp.json()
        # Encrypted room returns epoch info
        assert "current_epoch_number" in result
        assert result["current_epoch_number"] == 1  # Rotated from 0 to 1

    def test_add_member_without_pubkey_fails(self, client, setup_encrypted_room):
        """Adding member without pubkey to encrypted room fails."""
        data = setup_encrypted_room

        # Create second identity without pubkey
        resp = client.post(
            f"/{data['ns']}/identities",
            headers={"X-Namespace-Secret": data["ns_secret"]},
        )
        bob = resp.json()

        # Try to add Bob (no pubkey)
        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/members",
            json={"identity_id": bob["id"]},
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 400
        assert "pubkey" in resp.json()["detail"].lower()

    def test_remove_member_rotates(self, client, setup_encrypted_room):
        """Removing member triggers rotation."""
        data = setup_encrypted_room

        # Add Bob first
        resp = client.post(
            f"/{data['ns']}/identities",
            headers={"X-Namespace-Secret": data["ns_secret"]},
        )
        bob = resp.json()

        bob_kp = generate_keypair()
        client.put(
            f"/{data['ns']}/inbox/{bob['id']}/pubkey",
            json={
                "public_key": bytes_to_base64url(bob_kp.public_key),
                "signing_public_key": bytes_to_base64url(bob_kp.signing_public_key),
            },
            headers={"X-Inbox-Secret": bob["secret"]},
        )

        client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/members",
            json={"identity_id": bob["id"]},
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        # Remove Bob
        resp = client.delete(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/members/{bob['id']}",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        result = resp.json()
        assert result["ok"] is True
        assert result["current_epoch_number"] == 2  # Rotated from 1 to 2


class TestEncryptedMessages:
    """Tests for sending/receiving encrypted messages."""

    def test_send_encrypted_message(self, client, setup_encrypted_room):
        """Send encrypted message with correct epoch."""
        data = setup_encrypted_room

        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/messages",
            json={
                "body": "encrypted_ciphertext_here",
                "epoch_number": 0,
                "encrypted": True,
                "encryption_meta": '{"algorithm": "xsalsa20-poly1305+ed25519"}',
                "signature": "base64_signature",
            },
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        msg = resp.json()
        assert msg["encrypted"] is True
        assert msg["epoch_number"] == 0
        assert msg["encryption_meta"] is not None
        assert msg["signature"] is not None

    def test_send_encrypted_message_wrong_epoch(self, client, setup_encrypted_room):
        """Sending with wrong epoch returns 409."""
        data = setup_encrypted_room

        # Rotate to epoch 1
        client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/rotate",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        # Try to send with epoch 0 (stale)
        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/messages",
            json={
                "body": "encrypted_ciphertext",
                "epoch_number": 0,  # Wrong! Current is 1
                "encrypted": True,
            },
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 409
        error = resp.json()["detail"]
        assert error["error"] == "epoch_mismatch"
        assert error["expected_epoch"] == 1
        assert error["provided_epoch"] == 0

    def test_get_encrypted_messages(self, client, setup_encrypted_room):
        """Retrieved messages include encryption fields."""
        data = setup_encrypted_room

        # Send encrypted message
        client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/messages",
            json={
                "body": "ciphertext",
                "epoch_number": 0,
                "encrypted": True,
                "signature": "sig",
            },
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        # Get messages
        resp = client.get(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/messages",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        messages = resp.json()["messages"]
        assert len(messages) == 1
        assert messages[0]["encrypted"] is True
        assert messages[0]["epoch_number"] == 0

    def test_send_plaintext_to_encrypted_room(self, client, setup_encrypted_room):
        """Can still send plaintext to encrypted room (for compatibility)."""
        data = setup_encrypted_room

        resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/messages",
            json={"body": "Hello, plaintext!"},
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        # Should succeed (encrypted=False is allowed)
        assert resp.status_code == 200
        msg = resp.json()
        # encrypted field should be None (not set)
        assert msg.get("encrypted") is None


class TestRoomListingWithEncryption:
    """Tests for room listing with encryption status."""

    def test_list_rooms_shows_encryption_status(self, client, setup_encrypted_room):
        """Listed rooms include encryption status."""
        data = setup_encrypted_room

        resp = client.get(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        rooms = resp.json()
        assert len(rooms) == 1
        assert rooms[0]["encryption_enabled"] is True
        assert rooms[0]["current_epoch_number"] >= 0

    def test_get_room_shows_encryption_status(self, client, setup_encrypted_room):
        """Get room includes encryption status."""
        data = setup_encrypted_room

        resp = client.get(
            f"/{data['ns']}/rooms/{data['room']['room_id']}",
            headers={"X-Inbox-Secret": data["inbox_secret"]},
        )

        assert resp.status_code == 200
        room = resp.json()
        assert room["encryption_enabled"] is True
        assert room["current_epoch_number"] >= 0
