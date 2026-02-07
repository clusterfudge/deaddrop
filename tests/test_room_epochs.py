"""Tests for room epoch management functions."""

import pytest
from deadrop import db
from deadrop.crypto import (
    generate_room_base_secret,
    generate_keypair,
    derive_epoch_key,
    compute_membership_hash,
    base64url_to_bytes,
    bytes_to_base64url,
    decrypt_epoch_key,
)


class TestCreateRoomEpoch:
    """Tests for creating room epochs."""

    def test_create_epoch_basic(self):
        """Create a basic epoch record."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        epoch = db.create_room_epoch(
            room_id=room["room_id"],
            epoch_number=0,
            membership_hash="a" * 64,
            reason="created",
            triggered_by=alice["id"],
        )

        assert epoch["epoch_id"] is not None
        assert epoch["room_id"] == room["room_id"]
        assert epoch["epoch_number"] == 0
        assert epoch["membership_hash"] == "a" * 64
        assert epoch["reason"] == "created"
        assert epoch["triggered_by"] == alice["id"]
        assert epoch["created_at"] is not None

    def test_create_epoch_without_triggered_by(self):
        """Create epoch without triggered_by (e.g., system rotation)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        epoch = db.create_room_epoch(
            room_id=room["room_id"],
            epoch_number=0,
            membership_hash="b" * 64,
            reason="created",
        )

        assert epoch["triggered_by"] is None

    def test_create_sequential_epochs(self):
        """Create multiple epochs with sequential numbers."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        epoch0 = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")
        epoch1 = db.create_room_epoch(room["room_id"], 1, "b" * 64, "member_joined")
        epoch2 = db.create_room_epoch(room["room_id"], 2, "c" * 64, "member_left")

        assert epoch0["epoch_number"] == 0
        assert epoch1["epoch_number"] == 1
        assert epoch2["epoch_number"] == 2

    def test_create_epoch_duplicate_number_fails(self):
        """Creating epoch with duplicate number should fail."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        with pytest.raises(Exception):  # IntegrityError
            db.create_room_epoch(room["room_id"], 0, "b" * 64, "duplicate")


class TestGetCurrentEpoch:
    """Tests for getting the current epoch."""

    def test_get_current_epoch(self):
        """Get the highest numbered epoch."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")
        db.create_room_epoch(room["room_id"], 1, "b" * 64, "member_joined")
        epoch2 = db.create_room_epoch(room["room_id"], 2, "c" * 64, "member_left")

        current = db.get_current_epoch(room["room_id"])

        assert current is not None
        assert current["epoch_number"] == 2
        assert current["epoch_id"] == epoch2["epoch_id"]

    def test_get_current_epoch_none(self):
        """Get current epoch when room has no epochs."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        current = db.get_current_epoch(room["room_id"])
        assert current is None

    def test_get_current_epoch_nonexistent_room(self):
        """Get current epoch for nonexistent room."""
        current = db.get_current_epoch("nonexistent-room-id")
        assert current is None


class TestGetEpochByNumber:
    """Tests for getting epoch by number."""

    def test_get_epoch_by_number(self):
        """Get a specific epoch by number."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        epoch0 = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")
        db.create_room_epoch(room["room_id"], 1, "b" * 64, "member_joined")

        fetched = db.get_epoch_by_number(room["room_id"], 0)

        assert fetched is not None
        assert fetched["epoch_id"] == epoch0["epoch_id"]
        assert fetched["epoch_number"] == 0

    def test_get_epoch_by_number_not_found(self):
        """Get epoch that doesn't exist."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        fetched = db.get_epoch_by_number(room["room_id"], 999)
        assert fetched is None


class TestStoreEpochKey:
    """Tests for storing encrypted epoch keys."""

    def test_store_epoch_key(self):
        """Store an encrypted epoch key for a member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        key_record = db.store_epoch_key(
            epoch_id=epoch["epoch_id"],
            identity_id=alice["id"],
            encrypted_epoch_key="encrypted_key_base64_here",
        )

        assert key_record["epoch_id"] == epoch["epoch_id"]
        assert key_record["identity_id"] == alice["id"]
        assert key_record["encrypted_epoch_key"] == "encrypted_key_base64_here"
        assert key_record["created_at"] is not None

    def test_store_epoch_key_multiple_members(self):
        """Store epoch keys for multiple members."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        db.store_epoch_key(epoch["epoch_id"], alice["id"], "alice_key")
        db.store_epoch_key(epoch["epoch_id"], bob["id"], "bob_key")
        db.store_epoch_key(epoch["epoch_id"], carol["id"], "carol_key")

        keys = db.list_epoch_keys(epoch["epoch_id"])
        assert len(keys) == 3


class TestGetEpochKeyForIdentity:
    """Tests for getting epoch key for a specific identity."""

    def test_get_epoch_key_for_identity(self):
        """Get the encrypted key for a specific member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        db.store_epoch_key(epoch["epoch_id"], alice["id"], "alice_key")
        db.store_epoch_key(epoch["epoch_id"], bob["id"], "bob_key")

        alice_key = db.get_epoch_key_for_identity(room["room_id"], 0, alice["id"])
        bob_key = db.get_epoch_key_for_identity(room["room_id"], 0, bob["id"])

        assert alice_key is not None
        assert alice_key["encrypted_epoch_key"] == "alice_key"
        assert bob_key["encrypted_epoch_key"] == "bob_key"

    def test_get_epoch_key_for_identity_not_found(self):
        """Get key for member who doesn't have one."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        db.store_epoch_key(epoch["epoch_id"], alice["id"], "alice_key")

        # Bob doesn't have a key
        bob_key = db.get_epoch_key_for_identity(room["room_id"], 0, bob["id"])
        assert bob_key is None

    def test_get_epoch_key_for_identity_wrong_epoch(self):
        """Get key from wrong epoch returns None."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        db.store_epoch_key(epoch["epoch_id"], alice["id"], "alice_key")

        # Epoch 1 doesn't exist
        key = db.get_epoch_key_for_identity(room["room_id"], 1, alice["id"])
        assert key is None


class TestListEpochKeys:
    """Tests for listing all keys for an epoch."""

    def test_list_epoch_keys(self):
        """List all encrypted keys for an epoch."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        db.store_epoch_key(epoch["epoch_id"], alice["id"], "alice_key")
        db.store_epoch_key(epoch["epoch_id"], bob["id"], "bob_key")

        keys = db.list_epoch_keys(epoch["epoch_id"])

        assert len(keys) == 2
        identity_ids = {k["identity_id"] for k in keys}
        assert alice["id"] in identity_ids
        assert bob["id"] in identity_ids

    def test_list_epoch_keys_empty(self):
        """List keys for epoch with no keys."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        epoch = db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")

        keys = db.list_epoch_keys(epoch["epoch_id"])
        assert keys == []


class TestGetRoomWithEncryption:
    """Tests for getting room info with encryption status."""

    def test_get_room_with_encryption_default(self):
        """Get room with default (unencrypted) status."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        room_info = db.get_room_with_encryption(room["room_id"])

        assert room_info is not None
        assert room_info["room_id"] == room["room_id"]
        assert room_info["encryption_enabled"] == 0
        assert room_info["current_epoch_number"] == 0

    def test_get_room_with_encryption_not_found(self):
        """Get nonexistent room."""
        room_info = db.get_room_with_encryption("nonexistent-room-id")
        assert room_info is None


class TestUpdateRoomEpochNumber:
    """Tests for updating room's current epoch number."""

    def test_update_room_epoch_number(self):
        """Update room's current epoch number."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        result = db.update_room_epoch_number(room["room_id"], 5)
        assert result is True

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 5

    def test_update_room_epoch_number_not_found(self):
        """Update epoch number for nonexistent room."""
        result = db.update_room_epoch_number("nonexistent-room-id", 5)
        assert result is False


class TestListRoomEpochs:
    """Tests for listing room epochs."""

    def test_list_room_epochs(self):
        """List all epochs for a room (most recent first)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.create_room_epoch(room["room_id"], 0, "a" * 64, "created")
        db.create_room_epoch(room["room_id"], 1, "b" * 64, "member_joined")
        db.create_room_epoch(room["room_id"], 2, "c" * 64, "member_left")

        epochs = db.list_room_epochs(room["room_id"])

        assert len(epochs) == 3
        assert epochs[0]["epoch_number"] == 2  # Most recent first
        assert epochs[1]["epoch_number"] == 1
        assert epochs[2]["epoch_number"] == 0

    def test_list_room_epochs_with_limit(self):
        """List epochs with a limit."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        for i in range(5):
            db.create_room_epoch(room["room_id"], i, f"{i}" * 64, "test")

        epochs = db.list_room_epochs(room["room_id"], limit=2)

        assert len(epochs) == 2
        assert epochs[0]["epoch_number"] == 4
        assert epochs[1]["epoch_number"] == 3

    def test_list_room_epochs_empty(self):
        """List epochs for room with no epochs."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        epochs = db.list_room_epochs(room["room_id"])
        assert epochs == []


# =============================================================================
# Epoch Rotation Logic Tests
# =============================================================================


class TestGetRoomMembersWithPubkeys:
    """Tests for getting room members with their pubkeys."""

    def test_members_without_pubkeys(self):
        """Get members who don't have pubkeys registered."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        members = db.get_room_members_with_pubkeys(room["room_id"])

        assert len(members) == 2
        for member in members:
            assert member["public_key"] is None

    def test_members_with_pubkeys(self):
        """Get members who have pubkeys registered."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        # Register pubkeys
        alice_kp = generate_keypair()
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            alice["id"],
            bytes_to_base64url(alice_kp.public_key),
            bytes_to_base64url(alice_kp.signing_public_key),
        )
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        room = db.create_room(ns["ns"], alice["id"])
        db.add_room_member(room["room_id"], bob["id"])

        members = db.get_room_members_with_pubkeys(room["room_id"])

        assert len(members) == 2
        alice_member = next(m for m in members if m["identity_id"] == alice["id"])
        bob_member = next(m for m in members if m["identity_id"] == bob["id"])

        assert alice_member["public_key"] is not None
        assert bob_member["public_key"] is not None


class TestInitializeRoomEncryption:
    """Tests for initializing encryption on a room."""

    def test_initialize_encryption_basic(self):
        """Initialize encryption without server keypair (test mode)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        result = db.initialize_room_encryption(
            room_id=room["room_id"],
            base_secret=base_secret,
            triggered_by=alice["id"],
        )

        assert result["epoch"]["epoch_number"] == 0
        assert result["epoch"]["reason"] == "created"
        assert len(result["member_keys"]) == 1
        assert result["member_keys"][0]["identity_id"] == alice["id"]

        # Room should be marked as encrypted
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["encryption_enabled"] == 1
        assert room_info["current_epoch_number"] == 0

    def test_initialize_encryption_with_server_keypair(self):
        """Initialize encryption with actual key encryption."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])

        # Register Alice's pubkey
        alice_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            alice["id"],
            bytes_to_base64url(alice_kp.public_key),
            bytes_to_base64url(alice_kp.signing_public_key),
        )

        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        server_kp = generate_keypair()

        result = db.initialize_room_encryption(
            room_id=room["room_id"],
            base_secret=base_secret,
            triggered_by=alice["id"],
            server_keypair=(server_kp.private_key, server_kp.public_key),
        )

        # Alice should be able to decrypt her epoch key
        encrypted_key = base64url_to_bytes(result["member_keys"][0]["encrypted_epoch_key"])
        decrypted_key = decrypt_epoch_key(encrypted_key, server_kp.public_key, alice_kp.private_key)

        # Verify it's the correct epoch 0 key
        membership_hash = compute_membership_hash([alice["id"]])
        expected_key = derive_epoch_key(base_secret, 0, room["room_id"], membership_hash)
        assert decrypted_key == expected_key

    def test_initialize_encryption_fails_without_pubkey(self):
        """Initialize encryption fails if member lacks pubkey."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        server_kp = generate_keypair()

        # Alice has no pubkey, but we require one
        with pytest.raises(ValueError, match="does not have a registered pubkey"):
            db.initialize_room_encryption(
                room_id=room["room_id"],
                base_secret=base_secret,
                server_keypair=(server_kp.private_key, server_kp.public_key),
            )


class TestRotateRoomEpoch:
    """Tests for rotating room epochs."""

    def test_rotate_epoch_member_joined(self):
        """Rotate epoch when a member joins (via add_room_member)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        # Bob needs a pubkey to join encrypted room
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        # Initialize encryption (epoch 0)
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Add Bob - this automatically triggers rotation
        db.add_room_member(room["room_id"], bob["id"])

        # Room should be at epoch 1 (auto-rotated on member add)
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 1

        # Verify epoch 1 exists and has correct reason
        epoch = db.get_epoch_by_number(room["room_id"], 1)
        assert epoch is not None
        assert epoch["reason"] == "member_joined"
        assert epoch["triggered_by"] == bob["id"]

        # Both members should have keys for epoch 1
        alice_key = db.get_epoch_key_for_identity(room["room_id"], 1, alice["id"])
        bob_key = db.get_epoch_key_for_identity(room["room_id"], 1, bob["id"])
        assert alice_key is not None
        assert bob_key is not None

    def test_rotate_epoch_member_left(self):
        """Rotate epoch when a member leaves (via remove_room_member)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        # Add Bob before encryption (no pubkey required for unencrypted room)
        db.add_room_member(room["room_id"], bob["id"])

        # Initialize encryption (epoch 0)
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Remove Bob - this automatically triggers rotation
        db.remove_room_member(room["room_id"], bob["id"])

        # Room should be at epoch 1 (auto-rotated on member remove)
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 1

        # Verify epoch 1 exists and has correct reason
        epoch = db.get_epoch_by_number(room["room_id"], 1)
        assert epoch is not None
        assert epoch["reason"] == "member_left"
        assert epoch["triggered_by"] == bob["id"]

        # Only Alice should have key for epoch 1
        alice_key = db.get_epoch_key_for_identity(room["room_id"], 1, alice["id"])
        bob_key = db.get_epoch_key_for_identity(room["room_id"], 1, bob["id"])
        assert alice_key is not None
        assert bob_key is None  # Bob removed, shouldn't have new epoch key

    def test_rotate_epoch_verifies_key_chain(self):
        """Verify epoch keys form a correct derivation chain."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        # Initialize encryption (epoch 0)
        init_result = db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])
        epoch0_key = base64url_to_bytes(init_result["member_keys"][0]["encrypted_epoch_key"])

        # Compute expected epoch 0 key
        membership_hash_0 = init_result["membership_hash"]
        expected_epoch0 = derive_epoch_key(base_secret, 0, room["room_id"], membership_hash_0)
        assert epoch0_key == expected_epoch0

        # Rotate to epoch 1
        rotate_result = db.rotate_room_epoch(room["room_id"], "manual", alice["id"])
        epoch1_key = base64url_to_bytes(rotate_result["member_keys"][0]["encrypted_epoch_key"])

        # Compute expected epoch 1 key (derived from epoch 0 key)
        membership_hash_1 = rotate_result["membership_hash"]
        expected_epoch1 = derive_epoch_key(expected_epoch0, 1, room["room_id"], membership_hash_1)
        assert epoch1_key == expected_epoch1

    def test_rotate_epoch_fails_not_encrypted(self):
        """Rotation fails on unencrypted room."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        with pytest.raises(ValueError, match="does not have encryption enabled"):
            db.rotate_room_epoch(room["room_id"], "manual")

    def test_rotate_epoch_fails_no_members(self):
        """Rotation fails if room has no members."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Remove the only member (shouldn't happen in practice)
        db.remove_room_member(room["room_id"], alice["id"])

        with pytest.raises(ValueError, match="has no members"):
            db.rotate_room_epoch(room["room_id"], "manual")

    def test_multiple_rotations(self):
        """Test multiple sequential rotations."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Rotate 5 times
        for i in range(1, 6):
            result = db.rotate_room_epoch(room["room_id"], "manual")
            assert result["epoch"]["epoch_number"] == i

        # Room should be at epoch 5
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 5

        # Should have 6 epochs total
        epochs = db.list_room_epochs(room["room_id"])
        assert len(epochs) == 6


# =============================================================================
# Pubkey Enforcement Tests
# =============================================================================


class TestPubkeyEnforcementOnMembership:
    """Tests for pubkey requirement enforcement on encrypted rooms."""

    def test_join_encrypted_room_without_pubkey_fails(self):
        """Cannot join encrypted room without a pubkey."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])  # Bob has no pubkey
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        with pytest.raises(ValueError, match="must have a registered pubkey"):
            db.add_room_member(room["room_id"], bob["id"])

    def test_join_encrypted_room_with_pubkey_succeeds(self):
        """Can join encrypted room with a pubkey."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        # Register Bob's pubkey
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Bob can join
        member = db.add_room_member(room["room_id"], bob["id"])
        assert member["identity_id"] == bob["id"]

        # Verify Bob is a member
        assert db.is_room_member(room["room_id"], bob["id"])

    def test_join_unencrypted_room_without_pubkey_succeeds(self):
        """Can join unencrypted room without a pubkey."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])  # Bob has no pubkey
        room = db.create_room(ns["ns"], alice["id"])

        # Room is not encrypted, so Bob can join
        member = db.add_room_member(room["room_id"], bob["id"])
        assert member["identity_id"] == bob["id"]

    def test_join_triggers_rotation_for_encrypted_room(self):
        """Joining encrypted room triggers epoch rotation."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        # Register Bob's pubkey
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Room at epoch 0
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 0

        # Bob joins
        db.add_room_member(room["room_id"], bob["id"])

        # Room should be at epoch 1
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 1

    def test_join_no_rotation_for_unencrypted_room(self):
        """Joining unencrypted room does not create epochs."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.add_room_member(room["room_id"], bob["id"])

        # No epochs should exist
        epochs = db.list_room_epochs(room["room_id"])
        assert len(epochs) == 0

    def test_leave_triggers_rotation_for_encrypted_room(self):
        """Leaving encrypted room triggers epoch rotation."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        # Add Bob before encryption
        db.add_room_member(room["room_id"], bob["id"])

        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Room at epoch 0
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 0

        # Bob leaves
        db.remove_room_member(room["room_id"], bob["id"])

        # Room should be at epoch 1
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 1

    def test_leave_no_rotation_for_unencrypted_room(self):
        """Leaving unencrypted room does not create epochs."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        db.add_room_member(room["room_id"], bob["id"])
        db.remove_room_member(room["room_id"], bob["id"])

        # No epochs should exist
        epochs = db.list_room_epochs(room["room_id"])
        assert len(epochs) == 0

    def test_leave_no_rotation_when_last_member(self):
        """Removing last member doesn't trigger rotation (no one to rotate for)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()

        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Room at epoch 0
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 0

        # Alice leaves (last member)
        db.remove_room_member(room["room_id"], alice["id"])

        # Room should still be at epoch 0 (no rotation for empty room)
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 0

    def test_trigger_rotation_false_skips_rotation(self):
        """trigger_rotation=False skips automatic rotation."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        # Register Bob's pubkey
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Add Bob with trigger_rotation=False
        db.add_room_member(room["room_id"], bob["id"], trigger_rotation=False)

        # Room should still be at epoch 0
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 0


# =============================================================================
# Encrypted Message Tests
# =============================================================================


class TestEncryptedMessages:
    """Tests for sending and retrieving encrypted messages."""

    def test_send_plaintext_message(self):
        """Send a plaintext message (backward compatible)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])

        msg = db.send_room_message(room["room_id"], alice["id"], "Hello!")

        assert msg["body"] == "Hello!"
        assert "encrypted" not in msg

    def test_send_encrypted_message(self):
        """Send an encrypted message."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        msg = db.send_room_message(
            room_id=room["room_id"],
            from_id=alice["id"],
            body="encrypted_ciphertext_here",
            epoch_number=0,
            encrypted=True,
            encryption_meta='{"algorithm": "xsalsa20-poly1305+ed25519"}',
            signature="base64_signature_here",
        )

        assert msg["encrypted"] is True
        assert msg["epoch_number"] == 0
        assert msg["encryption_meta"] == '{"algorithm": "xsalsa20-poly1305+ed25519"}'
        assert msg["signature"] == "base64_signature_here"

    def test_send_encrypted_message_epoch_mismatch(self):
        """Sending with wrong epoch raises EpochMismatchError."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Rotate to epoch 1
        db.rotate_room_epoch(room["room_id"], "manual")

        # Try to send with epoch 0 (stale)
        with pytest.raises(db.EpochMismatchError) as exc_info:
            db.send_room_message(
                room_id=room["room_id"],
                from_id=alice["id"],
                body="ciphertext",
                epoch_number=0,  # Wrong! Current is 1
                encrypted=True,
            )

        assert exc_info.value.expected_epoch == 1
        assert exc_info.value.provided_epoch == 0
        assert exc_info.value.room_id == room["room_id"]

    def test_get_encrypted_messages(self):
        """Retrieved messages include encryption fields."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Send encrypted message
        db.send_room_message(
            room_id=room["room_id"],
            from_id=alice["id"],
            body="ciphertext1",
            epoch_number=0,
            encrypted=True,
            encryption_meta='{"nonce": "abc"}',
            signature="sig1",
        )

        # Send plaintext message (unencrypted room would do this)
        db.send_room_message(room["room_id"], alice["id"], "plaintext")

        messages = db.get_room_messages(room["room_id"])

        assert len(messages) == 2

        # First message is encrypted
        assert messages[0]["encrypted"] is True
        assert messages[0]["epoch_number"] == 0
        assert messages[0]["encryption_meta"] == '{"nonce": "abc"}'
        assert messages[0]["signature"] == "sig1"

        # Second message is not encrypted
        assert "encrypted" not in messages[1]

    def test_get_single_encrypted_message(self):
        """get_room_message returns encryption fields."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        sent = db.send_room_message(
            room_id=room["room_id"],
            from_id=alice["id"],
            body="ciphertext",
            epoch_number=0,
            encrypted=True,
            signature="my_sig",
        )

        fetched = db.get_room_message(room["room_id"], sent["mid"])

        assert fetched["encrypted"] is True
        assert fetched["epoch_number"] == 0
        assert fetched["signature"] == "my_sig"

    def test_validate_message_epoch_success(self):
        """validate_message_epoch succeeds for correct epoch."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        result = db.validate_message_epoch(room["room_id"], 0)
        assert result is True

    def test_validate_message_epoch_mismatch(self):
        """validate_message_epoch raises for wrong epoch."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"])
        base_secret = generate_room_base_secret()
        db.initialize_room_encryption(room["room_id"], base_secret, alice["id"])

        # Rotate to epoch 1
        db.rotate_room_epoch(room["room_id"], "manual")

        with pytest.raises(db.EpochMismatchError) as exc_info:
            db.validate_message_epoch(room["room_id"], 0)

        assert exc_info.value.expected_epoch == 1
        assert exc_info.value.provided_epoch == 0

    def test_validate_message_epoch_room_not_found(self):
        """validate_message_epoch raises for nonexistent room."""
        with pytest.raises(ValueError, match="not found"):
            db.validate_message_epoch("nonexistent-room", 0)


# =============================================================================
# True E2E Room Encryption Tests
# =============================================================================


class TestMemberSecretStorage:
    """Tests for storing encrypted base secrets per member."""

    def test_store_member_secret(self):
        """Can store an encrypted secret for a member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        result = db.store_member_secret(
            room_id=room["room_id"],
            identity_id=alice["id"],
            encrypted_base_secret="encrypted_secret_base64",
            inviter_public_key="inviter_pubkey_base64",
            secret_version=0,
        )

        assert result["room_id"] == room["room_id"]
        assert result["identity_id"] == alice["id"]
        assert result["secret_version"] == 0

    def test_get_member_secret_latest(self):
        """Can retrieve latest secret for a member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        # Store multiple versions
        db.store_member_secret(room["room_id"], alice["id"], "secret_v0", "pk", 0)
        db.store_member_secret(room["room_id"], alice["id"], "secret_v1", "pk", 1)
        db.store_member_secret(room["room_id"], alice["id"], "secret_v2", "pk", 2)

        result = db.get_member_secret(room["room_id"], alice["id"])

        assert result["secret_version"] == 2
        assert result["encrypted_base_secret"] == "secret_v2"

    def test_get_member_secret_specific_version(self):
        """Can retrieve a specific version."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        db.store_member_secret(room["room_id"], alice["id"], "secret_v0", "pk", 0)
        db.store_member_secret(room["room_id"], alice["id"], "secret_v1", "pk", 1)

        result = db.get_member_secret(room["room_id"], alice["id"], secret_version=0)

        assert result["secret_version"] == 0
        assert result["encrypted_base_secret"] == "secret_v0"

    def test_list_member_secrets(self):
        """Can list all secret versions for a member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        db.store_member_secret(room["room_id"], alice["id"], "v0", "pk", 0)
        db.store_member_secret(room["room_id"], alice["id"], "v1", "pk", 1)
        db.store_member_secret(room["room_id"], alice["id"], "v2", "pk", 2)

        secrets = db.list_member_secrets(room["room_id"], alice["id"])

        assert len(secrets) == 3
        assert secrets[0]["secret_version"] == 0
        assert secrets[1]["secret_version"] == 1
        assert secrets[2]["secret_version"] == 2


class TestInitializeRoomEncryptionE2E:
    """Tests for initializing E2E encryption."""

    def test_initialize_room_encryption_e2e(self):
        """Can initialize encryption in E2E mode."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pubkey", "signing_pubkey")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        result = db.initialize_room_encryption_e2e(
            room_id=room["room_id"],
            creator_id=alice["id"],
            encrypted_base_secret="encrypted_secret_for_alice",
            creator_public_key="alice_pubkey",
        )

        assert result["encryption_enabled"] is True
        assert result["secret_version"] == 0

        # Verify room state
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["encryption_enabled"] == 1
        assert room_info["secret_version"] == 0
        assert room_info["base_secret"] is None  # Not stored in E2E mode

        # Verify creator's secret is stored
        secret = db.get_member_secret(room["room_id"], alice["id"])
        assert secret["encrypted_base_secret"] == "encrypted_secret_for_alice"


class TestRotateRoomSecretE2E:
    """Tests for rotating secrets in E2E mode."""

    def test_rotate_secret_e2e(self):
        """Can rotate secret in E2E mode."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        # Initialize E2E
        db.initialize_room_encryption_e2e(
            room["room_id"], alice["id"], "enc_secret_alice", "alice_pk"
        )

        # Add Bob
        db.add_room_member(room["room_id"], bob["id"], trigger_rotation=False)
        db.store_member_secret(room["room_id"], bob["id"], "enc_secret_bob", "alice_pk", 0)

        # Rotate (e.g., after Carol was removed)
        result = db.rotate_room_secret_e2e(
            room_id=room["room_id"],
            new_secret_version=1,
            member_secrets=[
                {
                    "identity_id": alice["id"],
                    "encrypted_base_secret": "enc_v1_alice",
                    "inviter_public_key": "alice_pk",
                },
                {
                    "identity_id": bob["id"],
                    "encrypted_base_secret": "enc_v1_bob",
                    "inviter_public_key": "alice_pk",
                },
            ],
        )

        assert result["secret_version"] == 1
        assert result["member_count"] == 2

        # Verify new secrets
        alice_secret = db.get_member_secret(room["room_id"], alice["id"])
        assert alice_secret["secret_version"] == 1
        assert alice_secret["encrypted_base_secret"] == "enc_v1_alice"

    def test_rotate_secret_version_mismatch(self):
        """Rotation fails with wrong version number."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk", "spk")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "enc", "pk")

        with pytest.raises(ValueError, match="Invalid secret version"):
            db.rotate_room_secret_e2e(
                room_id=room["room_id"],
                new_secret_version=5,  # Should be 1
                member_secrets=[
                    {
                        "identity_id": alice["id"],
                        "encrypted_base_secret": "enc",
                        "inviter_public_key": "pk",
                    },
                ],
            )

    def test_rotate_secret_missing_member(self):
        """Rotation fails if not all members have secrets."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "enc", "pk")
        db.add_room_member(room["room_id"], bob["id"], trigger_rotation=False)

        with pytest.raises(ValueError, match="Member mismatch"):
            db.rotate_room_secret_e2e(
                room_id=room["room_id"],
                new_secret_version=1,
                member_secrets=[
                    # Missing bob
                    {
                        "identity_id": alice["id"],
                        "encrypted_base_secret": "enc",
                        "inviter_public_key": "pk",
                    },
                ],
            )


class TestPendingRemoval:
    """Tests for two-phase exit protocol (pending removal state)."""

    def test_set_pending_removal(self):
        """Can set a member as pending removal."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        result = db.set_pending_removal(room["room_id"], bob["id"])

        assert result["pending_removal_id"] == bob["id"]
        assert result["pending_removal_at"] is not None

    def test_set_pending_removal_nonmember_fails(self):
        """Cannot set pending removal for non-member."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        with pytest.raises(ValueError, match="not a member"):
            db.set_pending_removal(room["room_id"], bob["id"])

    def test_set_pending_removal_already_pending_fails(self):
        """Cannot set pending removal if one already exists."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])
        db.add_room_member(room["room_id"], carol["id"])

        db.set_pending_removal(room["room_id"], bob["id"])

        with pytest.raises(ValueError, match="already has pending removal"):
            db.set_pending_removal(room["room_id"], carol["id"])

    def test_get_pending_removal(self):
        """Can retrieve pending removal state."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        # No pending removal initially
        assert db.get_pending_removal(room["room_id"]) is None

        # After setting
        db.set_pending_removal(room["room_id"], bob["id"])
        pending = db.get_pending_removal(room["room_id"])

        assert pending["pending_removal_id"] == bob["id"]
        assert pending["pending_removal_at"] is not None

    def test_clear_pending_removal(self):
        """Can clear pending removal state."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        db.set_pending_removal(room["room_id"], bob["id"])
        assert db.get_pending_removal(room["room_id"]) is not None

        db.clear_pending_removal(room["room_id"])
        assert db.get_pending_removal(room["room_id"]) is None

    def test_add_member_blocked_during_pending_removal(self):
        """Cannot add members while a removal is pending (security)."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        db.create_pubkey(ns["ns"], carol["id"], "pk_c", "spk_c")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        # Initialize as E2E room
        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "encrypted", "pubkey")

        # Start pending removal for Bob
        db.set_pending_removal(room["room_id"], bob["id"])

        # Try to add Carol while Bob's removal is pending
        with pytest.raises(ValueError, match="Cannot add members while a removal is pending"):
            db.add_room_member(room["room_id"], carol["id"])

        # After clearing pending removal, Carol can be added
        db.clear_pending_removal(room["room_id"])
        db.add_room_member(room["room_id"], carol["id"])
        assert db.is_room_member(room["room_id"], carol["id"])

    def test_finalize_pending_removal(self):
        """Can finalize pending removal."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        db.set_pending_removal(room["room_id"], bob["id"])

        result = db.finalize_pending_removal(room["room_id"], bob["id"])
        assert result is True

        # Bob should no longer be a member
        assert not db.is_room_member(room["room_id"], bob["id"])

        # Pending state should be cleared
        assert db.get_pending_removal(room["room_id"]) is None

    def test_finalize_wrong_member_fails(self):
        """Finalize with wrong member ID fails."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])
        db.add_room_member(room["room_id"], carol["id"])

        db.set_pending_removal(room["room_id"], bob["id"])

        with pytest.raises(ValueError, match="mismatch"):
            db.finalize_pending_removal(room["room_id"], carol["id"])


class TestRemoveRoomMemberTwoPhase:
    """Tests for remove_room_member with two-phase protocol."""

    def test_e2e_room_uses_two_phase(self):
        """E2E encrypted room uses two-phase by default."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        # Initialize as E2E room
        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "encrypted", "pubkey")

        # Remove should use two-phase
        result = db.remove_room_member(room["room_id"], bob["id"])

        assert result["removed"] is False
        assert result["pending"] is True
        assert result["pending_removal_id"] == bob["id"]

        # Bob should still be a member
        assert db.is_room_member(room["room_id"], bob["id"])

    def test_non_e2e_room_immediate_removal(self):
        """Non-E2E room uses immediate removal."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        result = db.remove_room_member(room["room_id"], bob["id"])

        assert result["removed"] is True
        assert result["immediate"] is True
        assert not db.is_room_member(room["room_id"], bob["id"])

    def test_force_immediate_removal(self):
        """Can force immediate removal even for E2E rooms."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "encrypted", "pubkey")

        # Force immediate removal
        result = db.remove_room_member(room["room_id"], bob["id"], use_two_phase=False)

        assert result["removed"] is True
        assert result["immediate"] is True
        assert not db.is_room_member(room["room_id"], bob["id"])


class TestRotateWithFinalize:
    """Tests for rotating with finalize_removal (complete two-phase exit)."""

    def test_rotate_with_finalize_removal(self):
        """Can rotate and finalize pending removal in one step."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        db.create_pubkey(ns["ns"], carol["id"], "pk_c", "spk_c")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])
        db.add_room_member(room["room_id"], carol["id"])

        # Initialize E2E
        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "enc_alice", "pk_a")
        db.store_member_secret(room["room_id"], bob["id"], "enc_bob", "pk_a", 0)
        db.store_member_secret(room["room_id"], carol["id"], "enc_carol", "pk_a", 0)

        # Bob requests to leave (two-phase)
        db.set_pending_removal(room["room_id"], bob["id"])
        assert db.is_room_member(room["room_id"], bob["id"])  # Still member

        # Alice rotates with fresh secret, excluding Bob
        result = db.rotate_room_secret_e2e(
            room_id=room["room_id"],
            new_secret_version=1,
            member_secrets=[
                {
                    "identity_id": alice["id"],
                    "encrypted_base_secret": "new_enc_alice",
                    "inviter_public_key": "pk_a",
                },
                {
                    "identity_id": carol["id"],
                    "encrypted_base_secret": "new_enc_carol",
                    "inviter_public_key": "pk_a",
                },
            ],
            triggered_by=alice["id"],
            finalize_removal=bob["id"],
        )

        assert result["secret_version"] == 1
        assert result["removed_member"] == bob["id"]
        assert result["member_count"] == 2  # Alice and Carol

        # Bob should now be removed
        assert not db.is_room_member(room["room_id"], bob["id"])
        assert db.is_room_member(room["room_id"], alice["id"])
        assert db.is_room_member(room["room_id"], carol["id"])

        # Pending removal should be cleared
        assert db.get_pending_removal(room["room_id"]) is None

    def test_rotate_finalize_wrong_member_fails(self):
        """Cannot finalize with wrong member ID."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        db.create_pubkey(ns["ns"], carol["id"], "pk_c", "spk_c")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])
        db.add_room_member(room["room_id"], carol["id"])

        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "enc_alice", "pk_a")
        db.store_member_secret(room["room_id"], bob["id"], "enc_bob", "pk_a", 0)
        db.store_member_secret(room["room_id"], carol["id"], "enc_carol", "pk_a", 0)

        # Bob requests to leave
        db.set_pending_removal(room["room_id"], bob["id"])

        # Try to finalize Carol instead of Bob
        with pytest.raises(ValueError, match="mismatch"):
            db.rotate_room_secret_e2e(
                room_id=room["room_id"],
                new_secret_version=1,
                member_secrets=[
                    {
                        "identity_id": alice["id"],
                        "encrypted_base_secret": "new",
                        "inviter_public_key": "pk",
                    },
                    {
                        "identity_id": bob["id"],
                        "encrypted_base_secret": "new",
                        "inviter_public_key": "pk",
                    },
                ],
                finalize_removal=carol["id"],  # Wrong member
            )

    def test_rotate_finalize_no_pending_fails(self):
        """Cannot finalize removal if none is pending."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")

        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "enc_alice", "pk_a")

        with pytest.raises(ValueError, match="No pending removal"):
            db.rotate_room_secret_e2e(
                room_id=room["room_id"],
                new_secret_version=1,
                member_secrets=[
                    {
                        "identity_id": alice["id"],
                        "encrypted_base_secret": "new",
                        "inviter_public_key": "pk",
                    },
                ],
                finalize_removal=alice["id"],
            )


class TestForwardSecrecyFix:
    """Tests proving forward secrecy is now fixed with fresh random secrets.

    The vulnerability was: removed member could derive future epoch keys
    because HKDF derivation is deterministic.

    The fix: Use fresh random secrets for member removal (not HKDF derivation).
    """

    def test_removed_member_cannot_derive_new_secret_with_fresh_random(self):
        """Prove that with fresh random secrets, removed member cannot derive new key.

        This is the core security test for the two-phase exit fix.
        """
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_base_secret_for_member,
            decrypt_base_secret_from_invite,
        )

        # Setup: Alice, Bob, Carol in a room
        room_id = "test-room-id"
        base_secret_v0 = generate_room_base_secret()

        alice = generate_keypair()
        # bob keypair not needed - we test that Bob with base_secret_v0 cannot derive v1
        carol = generate_keypair()

        # Epoch 0: All three members have the base secret
        members_v0 = ["alice", "bob", "carol"]
        hash_v0 = compute_membership_hash(members_v0)
        epoch_key_0 = derive_epoch_key(base_secret_v0, 0, room_id, hash_v0)

        # Bob is removed. Alice generates FRESH RANDOM secret (not derived!)
        base_secret_v1 = generate_room_base_secret()  # Fresh random!

        # Alice encrypts new secret for herself and Carol only
        enc_alice = encrypt_base_secret_for_member(
            base_secret_v1, alice.public_key, alice.private_key, room_id
        )
        enc_carol = encrypt_base_secret_for_member(
            base_secret_v1, carol.public_key, alice.private_key, room_id
        )

        # Verify Alice and Carol can decrypt
        alice_secret = decrypt_base_secret_from_invite(
            enc_alice, alice.public_key, alice.private_key, room_id
        )
        carol_secret = decrypt_base_secret_from_invite(
            enc_carol, alice.public_key, carol.private_key, room_id
        )

        assert alice_secret == base_secret_v1
        assert carol_secret == base_secret_v1

        # Derive epoch 1 key from new base secret
        members_v1 = ["alice", "carol"]
        hash_v1 = compute_membership_hash(members_v1)
        epoch_key_1_real = derive_epoch_key(base_secret_v1, 0, room_id, hash_v1)

        # BOB'S ATTACK: Try to derive the new epoch key
        # Bob has: base_secret_v0, epoch_key_0, knows the new membership
        # Bob tries HKDF derivation (the old vulnerability)
        bob_attempt_hkdf = derive_epoch_key(base_secret_v0, 1, room_id, hash_v1)
        bob_attempt_from_epoch = derive_epoch_key(epoch_key_0, 1, room_id, hash_v1)

        # Bob's attempts should NOT match the real key
        assert bob_attempt_hkdf != epoch_key_1_real, (
            "Bob derived key via HKDF - forward secrecy broken!"
        )
        assert bob_attempt_from_epoch != epoch_key_1_real, (
            "Bob derived key from previous epoch - forward secrecy broken!"
        )

        # The base secrets should also be different
        assert base_secret_v0 != base_secret_v1, (
            "Base secrets should be different (fresh random vs original)"
        )

    def test_hkdf_derivation_is_vulnerable_demonstration(self):
        """Demonstrate why HKDF derivation was vulnerable (for documentation).

        This test shows the attack that was possible before the fix.
        """
        from deadrop.crypto import derive_epoch_key, compute_membership_hash
        import os

        room_id = "test-room"
        base_secret = os.urandom(32)

        # Original members
        members_with_bob = ["alice", "bob", "carol"]
        hash_with_bob = compute_membership_hash(members_with_bob)
        epoch_key_0 = derive_epoch_key(base_secret, 0, room_id, hash_with_bob)

        # Bob removed - if we use HKDF derivation:
        members_without_bob = ["alice", "carol"]
        hash_without_bob = compute_membership_hash(members_without_bob)

        # This is how the OLD implementation would derive the new key
        epoch_key_1_hkdf = derive_epoch_key(epoch_key_0, 1, room_id, hash_without_bob)

        # Bob has epoch_key_0 and can guess the new membership
        # Bob computes:
        bob_computed = derive_epoch_key(epoch_key_0, 1, room_id, hash_without_bob)

        # WITH HKDF DERIVATION: Bob can compute the new key!
        assert bob_computed == epoch_key_1_hkdf, (
            "This test demonstrates the vulnerability - Bob CAN derive with HKDF"
        )

        # This is why we MUST use fresh random secrets for member removal
