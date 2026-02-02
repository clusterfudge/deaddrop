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
