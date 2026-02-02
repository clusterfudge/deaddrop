"""Tests for room epoch management functions."""

import pytest
from deadrop import db


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
