"""End-to-end tests for room encryption with forward secrecy.

These tests validate the complete encryption lifecycle including:
- Room creation with encryption
- Member join/leave with epoch rotation
- Message encryption/decryption
- Forward secrecy (new members can't read old messages)
- Post-compromise security (removed members can't read new messages)
"""

import json

import pytest
from nacl.exceptions import CryptoError

from deadrop import db
from deadrop.crypto import (
    bytes_to_base64url,
    base64url_to_bytes,
    compute_membership_hash,
    derive_epoch_key,
    encrypt_base_secret_for_member,
    encrypt_room_message,
    decrypt_room_message,
    EncryptedRoomMessage,
    generate_keypair,
    generate_room_base_secret,
)

# Test constants for replay protection
TEST_SENDER_ID = "test-sender-123"
TEST_TIMESTAMP = "2026-01-01T00:00:00Z"
TEST_MESSAGE_ID = "test-msg-001"


class TestEncryptedRoomFullLifecycle:
    """Test the complete lifecycle of an encrypted room."""

    def test_full_lifecycle(self):
        """Test the complete encrypted room workflow.

        Scenario:
        1. Alice creates encrypted room
        2. Alice invites Bob (Bob has pubkey) - epoch rotates
        3. Alice sends encrypted message
        4. Bob receives and decrypts message
        5. Bob sends encrypted message
        6. Alice receives and decrypts
        7. Carol (no pubkey) tries to join - fails
        8. Carol registers pubkey, joins - epoch rotates
        9. Carol cannot decrypt messages from before join (forward secrecy)
        10. Bob is removed - epoch rotates
        11. Alice sends new message
        12. Bob cannot decrypt new message (post-compromise security)
        """
        # Setup
        ns = db.create_namespace()

        # Create Alice with keypair
        alice = db.create_identity(ns["ns"])
        alice_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            alice["id"],
            bytes_to_base64url(alice_kp.public_key),
            bytes_to_base64url(alice_kp.signing_public_key),
        )

        # Create Bob with keypair
        bob = db.create_identity(ns["ns"])
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        # Create Carol without keypair initially
        carol = db.create_identity(ns["ns"])

        # === Step 1: Alice creates encrypted room ===
        room = db.create_room(ns["ns"], alice["id"])
        db.initialize_room_encryption(
            room["room_id"],
            base_secret=b"test_secret_32_bytes_long_ok!",
            triggered_by=alice["id"],
        )

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["encryption_enabled"] == 1
        assert room_info["current_epoch_number"] == 0

        # Alice gets her epoch 0 key
        alice_epoch0_key_record = db.get_epoch_key_for_identity(room["room_id"], 0, alice["id"])
        assert alice_epoch0_key_record is not None
        base64url_to_bytes(alice_epoch0_key_record["encrypted_epoch_key"])  # Verify key exists

        # === Step 2: Alice invites Bob - epoch rotates to 1 ===
        db.add_room_member(room["room_id"], bob["id"])

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 1

        # Both Alice and Bob have epoch 1 keys
        alice_epoch1_key_record = db.get_epoch_key_for_identity(room["room_id"], 1, alice["id"])
        bob_epoch1_key_record = db.get_epoch_key_for_identity(room["room_id"], 1, bob["id"])
        assert alice_epoch1_key_record is not None
        assert bob_epoch1_key_record is not None

        # Bob doesn't have epoch 0 key (joined after)
        bob_epoch0_key_record = db.get_epoch_key_for_identity(room["room_id"], 0, bob["id"])
        assert bob_epoch0_key_record is None

        # === Step 3: Alice sends encrypted message ===
        # Alice uses epoch 1 key
        alice_epoch1_key = base64url_to_bytes(alice_epoch1_key_record["encrypted_epoch_key"])

        plaintext = "Hello Bob, this is a secret message!"
        encrypted = encrypt_room_message(
            plaintext=plaintext,
            epoch_key=alice_epoch1_key,
            sender_signing_key=alice_kp.private_key,
            room_id=room["room_id"],
            epoch_number=1,
            sender_id=TEST_SENDER_ID,
            timestamp=TEST_TIMESTAMP,
            message_id=TEST_MESSAGE_ID,
        )

        # Store encrypted message
        db.send_room_message(
            room_id=room["room_id"],
            from_id=alice["id"],
            body=bytes_to_base64url(encrypted.ciphertext),
            epoch_number=1,
            encrypted=True,
            encryption_meta=json.dumps(
                {
                    "algorithm": "xsalsa20-poly1305+ed25519",
                    "nonce": bytes_to_base64url(encrypted.nonce),
                }
            ),
            signature=bytes_to_base64url(encrypted.signature),
        )

        # === Step 4: Bob receives and decrypts message ===
        messages = db.get_room_messages(room["room_id"])
        assert len(messages) == 1
        assert messages[0]["encrypted"] is True
        assert messages[0]["epoch_number"] == 1

        # Bob decrypts with his epoch 1 key
        bob_epoch1_key = base64url_to_bytes(bob_epoch1_key_record["encrypted_epoch_key"])

        # Reconstruct EncryptedRoomMessage from stored data
        stored_meta = json.loads(messages[0]["encryption_meta"])
        encrypted_msg = EncryptedRoomMessage(
            ciphertext=base64url_to_bytes(messages[0]["body"]),
            nonce=base64url_to_bytes(stored_meta["nonce"]),
            signature=base64url_to_bytes(messages[0]["signature"]),
        )

        decrypted = decrypt_room_message(
            encrypted_msg,
            bob_epoch1_key,
            alice_kp.signing_public_key,
            room["room_id"],
            1,
            TEST_SENDER_ID,
            TEST_TIMESTAMP,
            TEST_MESSAGE_ID,
        )
        assert decrypted == plaintext

        # === Step 5: Bob sends encrypted message ===
        bob_plaintext = "Hi Alice, I received your secret!"
        bob_encrypted = encrypt_room_message(
            plaintext=bob_plaintext,
            epoch_key=bob_epoch1_key,
            sender_signing_key=bob_kp.private_key,
            room_id=room["room_id"],
            epoch_number=1,
            sender_id=TEST_SENDER_ID,
            timestamp=TEST_TIMESTAMP,
            message_id=TEST_MESSAGE_ID,
        )

        db.send_room_message(
            room_id=room["room_id"],
            from_id=bob["id"],
            body=bytes_to_base64url(bob_encrypted.ciphertext),
            epoch_number=1,
            encrypted=True,
            encryption_meta=json.dumps(
                {
                    "algorithm": "xsalsa20-poly1305+ed25519",
                    "nonce": bytes_to_base64url(bob_encrypted.nonce),
                }
            ),
            signature=bytes_to_base64url(bob_encrypted.signature),
        )

        # === Step 6: Alice receives and decrypts Bob's message ===
        messages = db.get_room_messages(room["room_id"])
        assert len(messages) == 2

        bob_msg = messages[1]
        bob_stored_meta = json.loads(bob_msg["encryption_meta"])
        bob_encrypted_msg = EncryptedRoomMessage(
            ciphertext=base64url_to_bytes(bob_msg["body"]),
            nonce=base64url_to_bytes(bob_stored_meta["nonce"]),
            signature=base64url_to_bytes(bob_msg["signature"]),
        )

        decrypted_bob = decrypt_room_message(
            bob_encrypted_msg,
            alice_epoch1_key,
            bob_kp.signing_public_key,
            room["room_id"],
            1,
            TEST_SENDER_ID,
            TEST_TIMESTAMP,
            TEST_MESSAGE_ID,
        )
        assert decrypted_bob == bob_plaintext

        # === Step 7: Carol (no pubkey) tries to join - fails ===
        with pytest.raises(ValueError, match="must have a registered pubkey"):
            db.add_room_member(room["room_id"], carol["id"])

        # === Step 8: Carol registers pubkey, joins - epoch rotates to 2 ===
        carol_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            carol["id"],
            bytes_to_base64url(carol_kp.public_key),
            bytes_to_base64url(carol_kp.signing_public_key),
        )

        db.add_room_member(room["room_id"], carol["id"])

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 2

        # Carol has epoch 2 key
        carol_epoch2_key_record = db.get_epoch_key_for_identity(room["room_id"], 2, carol["id"])
        assert carol_epoch2_key_record is not None

        # === Step 9: Carol cannot decrypt messages from before join (forward secrecy) ===
        # Carol doesn't have epoch 1 key
        carol_epoch1_key_record = db.get_epoch_key_for_identity(room["room_id"], 1, carol["id"])
        assert carol_epoch1_key_record is None

        # Even if Carol tries to use her epoch 2 key on epoch 1 message, it fails
        carol_epoch2_key = base64url_to_bytes(carol_epoch2_key_record["encrypted_epoch_key"])

        with pytest.raises(CryptoError):
            decrypt_room_message(
                encrypted_msg,  # Message from epoch 1
                carol_epoch2_key,  # Wrong key for epoch 1 message
                alice_kp.signing_public_key,
                room["room_id"],
                1,
                TEST_SENDER_ID,
                TEST_TIMESTAMP,
                TEST_MESSAGE_ID,
            )

        # === Step 10: Bob is removed - epoch rotates to 3 ===
        db.remove_room_member(room["room_id"], bob["id"])

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 3

        # Bob doesn't have epoch 3 key
        bob_epoch3_key_record = db.get_epoch_key_for_identity(room["room_id"], 3, bob["id"])
        assert bob_epoch3_key_record is None

        # Alice and Carol have epoch 3 keys
        alice_epoch3_key_record = db.get_epoch_key_for_identity(room["room_id"], 3, alice["id"])
        carol_epoch3_key_record = db.get_epoch_key_for_identity(room["room_id"], 3, carol["id"])
        assert alice_epoch3_key_record is not None
        assert carol_epoch3_key_record is not None

        # === Step 11: Alice sends new message at epoch 3 ===
        alice_epoch3_key = base64url_to_bytes(alice_epoch3_key_record["encrypted_epoch_key"])

        secret_from_bob = "This message is secret from Bob!"
        alice_encrypted3 = encrypt_room_message(
            plaintext=secret_from_bob,
            epoch_key=alice_epoch3_key,
            sender_signing_key=alice_kp.private_key,
            room_id=room["room_id"],
            epoch_number=3,
            sender_id=TEST_SENDER_ID,
            timestamp=TEST_TIMESTAMP,
            message_id=TEST_MESSAGE_ID,
        )

        db.send_room_message(
            room_id=room["room_id"],
            from_id=alice["id"],
            body=bytes_to_base64url(alice_encrypted3.ciphertext),
            epoch_number=3,
            encrypted=True,
            encryption_meta=json.dumps(
                {
                    "algorithm": "xsalsa20-poly1305+ed25519",
                    "nonce": bytes_to_base64url(alice_encrypted3.nonce),
                }
            ),
            signature=bytes_to_base64url(alice_encrypted3.signature),
        )

        # Reconstruct message for decryption attempts
        msg3_encrypted = EncryptedRoomMessage(
            ciphertext=alice_encrypted3.ciphertext,
            nonce=alice_encrypted3.nonce,
            signature=alice_encrypted3.signature,
        )

        # === Step 12: Bob cannot decrypt new message (post-compromise security) ===
        # Bob only has epoch 1 key, not epoch 3
        with pytest.raises(CryptoError):
            decrypt_room_message(
                msg3_encrypted,
                bob_epoch1_key,  # Bob's old key
                alice_kp.signing_public_key,
                room["room_id"],
                3,
                TEST_SENDER_ID,
                TEST_TIMESTAMP,
                TEST_MESSAGE_ID,
            )

        # But Carol can decrypt (she has epoch 3 key)
        carol_epoch3_key = base64url_to_bytes(carol_epoch3_key_record["encrypted_epoch_key"])

        carol_decrypted = decrypt_room_message(
            msg3_encrypted,
            carol_epoch3_key,
            alice_kp.signing_public_key,
            room["room_id"],
            3,
            TEST_SENDER_ID,
            TEST_TIMESTAMP,
            TEST_MESSAGE_ID,
        )
        assert carol_decrypted == secret_from_bob


class TestEpochMismatchAndRetry:
    """Test the epoch mismatch and retry workflow."""

    def test_epoch_mismatch_retry_workflow(self):
        """Test that stale epoch is rejected and client can retry.

        Scenario:
        1. Alice and Bob in encrypted room at epoch N
        2. Bob fetches epoch key (epoch N)
        3. Carol joins (triggers rotation to epoch N+1)
        4. Bob tries to send message with epoch N key
        5. Server returns EpochMismatchError with current_epoch=N+1
        6. Bob fetches new epoch key
        7. Bob retries with epoch N+1 - succeeds
        """
        # Setup
        ns = db.create_namespace()

        # Create users with keypairs
        alice = db.create_identity(ns["ns"])
        alice_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            alice["id"],
            bytes_to_base64url(alice_kp.public_key),
            bytes_to_base64url(alice_kp.signing_public_key),
        )

        bob = db.create_identity(ns["ns"])
        bob_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            bob["id"],
            bytes_to_base64url(bob_kp.public_key),
            bytes_to_base64url(bob_kp.signing_public_key),
        )

        carol = db.create_identity(ns["ns"])
        carol_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"],
            carol["id"],
            bytes_to_base64url(carol_kp.public_key),
            bytes_to_base64url(carol_kp.signing_public_key),
        )

        # Create encrypted room and add Bob (epoch 0 -> 1)
        room = db.create_room(ns["ns"], alice["id"])
        db.initialize_room_encryption(
            room["room_id"],
            base_secret=b"test_secret_32_bytes_long_ok!",
            triggered_by=alice["id"],
        )
        db.add_room_member(room["room_id"], bob["id"])  # Epoch 1

        # Rotate a few more times to get to epoch 5
        for _ in range(4):
            db.rotate_room_epoch(room["room_id"], "manual")

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 5

        # === Step 2: Bob fetches epoch 5 key ===
        bob_epoch5_key_record = db.get_epoch_key_for_identity(room["room_id"], 5, bob["id"])
        bob_epoch5_key = base64url_to_bytes(bob_epoch5_key_record["encrypted_epoch_key"])

        # === Step 3: Carol joins (triggers rotation to epoch 6) ===
        db.add_room_member(room["room_id"], carol["id"])

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 6

        # === Step 4: Bob tries to send with epoch 5 - server rejects ===
        plaintext = "Hello from Bob!"
        encrypted = encrypt_room_message(
            plaintext=plaintext,
            epoch_key=bob_epoch5_key,
            sender_signing_key=bob_kp.private_key,
            room_id=room["room_id"],
            epoch_number=5,
            sender_id=TEST_SENDER_ID,
            timestamp=TEST_TIMESTAMP,
            message_id=TEST_MESSAGE_ID,
        )

        # === Step 5: Server returns EpochMismatchError ===
        with pytest.raises(db.EpochMismatchError) as exc_info:
            db.send_room_message(
                room_id=room["room_id"],
                from_id=bob["id"],
                body=bytes_to_base64url(encrypted.ciphertext),
                epoch_number=5,  # Stale!
                encrypted=True,
            )

        assert exc_info.value.expected_epoch == 6
        assert exc_info.value.provided_epoch == 5

        # === Step 6: Bob fetches new epoch 6 key ===
        bob_epoch6_key_record = db.get_epoch_key_for_identity(room["room_id"], 6, bob["id"])
        bob_epoch6_key = base64url_to_bytes(bob_epoch6_key_record["encrypted_epoch_key"])

        # === Step 7: Bob retries with epoch 6 - succeeds ===
        encrypted_retry = encrypt_room_message(
            plaintext=plaintext,
            epoch_key=bob_epoch6_key,
            sender_signing_key=bob_kp.private_key,
            room_id=room["room_id"],
            epoch_number=6,
            sender_id=TEST_SENDER_ID,
            timestamp=TEST_TIMESTAMP,
            message_id=TEST_MESSAGE_ID,
        )

        msg = db.send_room_message(
            room_id=room["room_id"],
            from_id=bob["id"],
            body=bytes_to_base64url(encrypted_retry.ciphertext),
            epoch_number=6,
            encrypted=True,
            signature=bytes_to_base64url(encrypted_retry.signature),
        )

        assert msg["epoch_number"] == 6
        assert msg["encrypted"] is True


class TestOfflineMemberCatchup:
    """Test that offline members can catch up on epoch keys."""

    def test_offline_member_catches_up(self):
        """Test that a member who goes offline can catch up.

        Scenario:
        1. Alice, Bob, Carol in encrypted room at epoch 3
        2. Bob goes 'offline' (doesn't fetch new epochs)
        3. Dave joins (epoch 4)
        4. Eve joins (epoch 5)
        5. Messages sent at epochs 4 and 5
        6. Bob comes back, fetches epoch keys 4 and 5
        7. Bob can decrypt all messages from epochs 4 and 5
        """
        # Setup
        ns = db.create_namespace()

        # Create all users with keypairs
        users = {}
        for name in ["alice", "bob", "carol", "dave", "eve"]:
            user = db.create_identity(ns["ns"])
            kp = generate_keypair()
            db.create_pubkey(
                ns["ns"],
                user["id"],
                bytes_to_base64url(kp.public_key),
                bytes_to_base64url(kp.signing_public_key),
            )
            users[name] = {"identity": user, "keypair": kp}

        # Create encrypted room with Alice, add Bob and Carol
        room = db.create_room(ns["ns"], users["alice"]["identity"]["id"])
        db.initialize_room_encryption(
            room["room_id"],
            base_secret=b"test_secret_32_bytes_long_ok!",
            triggered_by=users["alice"]["identity"]["id"],
        )

        db.add_room_member(room["room_id"], users["bob"]["identity"]["id"])  # Epoch 1
        db.add_room_member(room["room_id"], users["carol"]["identity"]["id"])  # Epoch 2

        # Rotate to epoch 3
        db.rotate_room_epoch(room["room_id"], "manual")

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 3

        # === Step 2: Bob goes offline (just doesn't fetch new keys) ===
        # Bob has epoch 3 key
        bob_epoch3_key_record = db.get_epoch_key_for_identity(
            room["room_id"], 3, users["bob"]["identity"]["id"]
        )
        assert bob_epoch3_key_record is not None

        # === Step 3: Dave joins (epoch 4) ===
        db.add_room_member(room["room_id"], users["dave"]["identity"]["id"])

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 4

        # === Step 4: Eve joins (epoch 5) ===
        db.add_room_member(room["room_id"], users["eve"]["identity"]["id"])

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["current_epoch_number"] == 5

        # === Step 5: Messages sent at epoch 5 ===
        alice_epoch5_key_record = db.get_epoch_key_for_identity(
            room["room_id"], 5, users["alice"]["identity"]["id"]
        )
        alice_epoch5_key = base64url_to_bytes(alice_epoch5_key_record["encrypted_epoch_key"])

        msg5_plain = "Message at epoch 5!"
        msg5_encrypted = encrypt_room_message(
            plaintext=msg5_plain,
            epoch_key=alice_epoch5_key,
            sender_signing_key=users["alice"]["keypair"].private_key,
            room_id=room["room_id"],
            epoch_number=5,
            sender_id=TEST_SENDER_ID,
            timestamp=TEST_TIMESTAMP,
            message_id=TEST_MESSAGE_ID,
        )

        db.send_room_message(
            room_id=room["room_id"],
            from_id=users["alice"]["identity"]["id"],
            body=bytes_to_base64url(msg5_encrypted.ciphertext),
            epoch_number=5,
            encrypted=True,
            encryption_meta=json.dumps(
                {
                    "algorithm": "xsalsa20-poly1305+ed25519",
                    "nonce": bytes_to_base64url(msg5_encrypted.nonce),
                }
            ),
            signature=bytes_to_base64url(msg5_encrypted.signature),
        )

        # === Step 6: Bob comes back, fetches epoch keys 4 and 5 ===
        bob_epoch4_key_record = db.get_epoch_key_for_identity(
            room["room_id"], 4, users["bob"]["identity"]["id"]
        )
        bob_epoch5_key_record = db.get_epoch_key_for_identity(
            room["room_id"], 5, users["bob"]["identity"]["id"]
        )

        # Bob has keys for epochs 4 and 5 (he was a member when they were created)
        assert bob_epoch4_key_record is not None
        assert bob_epoch5_key_record is not None

        # === Step 7: Bob can decrypt epoch 5 message ===
        bob_epoch5_key = base64url_to_bytes(bob_epoch5_key_record["encrypted_epoch_key"])

        messages = db.get_room_messages(room["room_id"])
        epoch5_msg = [m for m in messages if m.get("epoch_number") == 5][0]

        # Reconstruct EncryptedRoomMessage
        stored_meta = json.loads(epoch5_msg["encryption_meta"])
        encrypted_msg = EncryptedRoomMessage(
            ciphertext=base64url_to_bytes(epoch5_msg["body"]),
            nonce=base64url_to_bytes(stored_meta["nonce"]),
            signature=base64url_to_bytes(epoch5_msg["signature"]),
        )

        decrypted = decrypt_room_message(
            encrypted_msg,
            bob_epoch5_key,
            users["alice"]["keypair"].signing_public_key,
            room["room_id"],
            5,
            TEST_SENDER_ID,
            TEST_TIMESTAMP,
            TEST_MESSAGE_ID,
        )

        assert decrypted == msg5_plain


class TestTwoPhaseExitProtocol:
    """Integration tests for the two-phase exit protocol.

    These tests verify the complete flow from member exit request
    through secret rotation to finalized removal.
    """

    def test_voluntary_exit_two_phase_flow(self):
        """Test complete voluntary exit flow with two-phase protocol."""
        # Setup: Alice, Bob, Carol in an E2E room
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])

        # Create keypairs
        alice_kp = generate_keypair()
        bob_kp = generate_keypair()
        carol_kp = generate_keypair()

        db.create_pubkey(
            ns["ns"], alice["id"], alice_kp.public_key_base64, alice_kp.signing_public_key_base64
        )
        db.create_pubkey(
            ns["ns"], bob["id"], bob_kp.public_key_base64, bob_kp.signing_public_key_base64
        )
        db.create_pubkey(
            ns["ns"], carol["id"], carol_kp.public_key_base64, carol_kp.signing_public_key_base64
        )

        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])
        db.add_room_member(room["room_id"], carol["id"])

        # Initialize E2E encryption
        base_secret_v0 = generate_room_base_secret()
        db.initialize_room_encryption_e2e(
            room["room_id"],
            alice["id"],
            encrypt_base_secret_for_member(
                base_secret_v0, alice_kp.public_key, alice_kp.private_key, room["room_id"]
            ).hex(),
            alice_kp.public_key_base64,
        )
        db.store_member_secret(
            room["room_id"],
            bob["id"],
            encrypt_base_secret_for_member(
                base_secret_v0, bob_kp.public_key, alice_kp.private_key, room["room_id"]
            ).hex(),
            alice_kp.public_key_base64,
            0,
        )
        db.store_member_secret(
            room["room_id"],
            carol["id"],
            encrypt_base_secret_for_member(
                base_secret_v0, carol_kp.public_key, alice_kp.private_key, room["room_id"]
            ).hex(),
            alice_kp.public_key_base64,
            0,
        )

        # Step 1: Bob requests to leave (triggers pending removal)
        result = db.remove_room_member(room["room_id"], bob["id"])
        assert result["pending"] is True
        assert result["pending_removal_id"] == bob["id"]

        # Bob is still a member at this point
        assert db.is_room_member(room["room_id"], bob["id"])

        # Step 2: Alice generates FRESH random secret (not derived!)
        base_secret_v1 = generate_room_base_secret()
        assert base_secret_v0 != base_secret_v1  # Must be fresh

        # Step 3: Alice encrypts new secret for remaining members (Alice + Carol, NOT Bob)
        enc_alice_v1 = encrypt_base_secret_for_member(
            base_secret_v1, alice_kp.public_key, alice_kp.private_key, room["room_id"]
        ).hex()
        enc_carol_v1 = encrypt_base_secret_for_member(
            base_secret_v1, carol_kp.public_key, alice_kp.private_key, room["room_id"]
        ).hex()

        # Step 4: Alice rotates secret and finalizes Bob's removal
        rotate_result = db.rotate_room_secret_e2e(
            room_id=room["room_id"],
            new_secret_version=1,
            member_secrets=[
                {
                    "identity_id": alice["id"],
                    "encrypted_base_secret": enc_alice_v1,
                    "inviter_public_key": alice_kp.public_key_base64,
                },
                {
                    "identity_id": carol["id"],
                    "encrypted_base_secret": enc_carol_v1,
                    "inviter_public_key": alice_kp.public_key_base64,
                },
            ],
            triggered_by=alice["id"],
            finalize_removal=bob["id"],
        )

        assert rotate_result["secret_version"] == 1
        assert rotate_result["removed_member"] == bob["id"]

        # Step 5: Verify Bob is now removed
        assert not db.is_room_member(room["room_id"], bob["id"])
        assert db.is_room_member(room["room_id"], alice["id"])
        assert db.is_room_member(room["room_id"], carol["id"])

        # Step 6: Verify Bob cannot derive the new secret
        # Bob only has base_secret_v0, Alice and Carol have base_secret_v1
        # The secrets are different, so Bob cannot read new messages

        # Step 7: Verify Alice and Carol can derive new epoch key
        members_v1 = [alice["id"], carol["id"]]
        hash_v1 = compute_membership_hash(members_v1)
        epoch_key_v1 = derive_epoch_key(base_secret_v1, 0, room["room_id"], hash_v1)

        # Bob tries to derive with his old secret
        bob_attempt = derive_epoch_key(base_secret_v0, 1, room["room_id"], hash_v1)

        assert bob_attempt != epoch_key_v1, "Bob should NOT be able to derive new key!"

    def test_cancel_pending_exit(self):
        """Test that pending exit can be cancelled."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        db.create_pubkey(ns["ns"], alice["id"], "pk_a", "spk_a")
        db.create_pubkey(ns["ns"], bob["id"], "pk_b", "spk_b")
        room = db.create_room(ns["ns"], alice["id"], "Test Room")
        db.add_room_member(room["room_id"], bob["id"])

        # Initialize E2E
        db.initialize_room_encryption_e2e(room["room_id"], alice["id"], "encrypted", "pubkey")

        # Bob requests to leave
        result = db.remove_room_member(room["room_id"], bob["id"])
        assert result["pending"] is True

        # Bob changes mind and cancels
        db.clear_pending_removal(room["room_id"])

        # No pending removal
        assert db.get_pending_removal(room["room_id"]) is None

        # Bob is still a member
        assert db.is_room_member(room["room_id"], bob["id"])
