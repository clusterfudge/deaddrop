"""Test true E2E flow where server never sees plaintext secrets."""

from deadrop import db
from deadrop.crypto import (
    generate_keypair,
    generate_room_base_secret,
    encrypt_base_secret_for_member,
    decrypt_base_secret_from_invite,
)


class TestTrueE2EFlow:
    """Test the complete true E2E flow where server never sees plaintext secrets."""

    def test_room_creation_without_server_seeing_secret(self):
        """Server should not store plaintext base_secret for E2E rooms."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        alice_kp = generate_keypair()
        db.create_pubkey(
            ns["ns"], alice["id"], alice_kp.public_key_base64, alice_kp.signing_public_key_base64
        )

        room = db.create_room(ns["ns"], alice["id"], "E2E Room")
        base_secret = generate_room_base_secret()

        alice_encrypted = encrypt_base_secret_for_member(
            base_secret, alice_kp.public_key, alice_kp.private_key, room["room_id"]
        )

        db.initialize_room_encryption_e2e(
            room_id=room["room_id"],
            creator_id=alice["id"],
            encrypted_base_secret=alice_encrypted.hex(),
            creator_public_key=alice_kp.public_key_base64,
        )

        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["encryption_enabled"] == 1
        assert room_info["base_secret"] is None, "Server should NOT have plaintext base_secret!"

    def test_add_member_with_client_side_encryption(self):
        """Adding a member should use client-side encrypted secrets."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])

        alice_kp = generate_keypair()
        bob_kp = generate_keypair()

        db.create_pubkey(
            ns["ns"], alice["id"], alice_kp.public_key_base64, alice_kp.signing_public_key_base64
        )
        db.create_pubkey(
            ns["ns"], bob["id"], bob_kp.public_key_base64, bob_kp.signing_public_key_base64
        )

        # Create room and initialize E2E
        room = db.create_room(ns["ns"], alice["id"], "E2E Room")
        base_secret = generate_room_base_secret()
        alice_encrypted = encrypt_base_secret_for_member(
            base_secret, alice_kp.public_key, alice_kp.private_key, room["room_id"]
        )
        db.initialize_room_encryption_e2e(
            room["room_id"], alice["id"], alice_encrypted.hex(), alice_kp.public_key_base64
        )

        # Add Bob (membership only, no server-side key distribution)
        db.add_room_member(room["room_id"], bob["id"])

        # Alice creates new secret and encrypts for both
        new_secret = generate_room_base_secret()
        alice_enc = encrypt_base_secret_for_member(
            new_secret, alice_kp.public_key, alice_kp.private_key, room["room_id"]
        )
        bob_enc = encrypt_base_secret_for_member(
            new_secret, bob_kp.public_key, alice_kp.private_key, room["room_id"]
        )

        # Rotate with client-provided secrets
        db.rotate_room_secret_e2e(
            room["room_id"],
            new_secret_version=1,
            member_secrets=[
                {
                    "identity_id": alice["id"],
                    "encrypted_base_secret": alice_enc.hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
                {
                    "identity_id": bob["id"],
                    "encrypted_base_secret": bob_enc.hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
            ],
        )

        # Verify Bob can decrypt
        bob_stored = db.get_member_secret(room["room_id"], bob["id"])
        bob_decrypted = decrypt_base_secret_from_invite(
            bytes.fromhex(bob_stored["encrypted_base_secret"]),
            alice_kp.public_key,
            bob_kp.private_key,
            room["room_id"],
        )
        assert bob_decrypted == new_secret

        # Server still doesn't have plaintext
        room_info = db.get_room_with_encryption(room["room_id"])
        assert room_info["base_secret"] is None

    def test_full_e2e_flow_three_members(self):
        """Complete test: create room, add 2 members, verify all can decrypt."""
        ns = db.create_namespace()
        alice = db.create_identity(ns["ns"])
        bob = db.create_identity(ns["ns"])
        carol = db.create_identity(ns["ns"])

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

        # Alice creates room with E2E
        room = db.create_room(ns["ns"], alice["id"], "Team Room")
        secret_v0 = generate_room_base_secret()
        alice_enc_v0 = encrypt_base_secret_for_member(
            secret_v0, alice_kp.public_key, alice_kp.private_key, room["room_id"]
        )
        db.initialize_room_encryption_e2e(
            room["room_id"], alice["id"], alice_enc_v0.hex(), alice_kp.public_key_base64
        )

        # Add Bob
        db.add_room_member(room["room_id"], bob["id"])
        secret_v1 = generate_room_base_secret()
        db.rotate_room_secret_e2e(
            room["room_id"],
            new_secret_version=1,
            member_secrets=[
                {
                    "identity_id": alice["id"],
                    "encrypted_base_secret": encrypt_base_secret_for_member(
                        secret_v1, alice_kp.public_key, alice_kp.private_key, room["room_id"]
                    ).hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
                {
                    "identity_id": bob["id"],
                    "encrypted_base_secret": encrypt_base_secret_for_member(
                        secret_v1, bob_kp.public_key, alice_kp.private_key, room["room_id"]
                    ).hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
            ],
        )

        # Add Carol
        db.add_room_member(room["room_id"], carol["id"])
        secret_v2 = generate_room_base_secret()
        db.rotate_room_secret_e2e(
            room["room_id"],
            new_secret_version=2,
            member_secrets=[
                {
                    "identity_id": alice["id"],
                    "encrypted_base_secret": encrypt_base_secret_for_member(
                        secret_v2, alice_kp.public_key, alice_kp.private_key, room["room_id"]
                    ).hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
                {
                    "identity_id": bob["id"],
                    "encrypted_base_secret": encrypt_base_secret_for_member(
                        secret_v2, bob_kp.public_key, alice_kp.private_key, room["room_id"]
                    ).hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
                {
                    "identity_id": carol["id"],
                    "encrypted_base_secret": encrypt_base_secret_for_member(
                        secret_v2, carol_kp.public_key, alice_kp.private_key, room["room_id"]
                    ).hex(),
                    "inviter_public_key": alice_kp.public_key_base64,
                },
            ],
        )

        # Verify all can decrypt current secret
        for identity, kp, name in [
            (alice, alice_kp, "Alice"),
            (bob, bob_kp, "Bob"),
            (carol, carol_kp, "Carol"),
        ]:
            stored = db.get_member_secret(room["room_id"], identity["id"])
            decrypted = decrypt_base_secret_from_invite(
                bytes.fromhex(stored["encrypted_base_secret"]),
                alice_kp.public_key,  # Alice encrypted all
                kp.private_key,
                room["room_id"],
            )
            assert decrypted == secret_v2, f"{name} should decrypt to current secret"

        # Final check: server never saw plaintext
        room_final = db.get_room_with_encryption(room["room_id"])
        assert room_final["base_secret"] is None
        assert room_final["secret_version"] == 2
        assert len(db.list_room_members(room["room_id"])) == 3
