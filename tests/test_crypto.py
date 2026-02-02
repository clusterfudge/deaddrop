"""Tests for the crypto module."""

import pytest
from cryptography.exceptions import InvalidTag

from deadrop.crypto import (
    base64url_to_bytes,
    bytes_to_base64url,
    create_invite_secrets,
    decrypt_invite_secret,
    decrypt_secret,
    encrypt_secret,
    generate_invite_id,
    generate_key,
)


class TestKeyGeneration:
    """Tests for key generation functions."""

    def test_generate_key_length(self):
        """Generated key should be 32 bytes."""
        key = generate_key()
        assert len(key) == 32

    def test_generate_key_randomness(self):
        """Generated keys should be unique."""
        keys = [generate_key() for _ in range(10)]
        assert len(set(keys)) == 10

    def test_generate_invite_id_length(self):
        """Invite ID should be 32 hex characters."""
        invite_id = generate_invite_id()
        assert len(invite_id) == 32
        # Should be valid hex
        int(invite_id, 16)

    def test_generate_invite_id_randomness(self):
        """Invite IDs should be unique."""
        ids = [generate_invite_id() for _ in range(10)]
        assert len(set(ids)) == 10


class TestEncryptionDecryption:
    """Tests for encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt to original plaintext."""
        plaintext = "this is a secret message"
        key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, key, invite_id)
        decrypted = decrypt_secret(encrypted, key, invite_id)

        assert decrypted == plaintext

    def test_encrypt_decrypt_mailbox_secret(self):
        """Should handle 64-char hex mailbox secrets."""
        mailbox_secret = "a" * 64  # 64 hex chars
        key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(mailbox_secret, key, invite_id)
        decrypted = decrypt_secret(encrypted, key, invite_id)

        assert decrypted == mailbox_secret

    def test_decrypt_wrong_key_fails(self):
        """Decryption with wrong key should fail."""
        plaintext = "secret"
        key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, key, invite_id)

        with pytest.raises(InvalidTag):
            decrypt_secret(encrypted, generate_key(), invite_id)

    def test_decrypt_wrong_invite_id_fails(self):
        """Decryption with wrong invite_id should fail."""
        plaintext = "secret"
        key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, key, invite_id)

        with pytest.raises(InvalidTag):
            decrypt_secret(encrypted, key, generate_invite_id())

    def test_encrypted_data_includes_nonce(self):
        """Encrypted data should be longer than plaintext (includes nonce and tag)."""
        plaintext = "secret"
        key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, key, invite_id)

        # Should include: 12-byte nonce + ciphertext (same length as plaintext) + 16-byte tag
        # So minimum length is: 12 + len(plaintext) + 16 = 28 + len(plaintext)
        assert len(encrypted) >= len(plaintext.encode()) + 12 + 16

    def test_encryption_produces_different_ciphertext(self):
        """Same plaintext should produce different ciphertext (random nonce)."""
        plaintext = "secret"
        key = generate_key()
        invite_id = generate_invite_id()

        encrypted1 = encrypt_secret(plaintext, key, invite_id)
        encrypted2 = encrypt_secret(plaintext, key, invite_id)

        # Different nonces mean different ciphertext
        assert encrypted1 != encrypted2

        # But both should decrypt to same plaintext
        assert decrypt_secret(encrypted1, key, invite_id) == plaintext
        assert decrypt_secret(encrypted2, key, invite_id) == plaintext


class TestBase64Encoding:
    """Tests for base64url encoding/decoding."""

    def test_roundtrip(self):
        """Data should survive encode/decode cycle."""
        data = generate_key()
        encoded = bytes_to_base64url(data)
        decoded = base64url_to_bytes(encoded)
        assert decoded == data

    def test_url_safe(self):
        """Encoded data should be URL-safe (no +, /, or =)."""
        # Generate many keys to ensure we hit edge cases
        for _ in range(100):
            data = generate_key()
            encoded = bytes_to_base64url(data)
            assert "+" not in encoded
            assert "/" not in encoded
            assert "=" not in encoded

    def test_handles_missing_padding(self):
        """Should handle base64 with missing padding."""
        data = b"test"
        encoded = bytes_to_base64url(data)
        # Manually add padding and decode
        decoded = base64url_to_bytes(encoded)
        assert decoded == data


class TestInviteSecrets:
    """Tests for the InviteSecrets helper."""

    def test_create_invite_secrets(self):
        """Should create all necessary secrets for an invite."""
        mailbox_secret = "a" * 64
        secrets = create_invite_secrets(mailbox_secret)

        assert len(secrets.invite_id) == 32
        assert len(secrets.key) == 32
        assert len(secrets.encrypted_secret) > 0

    def test_invite_secrets_properties(self):
        """Should provide encoded versions for storage/transport."""
        mailbox_secret = "a" * 64
        secrets = create_invite_secrets(mailbox_secret)

        # key_base64 should be URL-safe
        assert "+" not in secrets.key_base64
        assert "/" not in secrets.key_base64

        # encrypted_secret_hex should be valid hex
        int(secrets.encrypted_secret_hex, 16)

    def test_decrypt_invite_secret_helper(self):
        """decrypt_invite_secret should work with encoded formats."""
        mailbox_secret = "b" * 64
        secrets = create_invite_secrets(mailbox_secret)

        decrypted = decrypt_invite_secret(
            encrypted_secret_hex=secrets.encrypted_secret_hex,
            key_base64=secrets.key_base64,
            invite_id=secrets.invite_id,
        )

        assert decrypted == mailbox_secret


class TestSecurityProperties:
    """Tests for security properties of the crypto system."""

    def test_server_cannot_decrypt_without_key(self):
        """Server with only encrypted_secret cannot decrypt."""
        mailbox_secret = "secret123" * 7  # 63 chars
        secrets = create_invite_secrets(mailbox_secret)

        # Server has: encrypted_secret, invite_id
        # Server lacks: key

        # Try with a random key (simulating brute force)
        wrong_key = bytes_to_base64url(generate_key())

        with pytest.raises(InvalidTag):
            decrypt_invite_secret(
                encrypted_secret_hex=secrets.encrypted_secret_hex,
                key_base64=wrong_key,
                invite_id=secrets.invite_id,
            )

    def test_wrong_invite_id_fails(self):
        """Decryption with wrong invite_id fails (AAD mismatch)."""
        mailbox_secret = "topsecret" * 7
        secrets = create_invite_secrets(mailbox_secret)

        with pytest.raises(InvalidTag):
            decrypt_invite_secret(
                encrypted_secret_hex=secrets.encrypted_secret_hex,
                key_base64=secrets.key_base64,
                invite_id=generate_invite_id(),  # Wrong invite_id
            )


# =============================================================================
# E2E Encryption Tests (NaCl box + Ed25519)
# =============================================================================


class TestKeypairGeneration:
    """Tests for keypair generation."""

    def test_generate_keypair_produces_valid_keys(self):
        """Keypair should have 32-byte keys."""
        from deadrop.crypto import generate_keypair

        kp = generate_keypair()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32
        assert len(kp.signing_public_key) == 32

    def test_generate_keypair_randomness(self):
        """Generated keypairs should be unique."""
        from deadrop.crypto import generate_keypair

        keypairs = [generate_keypair() for _ in range(5)]
        private_keys = [kp.private_key for kp in keypairs]
        assert len(set(private_keys)) == 5

    def test_keypair_from_seed_reproducible(self):
        """Same seed should produce same keypair."""
        from deadrop.crypto import KeyPair

        seed = b"x" * 32
        kp1 = KeyPair.from_seed(seed)
        kp2 = KeyPair.from_seed(seed)

        assert kp1.public_key == kp2.public_key
        assert kp1.signing_public_key == kp2.signing_public_key

    def test_keypair_serialization_roundtrip(self):
        """Keypair should serialize/deserialize correctly."""
        from deadrop.crypto import generate_keypair, KeyPair

        kp = generate_keypair()
        serialized = kp.private_key_base64
        restored = KeyPair.from_private_key_base64(serialized)

        assert restored.private_key == kp.private_key
        assert restored.public_key == kp.public_key
        assert restored.signing_public_key == kp.signing_public_key


class TestPubkeyId:
    """Tests for pubkey ID generation."""

    def test_pubkey_id_deterministic(self):
        """Same public key should produce same ID."""
        from deadrop.crypto import generate_keypair, pubkey_id

        kp = generate_keypair()
        id1 = pubkey_id(kp.public_key)
        id2 = pubkey_id(kp.public_key)

        assert id1 == id2

    def test_pubkey_id_format(self):
        """Pubkey ID should be 32 hex characters."""
        from deadrop.crypto import generate_keypair, pubkey_id

        kp = generate_keypair()
        pk_id = pubkey_id(kp.public_key)

        assert len(pk_id) == 32
        # Should be valid hex
        int(pk_id, 16)

    def test_pubkey_id_different_keys(self):
        """Different keys should have different IDs."""
        from deadrop.crypto import generate_keypair, pubkey_id

        kp1 = generate_keypair()
        kp2 = generate_keypair()

        assert pubkey_id(kp1.public_key) != pubkey_id(kp2.public_key)


class TestMessageEncryption:
    """Tests for NaCl box message encryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted message should decrypt correctly."""
        from deadrop.crypto import (
            generate_keypair,
            encrypt_message,
            decrypt_message,
        )

        sender = generate_keypair()
        recipient = generate_keypair()

        plaintext = "Hello, encrypted world!"
        ciphertext = encrypt_message(plaintext, recipient.public_key, sender.private_key)
        decrypted = decrypt_message(ciphertext, sender.public_key, recipient.private_key)

        assert decrypted == plaintext

    def test_encryption_produces_different_ciphertext(self):
        """Same message encrypted twice should produce different ciphertext (random nonce)."""
        from deadrop.crypto import generate_keypair, encrypt_message

        sender = generate_keypair()
        recipient = generate_keypair()

        plaintext = "Same message"
        ct1 = encrypt_message(plaintext, recipient.public_key, sender.private_key)
        ct2 = encrypt_message(plaintext, recipient.public_key, sender.private_key)

        assert ct1 != ct2  # Different nonce each time

    def test_wrong_recipient_key_fails(self):
        """Decryption with wrong key should fail."""
        from deadrop.crypto import generate_keypair, encrypt_message, decrypt_message
        from nacl.exceptions import CryptoError

        sender = generate_keypair()
        recipient = generate_keypair()
        wrong_recipient = generate_keypair()

        ciphertext = encrypt_message("secret", recipient.public_key, sender.private_key)

        with pytest.raises(CryptoError):
            decrypt_message(ciphertext, sender.public_key, wrong_recipient.private_key)

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail decryption."""
        from deadrop.crypto import generate_keypair, encrypt_message, decrypt_message
        from nacl.exceptions import CryptoError

        sender = generate_keypair()
        recipient = generate_keypair()

        ciphertext = encrypt_message("secret", recipient.public_key, sender.private_key)
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

        with pytest.raises(CryptoError):
            decrypt_message(tampered, sender.public_key, recipient.private_key)

    def test_encrypt_unicode(self):
        """Encryption should handle unicode text."""
        from deadrop.crypto import generate_keypair, encrypt_message, decrypt_message

        sender = generate_keypair()
        recipient = generate_keypair()

        plaintext = "Hello 世界! 🔐🔑"
        ciphertext = encrypt_message(plaintext, recipient.public_key, sender.private_key)
        decrypted = decrypt_message(ciphertext, sender.public_key, recipient.private_key)

        assert decrypted == plaintext


class TestMessageSigning:
    """Tests for Ed25519 message signing."""

    def test_sign_verify_roundtrip(self):
        """Signed message should verify correctly."""
        from deadrop.crypto import generate_keypair, sign_message, verify_signature

        kp = generate_keypair()
        message = "This is my authentic message"

        signature = sign_message(message, kp.private_key)
        assert verify_signature(message, signature, kp.signing_public_key)

    def test_signature_length(self):
        """Signature should be 64 bytes."""
        from deadrop.crypto import generate_keypair, sign_message

        kp = generate_keypair()
        signature = sign_message("test", kp.private_key)

        assert len(signature) == 64

    def test_wrong_key_verification_fails(self):
        """Verification with wrong key should fail."""
        from deadrop.crypto import generate_keypair, sign_message, verify_signature

        signer = generate_keypair()
        wrong_key = generate_keypair()

        signature = sign_message("test", signer.private_key)
        assert not verify_signature("test", signature, wrong_key.signing_public_key)

    def test_tampered_message_verification_fails(self):
        """Tampered message should fail verification."""
        from deadrop.crypto import generate_keypair, sign_message, verify_signature

        kp = generate_keypair()
        signature = sign_message("original message", kp.private_key)

        assert not verify_signature("tampered message", signature, kp.signing_public_key)

    def test_sign_unicode(self):
        """Signing should handle unicode text."""
        from deadrop.crypto import generate_keypair, sign_message, verify_signature

        kp = generate_keypair()
        message = "Signed message 日本語 🖊️"

        signature = sign_message(message, kp.private_key)
        assert verify_signature(message, signature, kp.signing_public_key)


# =============================================================================
# Room Encryption Tests (Symmetric key with forward secrecy)
# =============================================================================


class TestMembershipHash:
    """Tests for membership hash computation."""

    def test_membership_hash_deterministic(self):
        """Same members should produce same hash."""
        from deadrop.crypto import compute_membership_hash

        members = ["alice-id", "bob-id", "carol-id"]
        hash1 = compute_membership_hash(members)
        hash2 = compute_membership_hash(members)

        assert hash1 == hash2

    def test_membership_hash_order_independent(self):
        """Member order should not affect hash (sorted internally)."""
        from deadrop.crypto import compute_membership_hash

        members1 = ["alice-id", "bob-id", "carol-id"]
        members2 = ["carol-id", "alice-id", "bob-id"]
        members3 = ["bob-id", "carol-id", "alice-id"]

        hash1 = compute_membership_hash(members1)
        hash2 = compute_membership_hash(members2)
        hash3 = compute_membership_hash(members3)

        assert hash1 == hash2 == hash3

    def test_membership_hash_format(self):
        """Hash should be 64 hex characters (SHA-256)."""
        from deadrop.crypto import compute_membership_hash

        members = ["alice-id"]
        membership_hash = compute_membership_hash(members)

        assert len(membership_hash) == 64
        # Should be valid hex
        int(membership_hash, 16)

    def test_membership_hash_different_members(self):
        """Different members should produce different hashes."""
        from deadrop.crypto import compute_membership_hash

        hash1 = compute_membership_hash(["alice-id", "bob-id"])
        hash2 = compute_membership_hash(["alice-id", "carol-id"])

        assert hash1 != hash2

    def test_membership_hash_empty(self):
        """Empty member list should produce consistent hash."""
        from deadrop.crypto import compute_membership_hash

        hash1 = compute_membership_hash([])
        hash2 = compute_membership_hash([])

        assert hash1 == hash2
        assert len(hash1) == 64


class TestEpochKeyDerivation:
    """Tests for epoch key derivation."""

    def test_epoch_key_derivation_deterministic(self):
        """Same inputs should produce same epoch key."""
        from deadrop.crypto import derive_epoch_key, generate_room_base_secret

        base_secret = generate_room_base_secret()
        room_id = "room-123"
        membership_hash = "a" * 64

        key1 = derive_epoch_key(base_secret, 0, room_id, membership_hash)
        key2 = derive_epoch_key(base_secret, 0, room_id, membership_hash)

        assert key1 == key2

    def test_epoch_key_length(self):
        """Epoch key should be 32 bytes."""
        from deadrop.crypto import derive_epoch_key, generate_room_base_secret

        base_secret = generate_room_base_secret()
        key = derive_epoch_key(base_secret, 0, "room-123", "a" * 64)

        assert len(key) == 32

    def test_epoch_key_different_epochs(self):
        """Different epochs should produce different keys."""
        from deadrop.crypto import derive_epoch_key, generate_room_base_secret

        base_secret = generate_room_base_secret()
        room_id = "room-123"
        membership_hash = "a" * 64

        key0 = derive_epoch_key(base_secret, 0, room_id, membership_hash)
        key1 = derive_epoch_key(key0, 1, room_id, membership_hash)
        key2 = derive_epoch_key(key1, 2, room_id, membership_hash)

        assert key0 != key1 != key2

    def test_epoch_key_different_rooms(self):
        """Different rooms should produce different keys."""
        from deadrop.crypto import derive_epoch_key, generate_room_base_secret

        base_secret = generate_room_base_secret()
        membership_hash = "a" * 64

        key1 = derive_epoch_key(base_secret, 0, "room-1", membership_hash)
        key2 = derive_epoch_key(base_secret, 0, "room-2", membership_hash)

        assert key1 != key2

    def test_epoch_key_different_membership(self):
        """Different membership should produce different keys."""
        from deadrop.crypto import derive_epoch_key, generate_room_base_secret

        base_secret = generate_room_base_secret()
        room_id = "room-123"

        key1 = derive_epoch_key(base_secret, 0, room_id, "a" * 64)
        key2 = derive_epoch_key(base_secret, 0, room_id, "b" * 64)

        assert key1 != key2

    def test_forward_secrecy_cannot_derive_previous(self):
        """Given epoch N key, should not be able to derive epoch N-1 key.

        This is a property test - we verify that the derivation is one-way
        by showing that knowing key_N and the derivation parameters doesn't
        let us recover key_N-1.
        """
        from deadrop.crypto import derive_epoch_key, generate_room_base_secret

        base_secret = generate_room_base_secret()
        room_id = "room-123"
        membership_hash = "a" * 64

        # Derive chain: base -> key0 -> key1 -> key2
        key0 = derive_epoch_key(base_secret, 0, room_id, membership_hash)
        key1 = derive_epoch_key(key0, 1, room_id, membership_hash)
        key2 = derive_epoch_key(key1, 2, room_id, membership_hash)

        # If we only have key2, we cannot derive key1 or key0
        # (HKDF is one-way - no inverse function exists)
        # We can verify this indirectly by showing that:
        # 1. key2 is deterministic from key1
        # 2. But there's no function to get key1 from key2

        # Verify the chain is correct (forward derivation works)
        assert derive_epoch_key(key0, 1, room_id, membership_hash) == key1
        assert derive_epoch_key(key1, 2, room_id, membership_hash) == key2

        # An attacker with key2 trying random "reverse" operations
        # would not get key1 (this is the security property of HKDF)
        # We can't directly test "impossibility" but we verify the forward chain


class TestRoomMessageEncryption:
    """Tests for room message encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted room message should decrypt correctly."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
        )

        # Setup
        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        # Encrypt
        plaintext = "Hello, room!"
        encrypted = encrypt_room_message(
            plaintext, epoch_key, sender.private_key, room_id, epoch_number
        )

        # Decrypt
        decrypted = decrypt_room_message(
            encrypted, epoch_key, sender.signing_public_key, room_id, epoch_number
        )

        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        """Should handle unicode messages."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
        )

        sender = generate_keypair()
        room_id = "room-unicode"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        plaintext = "Hello 世界! 🔐 Encrypted room message"
        encrypted = encrypt_room_message(
            plaintext, epoch_key, sender.private_key, room_id, epoch_number
        )
        decrypted = decrypt_room_message(
            encrypted, epoch_key, sender.signing_public_key, room_id, epoch_number
        )

        assert decrypted == plaintext

    def test_different_ciphertext_each_time(self):
        """Same message should produce different ciphertext (random nonce)."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
        )

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        plaintext = "Same message"
        encrypted1 = encrypt_room_message(
            plaintext, epoch_key, sender.private_key, room_id, epoch_number
        )
        encrypted2 = encrypt_room_message(
            plaintext, epoch_key, sender.private_key, room_id, epoch_number
        )

        # Different nonces mean different ciphertexts
        assert encrypted1.ciphertext != encrypted2.ciphertext
        assert encrypted1.nonce != encrypted2.nonce

    def test_wrong_epoch_key_fails(self):
        """Decryption with wrong epoch key should fail."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
        )
        from nacl.exceptions import CryptoError

        sender = generate_keypair()
        room_id = "room-123"
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()

        # Encrypt with epoch 0 key
        epoch_key_0 = derive_epoch_key(base_secret, 0, room_id, membership_hash)
        encrypted = encrypt_room_message("secret", epoch_key_0, sender.private_key, room_id, 0)

        # Try to decrypt with epoch 1 key
        epoch_key_1 = derive_epoch_key(epoch_key_0, 1, room_id, membership_hash)
        with pytest.raises(CryptoError):
            decrypt_room_message(encrypted, epoch_key_1, sender.signing_public_key, room_id, 0)

    def test_wrong_sender_signature_fails(self):
        """Decryption with wrong sender pubkey should fail signature verification."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
        )

        sender = generate_keypair()
        wrong_sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        encrypted = encrypt_room_message(
            "secret", epoch_key, sender.private_key, room_id, epoch_number
        )

        # Decryption succeeds but signature verification fails
        with pytest.raises(ValueError, match="Invalid signature"):
            decrypt_room_message(
                encrypted, epoch_key, wrong_sender.signing_public_key, room_id, epoch_number
            )

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail decryption."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
            EncryptedRoomMessage,
        )
        from nacl.exceptions import CryptoError

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        encrypted = encrypt_room_message(
            "secret", epoch_key, sender.private_key, room_id, epoch_number
        )

        # Tamper with ciphertext
        tampered = EncryptedRoomMessage(
            ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
            nonce=encrypted.nonce,
            signature=encrypted.signature,
        )

        with pytest.raises(CryptoError):
            decrypt_room_message(
                tampered, epoch_key, sender.signing_public_key, room_id, epoch_number
            )

    def test_wrong_room_id_verification_fails(self):
        """Message decrypted with wrong room_id should fail signature verification."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
        )

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        encrypted = encrypt_room_message(
            "secret", epoch_key, sender.private_key, room_id, epoch_number
        )

        # Try to verify with wrong room_id
        with pytest.raises(ValueError, match="Invalid signature"):
            decrypt_room_message(
                encrypted, epoch_key, sender.signing_public_key, "wrong-room", epoch_number
            )

    def test_wrong_epoch_number_verification_fails(self):
        """Message decrypted with wrong epoch_number should fail signature verification."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            decrypt_room_message,
        )

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 5
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        encrypted = encrypt_room_message(
            "secret", epoch_key, sender.private_key, room_id, epoch_number
        )

        # Try to verify with wrong epoch number
        with pytest.raises(ValueError, match="Invalid signature"):
            decrypt_room_message(encrypted, epoch_key, sender.signing_public_key, room_id, 999)


class TestEncryptedRoomMessageSerialization:
    """Tests for EncryptedRoomMessage serialization."""

    def test_to_dict_from_dict_roundtrip(self):
        """Message should survive dict serialization."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            EncryptedRoomMessage,
        )

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        original = encrypt_room_message(
            "test message", epoch_key, sender.private_key, room_id, epoch_number
        )

        # Roundtrip through dict
        data = original.to_dict()
        restored = EncryptedRoomMessage.from_dict(data)

        assert restored.ciphertext == original.ciphertext
        assert restored.nonce == original.nonce
        assert restored.signature == original.signature

    def test_to_json_from_json_roundtrip(self):
        """Message should survive JSON serialization."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
            EncryptedRoomMessage,
        )

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        original = encrypt_room_message(
            "test message", epoch_key, sender.private_key, room_id, epoch_number
        )

        # Roundtrip through JSON
        json_str = original.to_json()
        restored = EncryptedRoomMessage.from_json(json_str)

        assert restored.ciphertext == original.ciphertext
        assert restored.nonce == original.nonce
        assert restored.signature == original.signature

    def test_to_dict_includes_algorithm(self):
        """Serialized dict should include algorithm identifier."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_room_message,
        )

        sender = generate_keypair()
        room_id = "room-123"
        epoch_number = 0
        membership_hash = compute_membership_hash(["sender-id"])
        base_secret = generate_room_base_secret()
        epoch_key = derive_epoch_key(base_secret, epoch_number, room_id, membership_hash)

        encrypted = encrypt_room_message(
            "test", epoch_key, sender.private_key, room_id, epoch_number
        )

        data = encrypted.to_dict()
        assert data["algorithm"] == "xsalsa20-poly1305+ed25519"


class TestEpochKeyDistribution:
    """Tests for encrypting/decrypting epoch keys for members."""

    def test_encrypt_decrypt_epoch_key_roundtrip(self):
        """Epoch key should be deliverable to members via asymmetric encryption."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_epoch_key_for_member,
            decrypt_epoch_key,
        )

        # Room setup
        base_secret = generate_room_base_secret()
        room_id = "room-123"
        membership_hash = compute_membership_hash(["alice-id", "bob-id"])
        epoch_key = derive_epoch_key(base_secret, 0, room_id, membership_hash)

        # Key distributor (e.g., server or room admin)
        distributor = generate_keypair()

        # Member
        member = generate_keypair()

        # Encrypt epoch key for member
        encrypted_key = encrypt_epoch_key_for_member(
            epoch_key, member.public_key, distributor.private_key
        )

        # Member decrypts
        decrypted_key = decrypt_epoch_key(encrypted_key, distributor.public_key, member.private_key)

        assert decrypted_key == epoch_key

    def test_epoch_key_distribution_to_multiple_members(self):
        """Same epoch key should be distributable to multiple members."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_epoch_key_for_member,
            decrypt_epoch_key,
        )

        # Room setup
        base_secret = generate_room_base_secret()
        room_id = "room-123"

        # Members
        alice = generate_keypair()
        bob = generate_keypair()
        carol = generate_keypair()

        membership_hash = compute_membership_hash(["alice-id", "bob-id", "carol-id"])
        epoch_key = derive_epoch_key(base_secret, 0, room_id, membership_hash)

        # Distributor
        distributor = generate_keypair()

        # Encrypt for each member
        encrypted_for_alice = encrypt_epoch_key_for_member(
            epoch_key, alice.public_key, distributor.private_key
        )
        encrypted_for_bob = encrypt_epoch_key_for_member(
            epoch_key, bob.public_key, distributor.private_key
        )
        encrypted_for_carol = encrypt_epoch_key_for_member(
            epoch_key, carol.public_key, distributor.private_key
        )

        # Each encrypted key should be different (different recipient, random nonce)
        assert encrypted_for_alice != encrypted_for_bob != encrypted_for_carol

        # But all decrypt to the same epoch key
        assert (
            decrypt_epoch_key(encrypted_for_alice, distributor.public_key, alice.private_key)
            == epoch_key
        )
        assert (
            decrypt_epoch_key(encrypted_for_bob, distributor.public_key, bob.private_key)
            == epoch_key
        )
        assert (
            decrypt_epoch_key(encrypted_for_carol, distributor.public_key, carol.private_key)
            == epoch_key
        )

    def test_epoch_key_wrong_member_fails(self):
        """Member can't decrypt epoch key meant for another member."""
        from deadrop.crypto import (
            generate_keypair,
            generate_room_base_secret,
            derive_epoch_key,
            compute_membership_hash,
            encrypt_epoch_key_for_member,
            decrypt_epoch_key,
        )
        from nacl.exceptions import CryptoError

        base_secret = generate_room_base_secret()
        room_id = "room-123"
        membership_hash = compute_membership_hash(["alice-id", "bob-id"])
        epoch_key = derive_epoch_key(base_secret, 0, room_id, membership_hash)

        distributor = generate_keypair()
        alice = generate_keypair()
        bob = generate_keypair()

        # Encrypt for Alice
        encrypted_for_alice = encrypt_epoch_key_for_member(
            epoch_key, alice.public_key, distributor.private_key
        )

        # Bob tries to decrypt Alice's key
        with pytest.raises(CryptoError):
            decrypt_epoch_key(encrypted_for_alice, distributor.public_key, bob.private_key)
