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
