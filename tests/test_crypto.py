"""Tests for the crypto module."""

import pytest
from cryptography.exceptions import InvalidTag

from deadrop.crypto import (
    base64url_to_bytes,
    bytes_to_base64url,
    create_invite_secrets,
    decrypt_invite_secret,
    decrypt_secret,
    derive_encryption_key,
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


class TestKeyDerivation:
    """Tests for key derivation."""

    def test_derive_encryption_key_deterministic(self):
        """Same inputs should produce same key."""
        url_key = generate_key()
        server_key = generate_key()
        salt = b"test-salt"

        key1 = derive_encryption_key(url_key, server_key, salt)
        key2 = derive_encryption_key(url_key, server_key, salt)

        assert key1 == key2

    def test_derive_encryption_key_different_url_key(self):
        """Different url_key should produce different encryption key."""
        server_key = generate_key()
        salt = b"test-salt"

        key1 = derive_encryption_key(generate_key(), server_key, salt)
        key2 = derive_encryption_key(generate_key(), server_key, salt)

        assert key1 != key2

    def test_derive_encryption_key_different_server_key(self):
        """Different server_key should produce different encryption key."""
        url_key = generate_key()
        salt = b"test-salt"

        key1 = derive_encryption_key(url_key, generate_key(), salt)
        key2 = derive_encryption_key(url_key, generate_key(), salt)

        assert key1 != key2

    def test_derive_encryption_key_different_salt(self):
        """Different salt should produce different encryption key."""
        url_key = generate_key()
        server_key = generate_key()

        key1 = derive_encryption_key(url_key, server_key, b"salt1")
        key2 = derive_encryption_key(url_key, server_key, b"salt2")

        assert key1 != key2


class TestEncryptionDecryption:
    """Tests for encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt to original plaintext."""
        plaintext = "this is a secret message"
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, url_key, server_key, invite_id)
        decrypted = decrypt_secret(encrypted, url_key, server_key, invite_id)

        assert decrypted == plaintext

    def test_encrypt_decrypt_mailbox_secret(self):
        """Should handle 64-char hex mailbox secrets."""
        mailbox_secret = "a" * 64  # 64 hex chars
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(mailbox_secret, url_key, server_key, invite_id)
        decrypted = decrypt_secret(encrypted, url_key, server_key, invite_id)

        assert decrypted == mailbox_secret

    def test_decrypt_wrong_url_key_fails(self):
        """Decryption with wrong url_key should fail."""
        plaintext = "secret"
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, url_key, server_key, invite_id)

        with pytest.raises(InvalidTag):
            decrypt_secret(encrypted, generate_key(), server_key, invite_id)

    def test_decrypt_wrong_server_key_fails(self):
        """Decryption with wrong server_key should fail."""
        plaintext = "secret"
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, url_key, server_key, invite_id)

        with pytest.raises(InvalidTag):
            decrypt_secret(encrypted, url_key, generate_key(), invite_id)

    def test_decrypt_wrong_invite_id_fails(self):
        """Decryption with wrong invite_id should fail."""
        plaintext = "secret"
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, url_key, server_key, invite_id)

        with pytest.raises(InvalidTag):
            decrypt_secret(encrypted, url_key, server_key, generate_invite_id())

    def test_encrypted_data_includes_nonce(self):
        """Encrypted data should be longer than plaintext (includes nonce and tag)."""
        plaintext = "secret"
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted = encrypt_secret(plaintext, url_key, server_key, invite_id)

        # Should include: 12-byte nonce + ciphertext (same length as plaintext) + 16-byte tag
        # So minimum length is: 12 + len(plaintext) + 16 = 28 + len(plaintext)
        assert len(encrypted) >= len(plaintext.encode()) + 12 + 16

    def test_encryption_produces_different_ciphertext(self):
        """Same plaintext should produce different ciphertext (random nonce)."""
        plaintext = "secret"
        url_key = generate_key()
        server_key = generate_key()
        invite_id = generate_invite_id()

        encrypted1 = encrypt_secret(plaintext, url_key, server_key, invite_id)
        encrypted2 = encrypt_secret(plaintext, url_key, server_key, invite_id)

        # Different nonces mean different ciphertext
        assert encrypted1 != encrypted2

        # But both should decrypt to same plaintext
        assert decrypt_secret(encrypted1, url_key, server_key, invite_id) == plaintext
        assert decrypt_secret(encrypted2, url_key, server_key, invite_id) == plaintext


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
        assert len(secrets.url_key) == 32
        assert len(secrets.server_key) == 32
        assert len(secrets.encrypted_secret) > 0

    def test_invite_secrets_properties(self):
        """Should provide encoded versions for storage/transport."""
        mailbox_secret = "a" * 64
        secrets = create_invite_secrets(mailbox_secret)

        # url_key_base64 should be URL-safe
        assert "+" not in secrets.url_key_base64
        assert "/" not in secrets.url_key_base64

        # server_key_hex should be valid hex
        int(secrets.server_key_hex, 16)
        assert len(secrets.server_key_hex) == 64  # 32 bytes = 64 hex chars

        # encrypted_secret_hex should be valid hex
        int(secrets.encrypted_secret_hex, 16)

    def test_decrypt_invite_secret_helper(self):
        """decrypt_invite_secret should work with encoded formats."""
        mailbox_secret = "b" * 64
        secrets = create_invite_secrets(mailbox_secret)

        decrypted = decrypt_invite_secret(
            encrypted_secret_hex=secrets.encrypted_secret_hex,
            url_key_base64=secrets.url_key_base64,
            server_key_hex=secrets.server_key_hex,
            invite_id=secrets.invite_id,
        )

        assert decrypted == mailbox_secret


class TestSecurityProperties:
    """Tests for security properties of the crypto system."""

    def test_server_cannot_decrypt_without_url_key(self):
        """Server with only server_key cannot decrypt."""
        mailbox_secret = "secret123" * 7  # 63 chars
        secrets = create_invite_secrets(mailbox_secret)

        # Server has: server_key, encrypted_secret, invite_id
        # Server lacks: url_key

        # Try with a random url_key (simulating brute force)
        wrong_url_key = bytes_to_base64url(generate_key())

        with pytest.raises(InvalidTag):
            decrypt_invite_secret(
                encrypted_secret_hex=secrets.encrypted_secret_hex,
                url_key_base64=wrong_url_key,
                server_key_hex=secrets.server_key_hex,
                invite_id=secrets.invite_id,
            )

    def test_url_interceptor_cannot_decrypt_without_server_key(self):
        """Someone with only the URL cannot decrypt."""
        mailbox_secret = "topsecret" * 7
        secrets = create_invite_secrets(mailbox_secret)

        # URL interceptor has: url_key, invite_id
        # URL interceptor lacks: server_key, encrypted_secret

        # Even if they somehow got encrypted_secret, they can't decrypt without server_key
        wrong_server_key = generate_key().hex()

        with pytest.raises(InvalidTag):
            decrypt_invite_secret(
                encrypted_secret_hex=secrets.encrypted_secret_hex,
                url_key_base64=secrets.url_key_base64,
                server_key_hex=wrong_server_key,
                invite_id=secrets.invite_id,
            )
