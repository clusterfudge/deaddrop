"""Cryptographic utilities for the invite system.

Uses AES-256-GCM for encrypting mailbox secrets in invite links.
The encryption key is included in the URL fragment (never sent to server).
Server only stores the encrypted payload.
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    """Generate a random 256-bit key."""
    return os.urandom(32)


def generate_invite_id() -> str:
    """Generate a random invite ID (128-bit hex string)."""
    return os.urandom(16).hex()


def bytes_to_base64url(data: bytes) -> str:
    """Encode bytes to base64url (URL-safe, no padding)."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_to_bytes(s: str) -> bytes:
    """Decode base64url string to bytes (handles missing padding)."""
    import base64

    # Add padding if needed
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def encrypt_secret(plaintext: str, key: bytes, invite_id: str) -> bytes:
    """
    Encrypt a secret using AES-256-GCM.

    Args:
        plaintext: The secret to encrypt (e.g., mailbox secret)
        key: 32-byte encryption key
        invite_id: Used as additional authenticated data (AAD)

    Returns:
        Encrypted data: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = invite_id.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return nonce + ciphertext


def decrypt_secret(encrypted_data: bytes, key: bytes, invite_id: str) -> str:
    """
    Decrypt a secret using AES-256-GCM.

    Args:
        encrypted_data: nonce (12 bytes) + ciphertext + tag
        key: 32-byte encryption key
        invite_id: Additional authenticated data (must match encryption)

    Returns:
        Decrypted plaintext string

    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key or tampered data)
    """
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aad = invite_id.encode("utf-8")
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode("utf-8")


@dataclass
class InviteSecrets:
    """Container for invite creation secrets."""

    invite_id: str
    key: bytes
    encrypted_secret: bytes

    @property
    def key_base64(self) -> str:
        """Base64url-encoded key for URL fragment."""
        return bytes_to_base64url(self.key)

    @property
    def encrypted_secret_hex(self) -> str:
        """Hex-encoded encrypted secret for database storage."""
        return self.encrypted_secret.hex()


def create_invite_secrets(mailbox_secret: str) -> InviteSecrets:
    """
    Create all secrets needed for an invite.

    Returns an InviteSecrets object containing:
    - invite_id: Random identifier for the invite
    - key: Encryption key (goes in URL fragment)
    - encrypted_secret: Encrypted mailbox secret (stored on server)

    The URL will be: /join/{invite_id}#{key_base64}
    Server stores: invite_id, encrypted_secret_hex
    """
    invite_id = generate_invite_id()
    key = generate_key()
    encrypted_secret = encrypt_secret(mailbox_secret, key, invite_id)

    return InviteSecrets(
        invite_id=invite_id,
        key=key,
        encrypted_secret=encrypted_secret,
    )


def decrypt_invite_secret(
    encrypted_secret_hex: str,
    key_base64: str,
    invite_id: str,
) -> str:
    """
    Decrypt an invite secret using the key from the URL fragment.

    Args:
        encrypted_secret_hex: Hex-encoded encrypted data from server
        key_base64: Base64url-encoded key from URL fragment
        invite_id: The invite identifier

    Returns:
        Decrypted mailbox secret
    """
    encrypted_secret = bytes.fromhex(encrypted_secret_hex)
    key = base64url_to_bytes(key_base64)
    return decrypt_secret(encrypted_secret, key, invite_id)
