"""Cryptographic utilities for the invite system.

Implements split-secret encryption where:
- url_key: stored in URL fragment (never sent to server)
- server_key: stored on server

Neither party can decrypt alone. The browser combines both to recover the secret.
"""

import base64
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants
KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12  # 96 bits for AES-GCM
INFO = b"deadrop-invite-v1"


def generate_key() -> bytes:
    """Generate a random 256-bit key."""
    return secrets.token_bytes(KEY_SIZE)


def generate_invite_id() -> str:
    """Generate a random invite ID (16 bytes, hex-encoded = 32 chars)."""
    return secrets.token_hex(16)


def derive_encryption_key(url_key: bytes, server_key: bytes, salt: bytes) -> bytes:
    """
    Derive the encryption key from url_key and server_key using HKDF.

    Args:
        url_key: 32 bytes from URL fragment
        server_key: 32 bytes stored on server
        salt: invite_id as bytes (for domain separation)

    Returns:
        32-byte encryption key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=INFO,
    )
    return hkdf.derive(url_key + server_key)


def encrypt_secret(plaintext: str, url_key: bytes, server_key: bytes, invite_id: str) -> bytes:
    """
    Encrypt a secret using AES-256-GCM with a key derived from url_key + server_key.

    Args:
        plaintext: The secret to encrypt (e.g., mailbox secret)
        url_key: 32 bytes that will go in URL fragment
        server_key: 32 bytes that will be stored on server
        invite_id: Used as salt for key derivation and AAD for encryption

    Returns:
        Encrypted data: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    salt = invite_id.encode("utf-8")
    encryption_key = derive_encryption_key(url_key, server_key, salt)

    aesgcm = AESGCM(encryption_key)
    nonce = secrets.token_bytes(NONCE_SIZE)

    # Use invite_id as additional authenticated data
    aad = invite_id.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    # Return nonce + ciphertext (ciphertext includes the 16-byte auth tag)
    return nonce + ciphertext


def decrypt_secret(encrypted_data: bytes, url_key: bytes, server_key: bytes, invite_id: str) -> str:
    """
    Decrypt a secret using AES-256-GCM.

    Args:
        encrypted_data: nonce (12 bytes) + ciphertext + tag
        url_key: 32 bytes from URL fragment
        server_key: 32 bytes from server
        invite_id: Used as salt for key derivation and AAD for decryption

    Returns:
        Decrypted plaintext string

    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (wrong keys or tampered data)
    """
    salt = invite_id.encode("utf-8")
    encryption_key = derive_encryption_key(url_key, server_key, salt)

    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]

    aesgcm = AESGCM(encryption_key)
    aad = invite_id.encode("utf-8")
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    return plaintext.decode("utf-8")


def bytes_to_base64url(data: bytes) -> str:
    """Encode bytes to URL-safe base64 (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_to_bytes(data: str) -> bytes:
    """Decode URL-safe base64 (handles missing padding)."""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


@dataclass
class InviteSecrets:
    """Container for the secrets generated during invite creation."""

    invite_id: str
    url_key: bytes
    server_key: bytes
    encrypted_secret: bytes

    @property
    def url_key_base64(self) -> str:
        """URL key encoded for use in URL fragment."""
        return bytes_to_base64url(self.url_key)

    @property
    def server_key_hex(self) -> str:
        """Server key encoded for database storage."""
        return self.server_key.hex()

    @property
    def encrypted_secret_hex(self) -> str:
        """Encrypted secret encoded for database storage."""
        return self.encrypted_secret.hex()


def create_invite_secrets(mailbox_secret: str) -> InviteSecrets:
    """
    Create all the cryptographic material needed for an invite.

    Args:
        mailbox_secret: The secret to share (64 hex chars)

    Returns:
        InviteSecrets containing invite_id, url_key, server_key, and encrypted_secret
    """
    invite_id = generate_invite_id()
    url_key = generate_key()
    server_key = generate_key()

    encrypted_secret = encrypt_secret(mailbox_secret, url_key, server_key, invite_id)

    return InviteSecrets(
        invite_id=invite_id,
        url_key=url_key,
        server_key=server_key,
        encrypted_secret=encrypted_secret,
    )


def decrypt_invite_secret(
    encrypted_secret_hex: str,
    url_key_base64: str,
    server_key_hex: str,
    invite_id: str,
) -> str:
    """
    Decrypt an invite's secret from stored/transmitted formats.

    Args:
        encrypted_secret_hex: Hex-encoded encrypted data from database
        url_key_base64: Base64url-encoded key from URL fragment
        server_key_hex: Hex-encoded key from server
        invite_id: The invite identifier

    Returns:
        The decrypted mailbox secret
    """
    encrypted_data = bytes.fromhex(encrypted_secret_hex)
    url_key = base64url_to_bytes(url_key_base64)
    server_key = bytes.fromhex(server_key_hex)

    return decrypt_secret(encrypted_data, url_key, server_key, invite_id)
