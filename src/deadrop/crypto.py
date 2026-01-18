"""Cryptographic utilities for deaddrop.

Includes:
- AES-256-GCM for encrypting mailbox secrets in invite links
- NaCl box (X25519 + XSalsa20-Poly1305) for end-to-end message encryption
- Ed25519 for message signing
"""

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


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


# =============================================================================
# End-to-End Encryption (NaCl box: X25519 + XSalsa20-Poly1305)
# =============================================================================


@dataclass
class KeyPair:
    """Container for an encryption/signing keypair."""

    private_key: bytes  # 32 bytes - seed for both X25519 and Ed25519
    public_key: bytes  # 32 bytes - X25519 public key
    signing_public_key: bytes  # 32 bytes - Ed25519 public key (derived from same seed)

    @property
    def private_key_base64(self) -> str:
        """Base64url-encoded private key for storage."""
        return bytes_to_base64url(self.private_key)

    @property
    def public_key_base64(self) -> str:
        """Base64url-encoded public key for API."""
        return bytes_to_base64url(self.public_key)

    @property
    def signing_public_key_base64(self) -> str:
        """Base64url-encoded signing public key."""
        return bytes_to_base64url(self.signing_public_key)

    @classmethod
    def from_private_key_base64(cls, private_key_base64: str) -> "KeyPair":
        """Reconstruct keypair from stored private key."""
        private_key = base64url_to_bytes(private_key_base64)
        return cls.from_seed(private_key)

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        """Create keypair from a 32-byte seed."""
        # Generate X25519 keypair for encryption
        nacl_private = PrivateKey(seed)
        public_key = bytes(nacl_private.public_key)

        # Generate Ed25519 keypair for signing (same seed)
        signing_key = SigningKey(seed)
        signing_public_key = bytes(signing_key.verify_key)

        return cls(
            private_key=seed,
            public_key=public_key,
            signing_public_key=signing_public_key,
        )


def generate_keypair() -> KeyPair:
    """
    Generate a new keypair for encryption and signing.

    The same 32-byte seed is used for both:
    - X25519 (encryption via NaCl box)
    - Ed25519 (signing)

    Returns:
        KeyPair with private_key, public_key, and signing_public_key
    """
    seed = os.urandom(32)
    return KeyPair.from_seed(seed)


def pubkey_id(public_key: bytes) -> str:
    """
    Generate a deterministic ID for a public key.

    Uses first 16 bytes of SHA-256 hash, hex-encoded (32 chars).

    Args:
        public_key: 32-byte public key

    Returns:
        32-character hex string
    """
    return hashlib.sha256(public_key).hexdigest()[:32]


def encrypt_message(
    plaintext: str,
    recipient_public_key: bytes,
    sender_private_key: bytes,
) -> bytes:
    """
    Encrypt a message using NaCl box (X25519 + XSalsa20-Poly1305).

    Provides both confidentiality and authentication - the recipient can verify
    the message came from the sender (but cannot prove this to a third party).

    Args:
        plaintext: Message to encrypt
        recipient_public_key: 32-byte X25519 public key of recipient
        sender_private_key: 32-byte private key (seed) of sender

    Returns:
        Encrypted message: nonce (24 bytes) + ciphertext + auth tag
    """
    sender_key = PrivateKey(sender_private_key)
    recipient_key = PublicKey(recipient_public_key)
    box = Box(sender_key, recipient_key)

    # Box.encrypt() generates random nonce and prepends it to ciphertext
    encrypted = box.encrypt(plaintext.encode("utf-8"))
    return bytes(encrypted)


def decrypt_message(
    ciphertext: bytes,
    sender_public_key: bytes,
    recipient_private_key: bytes,
) -> str:
    """
    Decrypt a message using NaCl box.

    Args:
        ciphertext: Encrypted message (nonce + ciphertext + tag)
        sender_public_key: 32-byte X25519 public key of sender
        recipient_private_key: 32-byte private key (seed) of recipient

    Returns:
        Decrypted plaintext string

    Raises:
        nacl.exceptions.CryptoError: If decryption fails
    """
    recipient_key = PrivateKey(recipient_private_key)
    sender_key = PublicKey(sender_public_key)
    box = Box(recipient_key, sender_key)

    plaintext = box.decrypt(ciphertext)
    return plaintext.decode("utf-8")


# =============================================================================
# Message Signing (Ed25519)
# =============================================================================


def sign_message(message: str, private_key: bytes) -> bytes:
    """
    Sign a message using Ed25519.

    Args:
        message: Message to sign (will be encoded as UTF-8)
        private_key: 32-byte private key (seed)

    Returns:
        64-byte signature
    """
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(message.encode("utf-8"))
    # signed.signature is the 64-byte signature
    return bytes(signed.signature)


def verify_signature(message: str, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        message: Original message (will be encoded as UTF-8)
        signature: 64-byte signature
        public_key: 32-byte Ed25519 public key (signing_public_key from KeyPair)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message.encode("utf-8"), signature)
        return True
    except BadSignatureError:
        return False
