"""Cryptographic utilities for deaddrop.

Includes:
- AES-256-GCM for encrypting mailbox secrets in invite links
- NaCl box (X25519 + XSalsa20-Poly1305) for end-to-end message encryption
- Ed25519 for message signing
- Room encryption with forward secrecy (HKDF + SecretBox)
"""

import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
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


# =============================================================================
# Room Encryption (Symmetric key with forward secrecy)
# =============================================================================


def compute_membership_hash(member_ids: list[str]) -> str:
    """
    Compute a deterministic hash of room membership.

    The hash is order-independent (members are sorted) to ensure
    consistent results regardless of how members are enumerated.

    Args:
        member_ids: List of identity IDs in the room

    Returns:
        64-character hex string (SHA-256 hash)
    """
    # Sort for determinism, join with separator that can't appear in IDs
    sorted_ids = sorted(member_ids)
    membership_string = "\x00".join(sorted_ids)
    return hashlib.sha256(membership_string.encode("utf-8")).hexdigest()


def derive_epoch_key(
    previous_key_or_secret: bytes,
    epoch_number: int,
    room_id: str,
    membership_hash: str,
) -> bytes:
    """
    Derive an epoch key using HKDF.

    For epoch 0: previous_key_or_secret is the room's base secret
    For epoch N>0: previous_key_or_secret is the epoch N-1 key

    This provides forward secrecy - knowing epoch N key, you cannot
    derive epoch N-1 key (HKDF is one-way).

    Args:
        previous_key_or_secret: 32-byte base secret (epoch 0) or previous epoch key
        epoch_number: The epoch number being derived
        room_id: Room identifier (binds key to room)
        membership_hash: Hash of current members (binds key to membership)

    Returns:
        32-byte epoch key for use with SecretBox
    """
    # Build info string that binds key to context
    info = f"deaddrop-room-epoch:{room_id}:{epoch_number}:{membership_hash}".encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # No salt - previous key provides entropy
        info=info,
    )

    return hkdf.derive(previous_key_or_secret)


def generate_room_base_secret() -> bytes:
    """
    Generate a random base secret for a new encrypted room.

    This secret is used to derive epoch 0 key and should be
    stored securely (never transmitted, only used server-side
    for key derivation).

    Returns:
        32-byte random secret
    """
    return os.urandom(32)


@dataclass
class EncryptedRoomMessage:
    """Container for an encrypted room message."""

    ciphertext: bytes  # SecretBox encrypted: plaintext + signature
    nonce: bytes  # 24-byte nonce
    signature: bytes  # 64-byte Ed25519 signature (for verification after decrypt)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ciphertext": bytes_to_base64url(self.ciphertext),
            "nonce": bytes_to_base64url(self.nonce),
            "signature": bytes_to_base64url(self.signature),
            "algorithm": "xsalsa20-poly1305+ed25519",
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedRoomMessage":
        """Reconstruct from dictionary."""
        return cls(
            ciphertext=base64url_to_bytes(data["ciphertext"]),
            nonce=base64url_to_bytes(data["nonce"]),
            signature=base64url_to_bytes(data["signature"]),
        )

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedRoomMessage":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


def encrypt_room_message(
    plaintext: str,
    epoch_key: bytes,
    sender_signing_key: bytes,
    room_id: str,
    epoch_number: int,
    sender_id: str | None = None,
    timestamp: str | None = None,
    message_id: str | None = None,
) -> EncryptedRoomMessage:
    """
    Encrypt a message for a room using the epoch's symmetric key.

    The message is signed before encryption (sign-then-encrypt) so that:
    1. Only room members with the epoch key can decrypt
    2. After decryption, the signature proves the sender's identity
    3. Replay protection via timestamp and message_id binding

    Args:
        plaintext: Message to encrypt
        epoch_key: 32-byte symmetric key for this epoch
        sender_signing_key: 32-byte Ed25519 private key of sender
        room_id: Room identifier (included in signed data)
        epoch_number: Epoch number (included in signed data)
        sender_id: Sender's identity ID (included in signed data for authentication)
        timestamp: ISO timestamp (included in signed data for replay protection)
        message_id: Unique message ID (included in signed data for replay protection)

    Returns:
        EncryptedRoomMessage with ciphertext, nonce, and signature
    """
    # Create the data to sign (binds message to room, epoch, sender, and time)
    # Include sender_id, timestamp, and message_id if provided for replay protection
    sign_parts = [room_id, str(epoch_number)]
    if sender_id:
        sign_parts.append(sender_id)
    if timestamp:
        sign_parts.append(timestamp)
    if message_id:
        sign_parts.append(message_id)
    sign_parts.append(plaintext)
    sign_data = ":".join(sign_parts)
    signature = sign_message(sign_data, sender_signing_key)

    # Combine plaintext with signature for encryption
    # Format: <plaintext_length:4 bytes><plaintext><signature:64 bytes>
    plaintext_bytes = plaintext.encode("utf-8")
    length_prefix = len(plaintext_bytes).to_bytes(4, "big")
    combined = length_prefix + plaintext_bytes + signature

    # Encrypt with SecretBox (XSalsa20-Poly1305)
    box = SecretBox(epoch_key)
    nonce = os.urandom(24)
    ciphertext = box.encrypt(combined, nonce).ciphertext

    return EncryptedRoomMessage(
        ciphertext=ciphertext,
        nonce=nonce,
        signature=signature,
    )


def decrypt_room_message(
    encrypted: EncryptedRoomMessage,
    epoch_key: bytes,
    sender_signing_pubkey: bytes,
    room_id: str,
    epoch_number: int,
    sender_id: str | None = None,
    timestamp: str | None = None,
    message_id: str | None = None,
) -> str:
    """
    Decrypt a room message and verify the sender's signature.

    Args:
        encrypted: The encrypted message container
        epoch_key: 32-byte symmetric key for this epoch
        sender_signing_pubkey: 32-byte Ed25519 public key of claimed sender
        room_id: Room identifier (for signature verification)
        epoch_number: Epoch number (for signature verification)
        sender_id: Sender's identity ID (for signature verification)
        timestamp: ISO timestamp (for signature verification)
        message_id: Unique message ID (for signature verification)

    Returns:
        Decrypted plaintext string

    Raises:
        nacl.exceptions.CryptoError: If decryption fails (wrong key or tampered)
        ValueError: If signature verification fails
    """
    # Decrypt with SecretBox
    box = SecretBox(epoch_key)
    combined = box.decrypt(encrypted.ciphertext, encrypted.nonce)

    # Parse: <plaintext_length:4 bytes><plaintext><signature:64 bytes>
    plaintext_length = int.from_bytes(combined[:4], "big")
    plaintext_bytes = combined[4 : 4 + plaintext_length]
    signature = combined[4 + plaintext_length :]

    plaintext = plaintext_bytes.decode("utf-8")

    # Verify signature (must match what was signed during encryption)
    sign_parts = [room_id, str(epoch_number)]
    if sender_id:
        sign_parts.append(sender_id)
    if timestamp:
        sign_parts.append(timestamp)
    if message_id:
        sign_parts.append(message_id)
    sign_parts.append(plaintext)
    sign_data = ":".join(sign_parts)
    if not verify_signature(sign_data, signature, sender_signing_pubkey):
        raise ValueError("Invalid signature - message may be forged or corrupted")

    return plaintext


def encrypt_epoch_key_for_member(
    epoch_key: bytes,
    member_public_key: bytes,
    distributor_private_key: bytes,
) -> bytes:
    """
    Encrypt an epoch key for delivery to a room member.

    Uses NaCl box (asymmetric encryption) so only the intended
    member can decrypt with their private key.

    Args:
        epoch_key: 32-byte epoch key to encrypt
        member_public_key: 32-byte X25519 public key of the member
        distributor_private_key: 32-byte private key of the key distributor

    Returns:
        Encrypted epoch key (nonce + ciphertext)
    """
    # Reuse existing encrypt_message but with bytes instead of string
    sender_key = PrivateKey(distributor_private_key)
    recipient_key = PublicKey(member_public_key)
    box = Box(sender_key, recipient_key)

    encrypted = box.encrypt(epoch_key)
    return bytes(encrypted)


def decrypt_epoch_key(
    encrypted_epoch_key: bytes,
    distributor_public_key: bytes,
    member_private_key: bytes,
) -> bytes:
    """
    Decrypt an epoch key received from the key distributor.

    Args:
        encrypted_epoch_key: Encrypted key (nonce + ciphertext)
        distributor_public_key: 32-byte X25519 public key of distributor
        member_private_key: 32-byte private key of the member

    Returns:
        32-byte epoch key

    Raises:
        nacl.exceptions.CryptoError: If decryption fails
    """
    member_key = PrivateKey(member_private_key)
    distributor_key = PublicKey(distributor_public_key)
    box = Box(member_key, distributor_key)

    return bytes(box.decrypt(encrypted_epoch_key))


# =============================================================================
# True E2E Room Encryption (Client-side key management)
# =============================================================================


def rotate_base_secret(
    current_secret: bytes,
    room_id: str,
    removed_member_id: str,
    rotation_number: int,
) -> bytes:
    """
    Derive a new base secret after a member is removed.

    This is a deterministic ratchet - all remaining members who know
    the current secret can independently derive the new secret.
    The removed member cannot derive the new secret because they
    don't know which member triggered the rotation.

    Args:
        current_secret: Current 32-byte base secret
        room_id: Room identifier
        removed_member_id: ID of the member being removed
        rotation_number: Sequential number of this rotation (for uniqueness)

    Returns:
        New 32-byte base secret
    """
    info = f"deaddrop-secret-rotate:{room_id}:{removed_member_id}:{rotation_number}".encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )

    return hkdf.derive(current_secret)


def encrypt_base_secret_for_member(
    base_secret: bytes,
    member_public_key: bytes,
    sender_private_key: bytes,
    room_id: str,
) -> bytes:
    """
    Encrypt a room's base secret for delivery to a member (via invite or rotation).

    Uses NaCl box so only the intended member can decrypt.
    The room_id is included in the encryption context for domain separation.

    Args:
        base_secret: 32-byte base secret to encrypt
        member_public_key: 32-byte X25519 public key of the member
        sender_private_key: 32-byte private key of the sender (inviter)
        room_id: Room identifier (for context binding)

    Returns:
        Encrypted secret (nonce + ciphertext)
    """
    # Prepend room_id to secret for domain separation
    # This ensures the same secret encrypted for different rooms produces different ciphertext
    context = f"room:{room_id}:".encode("utf-8")
    payload = context + base_secret

    sender_key = PrivateKey(sender_private_key)
    recipient_key = PublicKey(member_public_key)
    box = Box(sender_key, recipient_key)

    encrypted = box.encrypt(payload)
    return bytes(encrypted)


def decrypt_base_secret_from_invite(
    encrypted_secret: bytes,
    sender_public_key: bytes,
    recipient_private_key: bytes,
    room_id: str,
) -> bytes:
    """
    Decrypt a room's base secret received via invite or rotation.

    Args:
        encrypted_secret: Encrypted secret (nonce + ciphertext)
        sender_public_key: 32-byte X25519 public key of sender (inviter)
        recipient_private_key: 32-byte private key of recipient
        room_id: Room identifier (for context verification)

    Returns:
        32-byte base secret

    Raises:
        nacl.exceptions.CryptoError: If decryption fails
        ValueError: If room_id context doesn't match
    """
    recipient_key = PrivateKey(recipient_private_key)
    sender_key = PublicKey(sender_public_key)
    box = Box(recipient_key, sender_key)

    payload = bytes(box.decrypt(encrypted_secret))

    # Verify and strip context
    expected_context = f"room:{room_id}:".encode("utf-8")
    if not payload.startswith(expected_context):
        raise ValueError("Room ID mismatch - encrypted secret is for a different room")

    return payload[len(expected_context) :]


@dataclass
class RoomInviteSecrets:
    """Container for encrypted room invite secrets (true E2E model)."""

    encrypted_base_secret: bytes  # Box-encrypted base secret for invitee
    inviter_public_key: bytes  # Inviter's public key (for decryption)
    secret_version: int  # Which version of base_secret this is (increments on rotation)

    def to_dict(self) -> dict:
        """Convert to dictionary for storage/transmission."""
        return {
            "encrypted_base_secret": bytes_to_base64url(self.encrypted_base_secret),
            "inviter_public_key": bytes_to_base64url(self.inviter_public_key),
            "secret_version": self.secret_version,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RoomInviteSecrets":
        """Reconstruct from dictionary."""
        return cls(
            encrypted_base_secret=base64url_to_bytes(data["encrypted_base_secret"]),
            inviter_public_key=base64url_to_bytes(data["inviter_public_key"]),
            secret_version=data["secret_version"],
        )


def create_room_invite_secrets(
    base_secret: bytes,
    secret_version: int,
    invitee_public_key: bytes,
    inviter_keypair: KeyPair,
    room_id: str,
) -> RoomInviteSecrets:
    """
    Create encrypted secrets for inviting a member to an encrypted room.

    The server stores only the encrypted secret - it cannot decrypt
    without the invitee's private key.

    Args:
        base_secret: Current room base secret (32 bytes)
        secret_version: Version number of this secret (0 for initial, increments on rotation)
        invitee_public_key: 32-byte public key of the person being invited
        inviter_keypair: KeyPair of the person sending the invite
        room_id: Room identifier

    Returns:
        RoomInviteSecrets with encrypted data for server storage
    """
    encrypted = encrypt_base_secret_for_member(
        base_secret=base_secret,
        member_public_key=invitee_public_key,
        sender_private_key=inviter_keypair.private_key,
        room_id=room_id,
    )

    return RoomInviteSecrets(
        encrypted_base_secret=encrypted,
        inviter_public_key=inviter_keypair.public_key,
        secret_version=secret_version,
    )
