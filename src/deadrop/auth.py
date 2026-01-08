"""Authentication utilities for deadrop."""

import hashlib
import secrets


def generate_secret() -> str:
    """Generate a new random secret (64 hex chars = 32 bytes)."""
    return secrets.token_hex(32)


def hash_secret(secret: str) -> str:
    """Hash a secret for storage/comparison. Returns full SHA-256."""
    return hashlib.sha256(secret.encode()).hexdigest()


def derive_id(secret: str) -> str:
    """Derive a public identity from a secret. Returns first 16 chars of SHA-256."""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def verify_secret(secret: str, expected_hash: str) -> bool:
    """Verify a secret against its stored hash."""
    return secrets.compare_digest(hash_secret(secret), expected_hash)


def verify_secret_derives_id(secret: str, expected_id: str) -> bool:
    """Verify a secret derives to the expected ID."""
    return secrets.compare_digest(derive_id(secret), expected_id)
