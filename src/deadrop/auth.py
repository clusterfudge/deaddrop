"""Authentication utilities for deadrop."""

import hashlib
import hmac
import os
import secrets

# Stdlib scrypt for recovery PINs (no new dependency). n=2**15, r=8 costs
# ~32 MiB and tens of milliseconds per hash; a PIN is checked only when a
# recovery invite is claimed.
PIN_SCRYPT_N = 2**15
PIN_SCRYPT_R = 8
PIN_SCRYPT_P = 1
PIN_MIN_LENGTH = 6

# Detail returned with 403 for a burned (rotated-out) secret. Clients match
# the prefix to tell a stale device from a wrong secret.
RETIRED_DETAIL = "credential_retired: this secret was rotated out; ask for a recovery invite"


def generate_secret() -> str:
    """Generate a new random secret (64 hex chars = 32 bytes)."""
    return secrets.token_hex(32)


def hash_secret(secret: str) -> str:
    """Hash a secret for storage/comparison. Returns full SHA-256."""
    return hashlib.sha256(secret.encode()).hexdigest()


def derive_id(secret: str) -> str:
    """Derive a namespace id from its secret: the first 16 chars of SHA-256.

    Identities created before secret versions also have ids of this form;
    new identities get random ids, and no identity id is derived at auth time.
    """
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def verify_secret(secret: str, expected_hash: str) -> bool:
    """Verify a secret against its stored hash."""
    return secrets.compare_digest(hash_secret(secret), expected_hash)


def _scrypt(pin: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        pin.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * r * n * 2 + 1024 * 1024
    )


def hash_pin(pin: str) -> str:
    """Salted scrypt hash of a recovery PIN: ``scrypt$n$r$p$salt$hash`` (hex)."""
    if len(pin) < PIN_MIN_LENGTH:
        raise ValueError(f"PIN must be at least {PIN_MIN_LENGTH} characters")
    salt = os.urandom(16)
    digest = _scrypt(pin, salt, PIN_SCRYPT_N, PIN_SCRYPT_R, PIN_SCRYPT_P)
    return f"scrypt${PIN_SCRYPT_N}${PIN_SCRYPT_R}${PIN_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_pin(pin: str, stored: str) -> bool:
    """Constant-time check of a PIN against :func:`hash_pin` output."""
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    digest = _scrypt(pin, bytes.fromhex(salt_hex), int(n), int(r), int(p))
    return hmac.compare_digest(digest, bytes.fromhex(digest_hex))
