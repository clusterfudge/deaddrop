"""Web Push transport for deadrop — VAPID auth and aes128gcm encryption.

Implements the client half of the Web Push stack directly on top of
``cryptography`` and ``httpx``, both already vendored:

* RFC 8291 — Message Encryption for Web Push (aes128gcm)
* RFC 8188 — Encrypted Content-Encoding for HTTP
* RFC 8292 — VAPID (ES256 JWT, ``Authorization: vapid t=…,k=…``)

Delivery is a single ``POST`` to the subscription's endpoint. Apple's
push service, Mozilla's autopush and Google's FCM all speak this;
nothing here is vendor-specific.

Configuration
-------------
``DEADROP_PUSH_ENABLED``
    ``1``/``true``/``yes`` to enable. Default off — everything below
    short-circuits when disabled.

``DEADROP_VAPID_PUBLIC_KEY``
    base64url of the uncompressed P-256 point (65 bytes). Handed to the
    browser as ``applicationServerKey``.

``DEADROP_VAPID_PRIVATE_KEY``
    base64url of the raw P-256 scalar (32 bytes).

``DEADROP_VAPID_SUBJECT``
    ``mailto:`` or ``https://`` URL. Apple rejects a JWT whose ``sub``
    is absent or not a URL with ``403 BadJwtToken``.

``DEADROP_PUSH_DEBOUNCE_SECONDS``
    Debounce window: the first unread message in a (room, identity) arms a
    timer this long, and every message arriving before it expires is folded
    into the same notification (default 120).

``DEADROP_PUSH_TTL_SECONDS``
    ``TTL`` header on the push request (default 3600).

Generate a keypair::

    uv run python -m deadrop.push
"""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

# Record size advertised in the aes128gcm header. One record per message;
# the notification bodies we build are two orders of magnitude smaller.
RECORD_SIZE = 4096

# Largest plaintext that fits in a single record: rs minus the 1-byte
# padding delimiter and the 16-byte GCM tag.
MAX_PAYLOAD_BYTES = RECORD_SIZE - 17

# VAPID JWTs must not outlive 24h (RFC 8292 §2); 12h leaves slack for clock skew.
_JWT_LIFETIME_SECONDS = 12 * 3600


# ---------------------------------------------------------------------------
# base64url helpers (Web Push uses unpadded base64url everywhere)
# ---------------------------------------------------------------------------


def b64u_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    """Decode unpadded (or padded) base64url into bytes."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PushConfig:
    """Resolved Web Push configuration."""

    enabled: bool = False
    public_key: str = ""
    private_key: str = ""
    subject: str = ""
    debounce_seconds: float = 120.0
    ttl_seconds: int = 3600

    @property
    def configured(self) -> bool:
        """True when the feature is on and a usable VAPID keypair is present."""
        return bool(self.enabled and self.public_key and self.private_key and self.subject)


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("invalid %s=%r, using %s", name, raw, default)
        return default


def load_config() -> PushConfig:
    """Read push configuration from the environment.

    Read on demand rather than cached at import so a process can be
    reconfigured (and so tests can monkeypatch the environment).
    """
    return PushConfig(
        enabled=_env_flag("DEADROP_PUSH_ENABLED"),
        public_key=os.environ.get("DEADROP_VAPID_PUBLIC_KEY", "").strip(),
        private_key=os.environ.get("DEADROP_VAPID_PRIVATE_KEY", "").strip(),
        subject=os.environ.get("DEADROP_VAPID_SUBJECT", "").strip(),
        debounce_seconds=_env_float("DEADROP_PUSH_DEBOUNCE_SECONDS", 120.0),
        ttl_seconds=int(_env_float("DEADROP_PUSH_TTL_SECONDS", 3600.0)),
    )


# ---------------------------------------------------------------------------
# VAPID
# ---------------------------------------------------------------------------


def generate_vapid_keys() -> tuple[str, str]:
    """Generate a VAPID keypair.

    Returns:
        ``(public_key, private_key)`` as base64url strings, in the format
        ``DEADROP_VAPID_PUBLIC_KEY`` / ``DEADROP_VAPID_PRIVATE_KEY`` expect.
    """
    private = ec.generate_private_key(ec.SECP256R1())
    return b64u_encode(_public_point(private)), b64u_encode(
        private.private_numbers().private_value.to_bytes(32, "big")
    )


def _public_point(key: ec.EllipticCurvePrivateKey) -> bytes:
    """Uncompressed X9.62 encoding of a P-256 public key (65 bytes)."""
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def load_private_key(value: str) -> ec.EllipticCurvePrivateKey:
    """Load a base64url raw P-256 scalar into a private key object."""
    raw = b64u_decode(value)
    if len(raw) != 32:
        raise ValueError(f"VAPID private key must be 32 bytes, got {len(raw)}")
    return ec.derive_private_key(int.from_bytes(raw, "big"), ec.SECP256R1())


def build_vapid_headers(endpoint: str, cfg: PushConfig, now: float | None = None) -> dict[str, str]:
    """Build the ``Authorization`` header for a push request.

    The JWT audience is the origin of the endpoint — not the full URL.
    """
    parsed = urlparse(endpoint)
    audience = f"{parsed.scheme}://{parsed.netloc}"
    issued = int(now if now is not None else time.time())

    header = b64u_encode(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
    claims = b64u_encode(
        json.dumps(
            {"aud": audience, "exp": issued + _JWT_LIFETIME_SECONDS, "sub": cfg.subject},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode("ascii")

    private = load_private_key(cfg.private_key)
    der = private.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    jwt = f"{header}.{claims}.{b64u_encode(signature)}"
    return {"Authorization": f"vapid t={jwt},k={cfg.public_key}"}


# ---------------------------------------------------------------------------
# Payload encryption (RFC 8291 aes128gcm)
# ---------------------------------------------------------------------------


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt_payload(
    plaintext: bytes,
    p256dh: str,
    auth: str,
    salt: bytes | None = None,
    ephemeral: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """Encrypt a push payload for one subscription.

    Args:
        plaintext: The message body to encrypt.
        p256dh: Subscriber's base64url P-256 public key (65-byte point).
        auth: Subscriber's base64url 16-byte auth secret.
        salt: Override the random salt (tests only).
        ephemeral: Override the ephemeral sender key (tests only).

    Returns:
        The aes128gcm body: ``salt || rs || idlen || keyid || ciphertext``.
    """
    if len(plaintext) > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload too large: {len(plaintext)} > {MAX_PAYLOAD_BYTES}")

    ua_public_bytes = b64u_decode(p256dh)
    auth_secret = b64u_decode(auth)
    ua_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public_bytes)

    as_private = ephemeral or ec.generate_private_key(ec.SECP256R1())
    as_public_bytes = _public_point(as_private)
    salt = salt or os.urandom(16)

    shared = as_private.exchange(ec.ECDH(), ua_public)

    # RFC 8291 §3.4: the auth secret salts the first extract, and the
    # info string binds the derived key to both parties' public keys.
    key_info = b"WebPush: info\x00" + ua_public_bytes + as_public_bytes
    ikm = _hkdf(auth_secret, shared, key_info, 32)

    # RFC 8188 §2.2: content-encryption key and nonce.
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)

    # A single record, so the padding delimiter is 0x02 ("last record").
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)

    header = salt + struct.pack("!I", RECORD_SIZE) + bytes([len(as_public_bytes)]) + as_public_bytes
    return header + ciphertext


# ---------------------------------------------------------------------------
# Notification payload
# ---------------------------------------------------------------------------


def build_payload(
    title: str,
    body: str,
    navigate: str,
    tag: str | None = None,
    badge: int | None = None,
) -> dict:
    """Build a Declarative Web Push envelope.

    iOS >= 18.4 and Safari 18.4 render this with no service worker
    involvement; older iOS (16.4-18.3) and every other browser dispatch it
    to the ``push`` handler in ``sw.js``, which reads the same fields. One
    payload shape covers both.

    ``badge`` becomes ``app_badge``, the Declarative Web Push member the OS
    applies to the app icon. It is a JSON number per the specification's
    ``unsigned long long``; the service-worker fallback coerces it before
    handing it to ``setAppBadge()``.
    """
    notification: dict[str, object] = {
        "title": title,
        "body": body,
        "navigate": navigate,
    }
    if tag:
        notification["tag"] = tag
    if badge is not None:
        notification["app_badge"] = int(badge)
    return {"web_push": 8030, "notification": notification}


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PushResult:
    """Outcome of one delivery attempt."""

    endpoint: str
    status_code: int
    ok: bool
    gone: bool
    error: str | None = None


async def send_web_push(
    subscription: dict,
    payload: dict,
    cfg: PushConfig,
    client: object | None = None,
) -> PushResult:
    """Encrypt and POST one notification to one subscription.

    Args:
        subscription: Row from ``push_subscriptions`` (endpoint/p256dh/auth).
        payload: Declarative payload from :func:`build_payload`.
        cfg: Resolved push configuration.
        client: Optional ``httpx.AsyncClient`` to reuse.

    Returns:
        A :class:`PushResult`. ``gone`` is set for 404/410, which means the
        caller should delete the subscription.
    """
    import httpx

    endpoint = subscription["endpoint"]
    body = json.dumps(payload, separators=(",", ":")).encode()

    try:
        encrypted = encrypt_payload(body, subscription["p256dh"], subscription["auth"])
        headers = build_vapid_headers(endpoint, cfg)
    except Exception as exc:
        logger.warning("push encryption failed for %s: %s", endpoint, exc)
        return PushResult(endpoint, 0, False, False, str(exc))

    headers.update(
        {
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(cfg.ttl_seconds),
            "Urgency": "normal",
        }
    )

    owns_client = client is None
    http = client if client is not None else httpx.AsyncClient(timeout=10.0)
    try:
        response = await http.post(endpoint, content=encrypted, headers=headers)  # type: ignore[union-attr]
    except Exception as exc:
        logger.warning("push delivery failed for %s: %s", endpoint, exc)
        return PushResult(endpoint, 0, False, False, str(exc))
    finally:
        if owns_client:
            await http.aclose()  # type: ignore[union-attr]

    status = response.status_code
    gone = status in (404, 410)
    ok = 200 <= status < 300
    error = None if ok else (response.text or "")[:200]
    if not ok and not gone:
        logger.warning("push rejected by %s: %s %s", urlparse(endpoint).netloc, status, error)
    return PushResult(endpoint, status, ok, gone, error)


def _main() -> None:
    """Print a fresh VAPID keypair as shell exports."""
    public, private = generate_vapid_keys()
    print(f"DEADROP_VAPID_PUBLIC_KEY={public}")
    print(f"DEADROP_VAPID_PRIVATE_KEY={private}")
    print("DEADROP_VAPID_SUBJECT=mailto:you@example.com")


if __name__ == "__main__":
    _main()
