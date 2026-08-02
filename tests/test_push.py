"""Tests for the Web Push transport (VAPID + aes128gcm).

The encryption tests implement the *receiver* half of RFC 8291 with
``cryptography`` and decrypt what ``push.encrypt_payload`` produced. That is
the only way to prove the wire format is right without a live push service.
"""

import json
import struct
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from deadrop import push


def _make_subscriber() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    """Create a fake user-agent keypair + auth secret, as a subscription dict."""
    ua_private = ec.generate_private_key(ec.SECP256R1())
    ua_public = push._public_point(ua_private)
    auth_secret = b"0123456789abcdef"
    return ua_private, {
        "endpoint": "https://push.example.com/sub/abc123",
        "p256dh": push.b64u_encode(ua_public),
        "auth": push.b64u_encode(auth_secret),
    }


def _decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth: str) -> bytes:
    """Receiver side of RFC 8291 / RFC 8188."""
    salt = body[:16]
    record_size = struct.unpack("!I", body[16:20])[0]
    idlen = body[20]
    as_public_bytes = body[21 : 21 + idlen]
    ciphertext = body[21 + idlen :]

    assert record_size == push.RECORD_SIZE
    assert idlen == 65

    as_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public_bytes)
    shared = ua_private.exchange(ec.ECDH(), as_public)
    ua_public_bytes = push._public_point(ua_private)

    def hkdf(salt_: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt_, info=info).derive(ikm)

    key_info = b"WebPush: info\x00" + ua_public_bytes + as_public_bytes
    ikm = hkdf(push.b64u_decode(auth), shared, key_info, 32)
    cek = hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)

    padded = AESGCM(cek).decrypt(nonce, ciphertext, None)
    assert padded[-1] == 0x02, "final record must end with the 0x02 delimiter"
    return padded[:-1]


class TestBase64Url:
    def test_roundtrip_unpadded(self):
        raw = b"\x00\x01\x02\xff" * 5
        encoded = push.b64u_encode(raw)
        assert "=" not in encoded
        assert push.b64u_decode(encoded) == raw

    def test_decode_tolerates_padding(self):
        raw = b"abcde"
        assert push.b64u_decode(push.b64u_encode(raw) + "===") == raw


class TestVapidKeys:
    def test_generate_shapes(self):
        public, private = push.generate_vapid_keys()
        assert len(push.b64u_decode(public)) == 65
        assert push.b64u_decode(public)[0] == 0x04  # uncompressed point
        assert len(push.b64u_decode(private)) == 32

    def test_private_key_derives_matching_public(self):
        public, private = push.generate_vapid_keys()
        key = push.load_private_key(private)
        assert push.b64u_encode(push._public_point(key)) == public

    def test_rejects_wrong_length_private_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            push.load_private_key(push.b64u_encode(b"short"))


class TestVapidHeaders:
    def test_jwt_is_verifiable_and_scoped_to_endpoint_origin(self):
        public, private = push.generate_vapid_keys()
        cfg = push.PushConfig(
            enabled=True,
            public_key=public,
            private_key=private,
            subject="mailto:ops@example.com",
        )
        now = time.time()
        headers = push.build_vapid_headers(
            "https://web.push.apple.com/some/very/long/token", cfg, now=now
        )

        scheme, _, params = headers["Authorization"].partition(" ")
        assert scheme == "vapid"
        parts = dict(kv.split("=", 1) for kv in params.split(","))
        assert parts["k"] == public

        header_b64, claims_b64, sig_b64 = parts["t"].split(".")
        claims = json.loads(push.b64u_decode(claims_b64))
        assert claims["aud"] == "https://web.push.apple.com"
        assert claims["sub"] == "mailto:ops@example.com"
        assert int(now) < claims["exp"] <= int(now) + 24 * 3600

        signature = push.b64u_decode(sig_b64)
        assert len(signature) == 64  # P1363 r||s, not DER
        der = asym_utils.encode_dss_signature(
            int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        )
        verifier = push.load_private_key(private).public_key()
        verifier.verify(der, f"{header_b64}.{claims_b64}".encode(), ec.ECDSA(hashes.SHA256()))


class TestEncryptPayload:
    def test_roundtrip(self):
        ua_private, subscription = _make_subscriber()
        plaintext = json.dumps(push.build_payload("sean", "hello", "/app/twin")).encode()

        body = push.encrypt_payload(plaintext, subscription["p256dh"], subscription["auth"])

        assert _decrypt(body, ua_private, subscription["auth"]) == plaintext

    def test_each_call_uses_a_fresh_salt_and_key(self):
        _, subscription = _make_subscriber()
        a = push.encrypt_payload(b"x", subscription["p256dh"], subscription["auth"])
        b = push.encrypt_payload(b"x", subscription["p256dh"], subscription["auth"])
        assert a[:16] != b[:16]  # salt
        assert a[21:86] != b[21:86]  # ephemeral public key

    def test_rejects_oversized_payload(self):
        _, subscription = _make_subscriber()
        with pytest.raises(ValueError, match="too large"):
            push.encrypt_payload(
                b"x" * (push.MAX_PAYLOAD_BYTES + 1), subscription["p256dh"], subscription["auth"]
            )


class TestBuildPayload:
    def test_declarative_envelope(self):
        payload = push.build_payload("sean in twin", "ship it", "/app/twin/room/r1", tag="room:r1")
        assert payload["web_push"] == 8030
        assert payload["notification"] == {
            "title": "sean in twin",
            "body": "ship it",
            "navigate": "/app/twin/room/r1",
            "tag": "room:r1",
        }

    def test_tag_omitted_when_absent(self):
        assert "tag" not in push.build_payload("t", "b", "/app")["notification"]


class TestLoadConfig:
    def test_defaults_are_disabled(self, monkeypatch):
        for key in (
            "DEADROP_PUSH_ENABLED",
            "DEADROP_VAPID_PUBLIC_KEY",
            "DEADROP_VAPID_PRIVATE_KEY",
            "DEADROP_VAPID_SUBJECT",
            "DEADROP_PUSH_UNREAD_SECONDS",
            "DEADROP_PUSH_COOLDOWN_SECONDS",
        ):
            monkeypatch.delenv(key, raising=False)
        cfg = push.load_config()
        assert cfg.enabled is False
        assert cfg.configured is False
        assert cfg.unread_seconds == 60.0
        assert cfg.cooldown_seconds == 300.0

    def test_enabled_requires_full_keypair(self, monkeypatch):
        monkeypatch.setenv("DEADROP_PUSH_ENABLED", "true")
        monkeypatch.setenv("DEADROP_VAPID_PUBLIC_KEY", "pub")
        monkeypatch.delenv("DEADROP_VAPID_PRIVATE_KEY", raising=False)
        monkeypatch.setenv("DEADROP_VAPID_SUBJECT", "mailto:a@b.c")
        assert push.load_config().configured is False

        monkeypatch.setenv("DEADROP_VAPID_PRIVATE_KEY", "priv")
        assert push.load_config().configured is True

    def test_invalid_numeric_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DEADROP_PUSH_UNREAD_SECONDS", "not-a-number")
        assert push.load_config().unread_seconds == 60.0


class _FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Minimal stand-in for httpx.AsyncClient."""

    def __init__(self, response=None, raises: Exception | None = None):
        self.response = response or _FakeResponse(201)
        self.raises = raises
        self.calls: list[dict] = []

    async def post(self, url, content=None, headers=None):
        self.calls.append({"url": url, "content": content, "headers": headers})
        if self.raises:
            raise self.raises
        return self.response


@pytest.fixture
def cfg():
    public, private = push.generate_vapid_keys()
    return push.PushConfig(
        enabled=True,
        public_key=public,
        private_key=private,
        subject="mailto:ops@example.com",
        ttl_seconds=1800,
    )


class TestSendWebPush:
    @pytest.mark.asyncio
    async def test_success_sets_headers_and_encrypted_body(self, cfg):
        ua_private, subscription = _make_subscriber()
        client = _FakeClient(_FakeResponse(201))
        payload = push.build_payload("sean", "hi", "/app/twin")

        result = await push.send_web_push(subscription, payload, cfg, client=client)

        assert result.ok is True
        assert result.gone is False
        call = client.calls[0]
        assert call["url"] == subscription["endpoint"]
        assert call["headers"]["Content-Encoding"] == "aes128gcm"
        assert call["headers"]["TTL"] == "1800"
        assert call["headers"]["Authorization"].startswith("vapid t=")
        decrypted = json.loads(_decrypt(call["content"], ua_private, subscription["auth"]))
        assert decrypted == payload

    @pytest.mark.asyncio
    async def test_410_marks_subscription_gone(self, cfg):
        _, subscription = _make_subscriber()
        client = _FakeClient(_FakeResponse(410, "gone"))
        result = await push.send_web_push(subscription, {}, cfg, client=client)
        assert result.gone is True
        assert result.ok is False

    @pytest.mark.asyncio
    async def test_403_is_an_error_but_not_gone(self, cfg):
        _, subscription = _make_subscriber()
        client = _FakeClient(_FakeResponse(403, "BadJwtToken"))
        result = await push.send_web_push(subscription, {}, cfg, client=client)
        assert (result.ok, result.gone) == (False, False)
        assert "BadJwtToken" in (result.error or "")

    @pytest.mark.asyncio
    async def test_transport_exception_is_swallowed(self, cfg):
        _, subscription = _make_subscriber()
        client = _FakeClient(raises=RuntimeError("connection reset"))
        result = await push.send_web_push(subscription, {}, cfg, client=client)
        assert result.ok is False
        assert result.status_code == 0
        assert "connection reset" in (result.error or "")

    @pytest.mark.asyncio
    async def test_bad_subscription_keys_do_not_raise(self, cfg):
        client = _FakeClient()
        bad = {"endpoint": "https://push.example.com/x", "p256dh": "!!!", "auth": "!!!"}
        result = await push.send_web_push(bad, {}, cfg, client=client)
        assert result.ok is False
        assert client.calls == []
