"""Tests for the attachments feature."""

import base64
import struct
import zlib

import pytest
from fastapi.testclient import TestClient

from deadrop import db
from deadrop.api import app


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def room_setup(client, admin_headers):
    """Create a namespace, identity, and room."""
    ns = client.post("/admin/namespaces", headers=admin_headers).json()
    alice = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns["secret"]},
        json={"metadata": {"display_name": "Alice"}},
    ).json()

    room = client.post(
        f"/{ns['ns']}/rooms",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"display_name": "Test Room"},
    ).json()

    return {
        "ns": ns["ns"],
        "ns_secret": ns["secret"],
        "room_id": room["room_id"],
        "alice_secret": alice["secret"],
        "alice_id": alice["id"],
    }


@pytest.fixture
def two_member_setup(client, room_setup, admin_headers):
    """Room with two members (Alice + Bob)."""
    setup = room_setup
    bob = client.post(
        f"/{setup['ns']}/identities",
        headers={"X-Namespace-Secret": setup["ns_secret"]},
        json={"metadata": {"display_name": "Bob"}},
    ).json()

    client.post(
        f"/{setup['ns']}/rooms/{setup['room_id']}/members",
        headers={"X-Inbox-Secret": setup["alice_secret"]},
        json={"identity_id": bob["id"]},
    )

    return {**setup, "bob_secret": bob["secret"], "bob_id": bob["id"]}


def _make_png_b64():
    """Create a minimal valid 1x1 red pixel PNG as base64."""

    def _chunk(chunk_type, data):
        c = chunk_type + data
        crc = struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + c + crc

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\xff\x00\x00"
    idat = zlib.compress(raw)
    png = sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    return base64.b64encode(png).decode()


def _make_jpeg_b64():
    """Minimal JPEG-like blob for testing."""
    data = b"\xff\xd8\xff\xe0" + b"\x00" * 100 + b"\xff\xd9"
    return base64.b64encode(data).decode()


_SVG_PLAIN = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'

_SVG_MALICIOUS = (
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
    b"<script>alert(document.cookie)</script>"
    b'<foreignObject><iframe src="https://evil.example/"></iframe></foreignObject>'
    b"</svg>"
)


# ---------------------------------------------------------------------------
# DB-level tests
# ---------------------------------------------------------------------------


class TestAttachmentDB:
    def test_add_and_get(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "test"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        mid = resp.json()["mid"]

        png = _make_png_b64()
        raw_size = len(base64.b64decode(png))
        att = db.add_attachment(mid, "image/png", png, raw_size, "test.png")

        assert att["id"]
        assert att["message_mid"] == mid
        assert att["filename"] == "test.png"
        assert att["content_type"] == "image/png"
        assert att["size"] == raw_size

        fetched = db.get_attachment(att["id"])
        assert fetched is not None
        assert fetched["data"] == png
        assert fetched["content_type"] == "image/png"

    def test_get_without_data(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "test"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        mid = resp.json()["mid"]

        att = db.add_attachment(mid, "image/jpeg", _make_jpeg_b64(), 104, "photo.jpg")
        fetched = db.get_attachment(att["id"], include_data=False)
        assert fetched is not None
        assert "data" not in fetched
        assert fetched["content_type"] == "image/jpeg"

    def test_multiple_attachments(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "multi"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        mid = resp.json()["mid"]

        db.add_attachment(mid, "image/png", _make_png_b64(), 100, "a.png")
        db.add_attachment(mid, "image/jpeg", _make_jpeg_b64(), 104, "b.jpg")

        atts = db.get_message_attachments(mid, include_data=False)
        assert len(atts) == 2
        assert atts[0]["filename"] == "a.png"
        assert atts[1]["filename"] == "b.jpg"

    def test_nonexistent_attachment(self, client, room_setup):
        assert db.get_attachment("nonexistent-id") is None

    def test_no_attachments(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "plain"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        mid = resp.json()["mid"]
        assert db.get_message_attachments(mid) == []

    def test_optional_filename(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "test"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        mid = resp.json()["mid"]
        att = db.add_attachment(mid, "image/png", _make_png_b64(), 100)
        assert att["filename"] is None

        fetched = db.get_attachment(att["id"])
        assert fetched["filename"] is None


# ---------------------------------------------------------------------------
# API-level tests
# ---------------------------------------------------------------------------


class TestAttachmentAPI:
    def test_send_with_attachment(self, client, room_setup):
        s = room_setup
        png = _make_png_b64()

        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Screenshot",
                "content_type": "text/markdown",
                "attachments": [
                    {"filename": "shot.png", "content_type": "image/png", "data": png},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["body"] == "Screenshot"
        assert data["attachments"] is not None
        assert len(data["attachments"]) == 1
        att = data["attachments"][0]
        assert att["filename"] == "shot.png"
        assert att["content_type"] == "image/png"
        assert att["size"] > 0
        assert "data" not in att  # Metadata only in response

    def test_send_multiple_attachments(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Two files",
                "attachments": [
                    {"filename": "a.png", "content_type": "image/png", "data": _make_png_b64()},
                    {"filename": "b.jpg", "content_type": "image/jpeg", "data": _make_jpeg_b64()},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert len(resp.json()["attachments"]) == 2

    def test_send_without_attachments(self, client, room_setup):
        s = room_setup
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "Plain text"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.json()["attachments"] is None

    def test_list_includes_attachment_metadata(self, client, room_setup):
        s = room_setup

        # Message with attachment
        client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "With image",
                "attachments": [
                    {"filename": "img.png", "content_type": "image/png", "data": _make_png_b64()},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        # Message without
        client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "No image"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )

        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        msgs = resp.json()["messages"]
        assert len(msgs) == 2
        assert msgs[0]["attachments"] is not None
        assert len(msgs[0]["attachments"]) == 1
        assert msgs[0]["attachments"][0]["filename"] == "img.png"
        assert msgs[1]["attachments"] is None

    def test_fetch_attachment_data(self, client, room_setup):
        s = room_setup
        png = _make_png_b64()

        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Fetch me",
                "attachments": [
                    {"filename": "test.png", "content_type": "image/png", "data": png},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        att_id = resp.json()["attachments"][0]["id"]

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["data"] == png
        assert data["content_type"] == "image/png"

    def test_fetch_attachment_not_found(self, client, room_setup):
        s = room_setup
        resp = client.get(
            f"/{s['ns']}/attachments/nonexistent-id",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 404

    def test_fetch_attachment_requires_auth(self, client, room_setup):
        s = room_setup
        resp = client.get(f"/{s['ns']}/attachments/any-id")
        assert resp.status_code == 401

    def test_fetch_attachment_requires_room_membership(
        self, client, two_member_setup, admin_headers
    ):
        """Non-member can't fetch attachment."""
        s = two_member_setup

        # Alice sends message with attachment
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Secret image",
                "attachments": [
                    {
                        "filename": "secret.png",
                        "content_type": "image/png",
                        "data": _make_png_b64(),
                    },
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        att_id = resp.json()["attachments"][0]["id"]

        # Create Charlie (not a room member)
        charlie = client.post(
            f"/{s['ns']}/identities",
            headers={"X-Namespace-Secret": s["ns_secret"]},
            json={"metadata": {"display_name": "Charlie"}},
        ).json()

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}",
            headers={"X-Inbox-Secret": charlie["secret"]},
        )
        assert resp.status_code == 403

    def test_invalid_base64_rejected(self, client, room_setup):
        s = room_setup
        # Use characters that are definitely not valid base64 (= padding in wrong place)
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Bad data",
                "attachments": [
                    {"filename": "bad.png", "content_type": "image/png", "data": "===invalid==="},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 400

    def test_dedup_no_duplicate_attachments(self, client, room_setup):
        """Deduped messages should not create extra attachments."""
        s = room_setup
        msg = {
            "body": "Dedup test",
            "attachments": [
                {"filename": "test.png", "content_type": "image/png", "data": _make_png_b64()},
            ],
        }

        resp1 = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json=msg,
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        resp2 = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json=msg,
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )

        assert resp1.json()["mid"] == resp2.json()["mid"]
        atts = db.get_message_attachments(resp1.json()["mid"])
        assert len(atts) == 1


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


class TestAttachmentValidation:
    def test_accept_html_content_type(self, client, room_setup):
        """text/html is accepted (large-paste feature) but must be served safely."""
        s = room_setup
        import base64

        html_b64 = base64.b64encode(b"<script>alert(1)</script>").decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "HTML paste",
                "attachments": [
                    {"filename": "note.html", "content_type": "text/html", "data": html_b64},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200

    def test_accept_svg_content_type(self, client, room_setup):
        """image/svg+xml is accepted; the download path makes it inert."""
        s = room_setup
        import base64

        svg_b64 = base64.b64encode(_SVG_PLAIN).decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Diagram",
                "attachments": [
                    {"filename": "chart.svg", "content_type": "image/svg+xml", "data": svg_b64},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200, resp.text
        att = resp.json()["attachments"][0]
        assert att["filename"] == "chart.svg"
        assert att["content_type"] == "image/svg+xml"

    def test_reject_javascript_content_type(self, client, room_setup):
        s = room_setup
        import base64

        js_b64 = base64.b64encode(b"alert(1)").decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "JS",
                "attachments": [
                    {
                        "filename": "evil.js",
                        "content_type": "application/javascript",
                        "data": js_b64,
                    },
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 400

    def test_allow_pdf(self, client, room_setup):
        """application/pdf should be allowed."""
        s = room_setup
        import base64

        pdf_b64 = base64.b64encode(b"%PDF-1.4 fake content").decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "PDF",
                "attachments": [
                    {"filename": "doc.pdf", "content_type": "application/pdf", "data": pdf_b64},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200

    def test_too_many_attachments(self, client, room_setup):
        """More than 10 attachments must be rejected."""
        s = room_setup
        png = _make_png_b64()
        attachments = [
            {"filename": f"img{i}.png", "content_type": "image/png", "data": png} for i in range(11)
        ]
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "Too many", "attachments": attachments},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 400
        assert "Too many attachments" in resp.json()["detail"]

    def test_exactly_max_attachments_ok(self, client, room_setup):
        """Exactly 10 attachments should succeed."""
        s = room_setup
        png = _make_png_b64()
        attachments = [
            {"filename": f"img{i}.png", "content_type": "image/png", "data": png} for i in range(10)
        ]
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "Max ok", "attachments": attachments},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert len(resp.json()["attachments"]) == 10

    def test_oversized_attachment_returns_413(self, client, room_setup):
        """Attachment over 10MB should return 413."""
        s = room_setup
        import base64

        # 10MB + 1 byte
        big_data = base64.b64encode(b"x" * (10 * 1024 * 1024 + 1)).decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "Too big",
                "attachments": [
                    {"filename": "huge.png", "content_type": "image/png", "data": big_data},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Batch query tests
# ---------------------------------------------------------------------------


class TestBatchAttachmentQuery:
    def test_batch_fetch(self, client, room_setup):
        """get_batch_message_attachments returns grouped results."""
        s = room_setup
        # Send two messages with attachments
        r1 = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "msg1",
                "attachments": [
                    {"filename": "a.png", "content_type": "image/png", "data": _make_png_b64()},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        r2 = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "msg2",
                "attachments": [
                    {"filename": "b.jpg", "content_type": "image/jpeg", "data": _make_jpeg_b64()},
                    {"filename": "c.png", "content_type": "image/png", "data": _make_png_b64()},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        mid1 = r1.json()["mid"]
        mid2 = r2.json()["mid"]

        result = db.get_batch_message_attachments([mid1, mid2])
        assert mid1 in result
        assert mid2 in result
        assert len(result[mid1]) == 1
        assert len(result[mid2]) == 2

    def test_batch_empty_list(self, client, room_setup):
        result = db.get_batch_message_attachments([])
        assert result == {}

    def test_listing_uses_batch(self, client, room_setup):
        """GET /messages should work correctly with batch query."""
        s = room_setup
        client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "with att",
                "attachments": [
                    {"filename": "test.png", "content_type": "image/png", "data": _make_png_b64()},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={"body": "no att"},
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        msgs = resp.json()["messages"]
        assert len(msgs) == 2
        with_att = [m for m in msgs if m["attachments"]]
        without_att = [m for m in msgs if not m["attachments"]]
        assert len(with_att) == 1
        assert len(without_att) == 1


# ---------------------------------------------------------------------------
# Migration tests
# ---------------------------------------------------------------------------


class TestAttachmentMigration:
    def test_table_exists(self, client, room_setup):
        conn = db.get_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='attachments'"
        )
        assert cursor.fetchone() is not None

    def test_index_exists(self, client, room_setup):
        conn = db.get_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_attachments_mid'"
        )
        assert cursor.fetchone() is not None

    def test_foreign_key_constraint(self, client, room_setup):
        """attachments.message_mid should reference room_messages(mid)."""
        conn = db.get_connection()
        fks = conn.execute("PRAGMA foreign_key_list(attachments)").fetchall()
        # FK should reference room_messages.mid
        assert len(fks) >= 1
        fk = fks[0]
        assert fk[2] == "room_messages"  # table
        assert fk[4] == "mid"  # to column


# ---------------------------------------------------------------------------
# Large-paste text attachment tests (allowlist + safe download)
# ---------------------------------------------------------------------------


class TestTextAttachmentAllowlist:
    """Each text MIME type added for the large-paste feature is accepted."""

    @pytest.mark.parametrize(
        ("content_type", "payload"),
        [
            ("text/plain", b"just some plain text"),
            ("text/csv", b"a,b,c\n1,2,3\n"),
            ("text/tab-separated-values", b"a\tb\tc\n1\t2\t3\n"),
            ("text/markdown", b"# Heading\n\n- item\n"),
            ("text/html", b"<html><body>hi</body></html>"),
            ("application/json", b'{"k": "v"}'),
            ("application/yaml", b"key: value\nlist:\n  - a\n"),
            ("application/xml", b"<?xml version='1.0'?><root/>"),
        ],
    )
    def test_text_types_accepted(self, client, room_setup, content_type, payload):
        s = room_setup
        b64 = base64.b64encode(payload).decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "paste",
                "attachments": [
                    {
                        "filename": f"pasted.{content_type}",
                        "content_type": content_type,
                        "data": b64,
                    },
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["attachments"][0]["content_type"] == content_type


class TestSafeAttachmentDownload:
    """The raw download path must force download and never render HTML inline."""

    def _upload(self, client, s, filename, content_type, payload):
        b64 = base64.b64encode(payload).decode()
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "paste",
                "attachments": [
                    {"filename": filename, "content_type": content_type, "data": b64},
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["attachments"][0]["id"]

    def test_html_served_as_text_plain_not_html(self, client, room_setup):
        """XSS: a text/html attachment with <script> must NOT be served as
        renderable text/html — it is downgraded to text/plain and forced to
        download so it can't execute in the room."""
        s = room_setup
        script = b"<html><body><script>alert('xss')</script></body></html>"
        att_id = self._upload(client, s, "evil.html", "text/html", script)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        # Wire content-type must not be renderable HTML.
        ctype = resp.headers["content-type"]
        assert "text/html" not in ctype
        assert ctype.startswith("text/plain")
        # Must force download.
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.headers["x-content-type-options"] == "nosniff"
        # The bytes are preserved verbatim (so the user can still read/save them),
        # but the wire content-type prevents inline execution.
        assert resp.content == script

    def test_xml_served_as_text_plain_not_xml(self, client, room_setup):
        """XSS/XXE: an application/xml attachment must be served as text/plain
        and forced to download, never as renderable/parseable XML inline."""
        s = room_setup
        payload = b"<?xml version='1.0'?><root><script>alert(1)</script></root>"
        att_id = self._upload(client, s, "data.xml", "application/xml", payload)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        ctype = resp.headers["content-type"]
        assert "xml" not in ctype
        assert ctype.startswith("text/plain")
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.content == payload

    def test_plain_text_download_forces_attachment(self, client, room_setup):
        s = room_setup
        payload = b"hello world"
        att_id = self._upload(client, s, "note.txt", "text/plain", payload)
        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.content == payload

    def test_download_requires_auth(self, client, room_setup):
        s = room_setup
        resp = client.get(f"/{s['ns']}/attachments/any-id/download")
        assert resp.status_code == 401

    def test_download_requires_room_membership(self, client, two_member_setup):
        s = two_member_setup
        att_id = self._upload(client, s, "note.txt", "text/plain", b"secret")
        charlie = client.post(
            f"/{s['ns']}/identities",
            headers={"X-Namespace-Secret": s["ns_secret"]},
            json={"metadata": {"display_name": "Charlie"}},
        ).json()
        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": charlie["secret"]},
        )
        assert resp.status_code == 403

    def test_download_filename_header_sanitized(self, client, room_setup):
        """Newlines/quotes in filename can't break out of the header."""
        s = room_setup
        att_id = self._upload(client, s, 'bad"\r\nname.txt', "text/plain", b"x")
        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        cd = resp.headers["content-disposition"]
        assert "\r" not in cd and "\n" not in cd

    def test_malicious_svg_download_is_inert(self, client, room_setup):
        """A scripted SVG keeps its real Content-Type but is served with a
        sandbox CSP, forced download, and nosniff, so nothing in it executes."""
        s = room_setup
        att_id = self._upload(client, s, "evil.svg", "image/svg+xml", _SVG_MALICIOUS)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/svg+xml")
        assert resp.headers["content-security-policy"] == "sandbox; default-src 'none'"
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.content == _SVG_MALICIOUS

    def test_png_download_headers_unchanged(self, client, room_setup):
        """Regression: PNG keeps its Content-Type and download semantics."""
        s = room_setup
        png = base64.b64decode(_make_png_b64())
        att_id = self._upload(client, s, "shot.png", "image/png", png)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/png")
        assert resp.headers["content-disposition"] == 'attachment; filename="shot.png"'
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.content == png


class TestAttachmentTypePolicy:
    """Default-deny policy: any text or media type in, archives/binaries out."""

    def _send(self, client, s, filename, content_type, payload=b"payload"):
        return client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "attach",
                "attachments": [
                    {
                        "filename": filename,
                        "content_type": content_type,
                        "data": base64.b64encode(payload).decode(),
                    },
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )

    @pytest.mark.parametrize(
        ("filename", "content_type"),
        [
            ("script.py", "text/x-python"),
            ("run.sh", "text/x-shellscript"),
            ("style.css", "text/css"),
            ("subs.vtt", "text/vtt"),
            ("feed.xml", "text/xml"),
            ("photo.heic", "image/heic"),
            ("photo.avif", "image/avif"),
            ("clip.mp4", "video/mp4"),
            ("clip.mov", "video/quicktime"),
            ("voice.m4a", "audio/mp4"),
            ("voice.mp3", "audio/mpeg"),
            ("conf.yml", "application/x-yaml"),
        ],
    )
    def test_newly_accepted_types(self, client, room_setup, filename, content_type):
        resp = self._send(client, room_setup, filename, content_type)
        assert resp.status_code == 200, resp.text
        assert resp.json()["attachments"][0]["content_type"] == content_type

    @pytest.mark.parametrize(
        ("filename", "content_type"),
        [
            ("bundle.zip", "application/zip"),
            ("logs.gz", "application/gzip"),
            ("src.tar", "application/x-tar"),
            ("src.7z", "application/x-7z-compressed"),
            ("src.rar", "application/vnd.rar"),
            ("blob.bin", "application/octet-stream"),
            ("setup.exe", "application/vnd.microsoft.portable-executable"),
            ("app.dmg", "application/x-apple-diskimage"),
            ("evil.js", "application/javascript"),
            ("evil.js", "text/javascript"),
            ("macro.doc", "application/msword"),
        ],
    )
    def test_rejected_types(self, client, room_setup, filename, content_type):
        resp = self._send(client, room_setup, filename, content_type)
        assert resp.status_code == 400, resp.text
        assert "Unsupported attachment type" in resp.json()["detail"]

    def test_content_type_parameters_tolerated(self, client, room_setup):
        """A charset parameter must not turn an accepted type into a rejection."""
        resp = self._send(client, room_setup, "note.txt", "text/plain; charset=utf-8")
        assert resp.status_code == 200, resp.text

    def test_empty_subtype_rejected(self, client, room_setup):
        """A bare prefix is not a MIME type and must not pass the prefix check."""
        resp = self._send(client, room_setup, "weird", "text/")
        assert resp.status_code == 400, resp.text


class TestExpandedTypeDownloadSafety:
    """Newly accepted types must inherit the forced-download guarantees."""

    def _upload(self, client, s, filename, content_type, payload):
        resp = client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            json={
                "body": "attach",
                "attachments": [
                    {
                        "filename": filename,
                        "content_type": content_type,
                        "data": base64.b64encode(payload).decode(),
                    },
                ],
            },
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["attachments"][0]["id"]

    def test_html_with_charset_still_downgraded(self, client, room_setup):
        """The downgrade compares normalized types, so a charset parameter
        cannot smuggle renderable HTML past it."""
        s = room_setup
        script = b"<html><script>alert('xss')</script></html>"
        att_id = self._upload(client, s, "evil.html", "text/html; charset=utf-8", script)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert "text/html" not in resp.headers["content-type"]
        assert resp.headers["content-type"].startswith("text/plain")
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.content == script

    def test_source_code_download_is_text_and_forced(self, client, room_setup):
        s = room_setup
        payload = b"import os\nprint(os.getcwd())\n"
        att_id = self._upload(client, s, "script.py", "text/x-python", payload)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.headers["content-disposition"].startswith("attachment")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.content == payload

    def test_video_keeps_real_content_type(self, client, room_setup):
        """Media is not script-capable, so it keeps its real type — but still
        downloads with nosniff and the sandbox CSP."""
        s = room_setup
        payload = b"\x00\x00\x00\x18ftypmp42"
        att_id = self._upload(client, s, "clip.mp4", "video/mp4", payload)

        resp = client.get(
            f"/{s['ns']}/attachments/{att_id}/download",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("video/mp4")
        assert resp.headers["content-disposition"] == 'attachment; filename="clip.mp4"'
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["content-security-policy"] == "sandbox; default-src 'none'"
        assert resp.content == payload
