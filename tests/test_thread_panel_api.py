"""Tests for the room attachments listing and message search endpoints."""

import base64
import struct
import uuid
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
def two_member_setup(client, admin_headers):
    """Namespace with a room containing Alice (creator) and Bob, plus Carol outside."""
    ns = client.post("/admin/namespaces", headers=admin_headers).json()
    ns_headers = {"X-Namespace-Secret": ns["secret"]}

    def _identity(name):
        return client.post(
            f"/{ns['ns']}/identities", headers=ns_headers, json={"metadata": {"display_name": name}}
        ).json()

    alice = _identity("Alice")
    bob = _identity("Bob")
    carol = _identity("Carol")

    room = client.post(
        f"/{ns['ns']}/rooms",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"display_name": "Gallery Room"},
    ).json()

    client.post(
        f"/{ns['ns']}/rooms/{room['room_id']}/members",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"identity_id": bob["id"]},
    )

    return {
        "ns": ns["ns"],
        "room_id": room["room_id"],
        "alice_secret": alice["secret"],
        "alice_id": alice["id"],
        "bob_secret": bob["secret"],
        "bob_id": bob["id"],
        "carol_secret": carol["secret"],
    }


def _make_png_b64():
    """Minimal valid 1x1 PNG as base64."""

    def _chunk(chunk_type, data):
        c = chunk_type + data
        crc = struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + c + crc

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    png = sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    return base64.b64encode(png).decode()


def _send(client, s, secret, body, attachments=None):
    payload = {"body": body}
    if attachments:
        payload["attachments"] = attachments
    resp = client.post(
        f"/{s['ns']}/rooms/{s['room_id']}/messages",
        headers={"X-Inbox-Secret": secret},
        json=payload,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["mid"]


def _png_att(name):
    return {"filename": name, "content_type": "image/png", "data": _make_png_b64()}


def _text_att(name):
    return {
        "filename": name,
        "content_type": "text/plain",
        "data": base64.b64encode(b"hello world").decode(),
    }


# ---------------------------------------------------------------------------
# DB layer
# ---------------------------------------------------------------------------


class TestListRoomAttachmentsDB:
    def test_newest_first_with_sender(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "first", [_png_att("a.png")])
        _send(client, s, s["bob_secret"], "second", [_png_att("b.png")])

        rows = db.list_room_attachments(s["room_id"])

        assert [r["filename"] for r in rows] == ["b.png", "a.png"]
        assert rows[0]["from"] == s["bob_id"]
        assert rows[1]["from"] == s["alice_id"]
        assert rows[0]["message_created_at"]
        assert "data" not in rows[0]

    def test_scoped_to_room(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "in room", [_png_att("mine.png")])

        other = client.post(
            f"/{s['ns']}/rooms",
            headers={"X-Inbox-Secret": s["alice_secret"]},
            json={"display_name": "Other"},
        ).json()
        client.post(
            f"/{s['ns']}/rooms/{other['room_id']}/messages",
            headers={"X-Inbox-Secret": s["alice_secret"]},
            json={"body": "elsewhere", "attachments": [_png_att("theirs.png")]},
        )

        rows = db.list_room_attachments(s["room_id"])
        assert [r["filename"] for r in rows] == ["mine.png"]

    def test_keyset_pagination_covers_every_row_once(self, client, two_member_setup):
        s = two_member_setup
        # Two messages, three attachments each: the page boundary falls inside
        # a message, which is exactly what the compound cursor exists for.
        for i in range(2):
            _send(
                client,
                s,
                s["alice_secret"],
                f"msg{i}",
                [_png_att(f"{i}-{j}.png") for j in range(3)],
            )

        seen = []
        cursor = (None, None)
        for _ in range(10):
            page = db.list_room_attachments(
                s["room_id"], before_mid=cursor[0], before_id=cursor[1], limit=2
            )
            if not page:
                break
            seen.extend(r["id"] for r in page)
            cursor = (page[-1]["message_mid"], page[-1]["id"])

        assert len(seen) == 6
        assert len(set(seen)) == 6

    def test_lone_mid_cursor_is_ignored_at_db_layer(self, client, two_member_setup):
        s = two_member_setup
        mid = _send(client, s, s["alice_secret"], "one", [_png_att("a.png")])

        # The API rejects a half cursor; the db layer treats it as no cursor
        # rather than silently dropping the boundary message's attachments.
        rows = db.list_room_attachments(s["room_id"], before_mid=mid)
        assert len(rows) == 1


class TestSearchRoomMessagesDB:
    def test_case_insensitive_substring(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "Deploying the Widget now")
        _send(client, s, s["alice_secret"], "unrelated")

        rows = db.search_room_messages(s["room_id"], "widget")
        assert [r["body"] for r in rows] == ["Deploying the Widget now"]

    def test_wildcards_are_literal(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "100% done")
        _send(client, s, s["alice_secret"], "nothing to see")

        assert len(db.search_room_messages(s["room_id"], "100%")) == 1
        # A bare % must not match everything.
        assert len(db.search_room_messages(s["room_id"], "%")) == 1

    def test_underscore_is_literal(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "snake_case wins")
        _send(client, s, s["alice_secret"], "snakeXcase loses")

        rows = db.search_room_messages(s["room_id"], "snake_case")
        assert [r["body"] for r in rows] == ["snake_case wins"]

    def test_reactions_excluded(self, client, two_member_setup):
        s = two_member_setup
        mid = _send(client, s, s["alice_secret"], "reactme")
        client.post(
            f"/{s['ns']}/rooms/{s['room_id']}/messages",
            headers={"X-Inbox-Secret": s["bob_secret"]},
            json={"body": "\U0001f44d", "content_type": "reaction", "reference_mid": mid},
        )

        rows = db.search_room_messages(s["room_id"], "")
        assert all(r["content_type"] != "reaction" for r in rows)

    def test_newest_first_and_before_cursor(self, client, two_member_setup):
        s = two_member_setup
        mids = [_send(client, s, s["alice_secret"], f"hit {i}") for i in range(3)]

        rows = db.search_room_messages(s["room_id"], "hit")
        assert [r["mid"] for r in rows] == list(reversed(mids))

        older = db.search_room_messages(s["room_id"], "hit", before_mid=mids[1])
        assert [r["mid"] for r in older] == [mids[0]]


class TestEscapeLike:
    def test_escapes_backslash_percent_underscore(self):
        assert db.escape_like(r"a%b_c\d") == r"a\%b\_c\\d"


# ---------------------------------------------------------------------------
# API layer
# ---------------------------------------------------------------------------


class TestAttachmentsEndpoint:
    def test_lists_images_and_files(self, client, two_member_setup):
        s = two_member_setup
        mid = _send(
            client, s, s["alice_secret"], "batch", [_png_att("pic.png"), _text_att("notes.txt")]
        )

        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments",
            headers={"X-Inbox-Secret": s["bob_secret"]},
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["room_id"] == s["room_id"]
        assert data["has_more"] is False
        assert data["next_before_mid"] is None
        assert {a["filename"] for a in data["attachments"]} == {"pic.png", "notes.txt"}
        entry = data["attachments"][0]
        assert entry["message_mid"] == mid
        assert entry["from_id"] == s["alice_id"]
        assert entry["message_created_at"]
        assert entry["size"] > 0
        assert "data" not in entry

    def test_empty_room(self, client, two_member_setup):
        s = two_member_setup
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 200
        assert resp.json()["attachments"] == []
        assert resp.json()["has_more"] is False

    def test_pagination_cursor_round_trip(self, client, two_member_setup):
        s = two_member_setup
        for i in range(4):
            _send(client, s, s["alice_secret"], f"m{i}", [_png_att(f"{i}.png")])

        first = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments?limit=2",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        ).json()
        assert first["has_more"] is True
        assert [a["filename"] for a in first["attachments"]] == ["3.png", "2.png"]

        second = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments"
            f"?limit=2&before_mid={first['next_before_mid']}&before_id={first['next_before_id']}",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        ).json()
        assert [a["filename"] for a in second["attachments"]] == ["1.png", "0.png"]
        assert second["has_more"] is False

    def test_half_cursor_rejected(self, client, two_member_setup):
        s = two_member_setup
        mid = _send(client, s, s["alice_secret"], "x", [_png_att("a.png")])

        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments?before_mid={mid}",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 400

    def test_non_v7_cursor_rejected(self, client, two_member_setup):
        s = two_member_setup
        v4 = str(uuid.uuid4())
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments?before_mid={v4}&before_id=abc",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 400

    def test_non_member_forbidden(self, client, two_member_setup):
        s = two_member_setup
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/attachments",
            headers={"X-Inbox-Secret": s["carol_secret"]},
        )
        assert resp.status_code == 403

    def test_auth_required(self, client, two_member_setup):
        s = two_member_setup
        resp = client.get(f"/{s['ns']}/rooms/{s['room_id']}/attachments")
        assert resp.status_code == 401

    def test_wrong_namespace(self, client, two_member_setup, admin_headers):
        s = two_member_setup
        other_ns = client.post("/admin/namespaces", headers=admin_headers).json()["ns"]
        resp = client.get(
            f"/{other_ns}/rooms/{s['room_id']}/attachments",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 404


class TestSearchEndpoint:
    def test_finds_matches_newest_first(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "the turso latency thing")
        _send(client, s, s["bob_secret"], "unrelated chatter")
        _send(client, s, s["alice_secret"], "TURSO again")

        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search?q=turso",
            headers={"X-Inbox-Secret": s["bob_secret"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["query"] == "turso"
        assert [m["body"] for m in data["messages"]] == [
            "TURSO again",
            "the turso latency thing",
        ]
        assert data["messages"][0]["from_id"] == s["alice_id"]
        assert data["has_more"] is False

    def test_no_matches(self, client, two_member_setup):
        s = two_member_setup
        _send(client, s, s["alice_secret"], "hello")
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search?q=zzz",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.json()["messages"] == []

    def test_pagination(self, client, two_member_setup):
        s = two_member_setup
        mids = [_send(client, s, s["alice_secret"], f"hit {i}") for i in range(3)]

        first = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search?q=hit&limit=2",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        ).json()
        assert first["has_more"] is True
        assert first["next_before_mid"] == mids[1]

        second = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search"
            f"?q=hit&limit=2&before_mid={first['next_before_mid']}",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        ).json()
        assert [m["mid"] for m in second["messages"]] == [mids[0]]

    def test_blank_term_rejected(self, client, two_member_setup):
        s = two_member_setup
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search?q=%20%20",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 400

    def test_missing_term_rejected(self, client, two_member_setup):
        s = two_member_setup
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search",
            headers={"X-Inbox-Secret": s["alice_secret"]},
        )
        assert resp.status_code == 422

    def test_non_member_forbidden(self, client, two_member_setup):
        s = two_member_setup
        resp = client.get(
            f"/{s['ns']}/rooms/{s['room_id']}/search?q=x",
            headers={"X-Inbox-Secret": s["carol_secret"]},
        )
        assert resp.status_code == 403

    def test_named_queries_are_instrumented(self, client, two_member_setup):
        """Both new queries must appear by name in the instrumentation buffer."""
        from deadrop.metrics import _request_query_buffer

        s = two_member_setup
        _send(client, s, s["alice_secret"], "instrument me", [_png_att("a.png")])

        buf: list[dict] = []
        token = _request_query_buffer.set(buf)
        try:
            db.list_room_attachments(s["room_id"])
            db.search_room_messages(s["room_id"], "instrument")
        finally:
            _request_query_buffer.reset(token)

        names = {q.get("name") for q in buf}
        assert "list_room_attachments.select" in names
        assert "search_room_messages.select" in names
