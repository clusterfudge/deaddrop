"""Player cards ride the existing room message and attachment APIs.

A player is an ordinary room message with ``content_type`` set to
``application/x-player`` and a JSON body whose tracks are http(s) URLs or
audio files attached to the same message. These tests pin the server-side
properties the client-side card depends on:

  1. The body and ``content_type`` are stored and returned verbatim.
  2. Audio attachments (``audio/mpeg``, ``audio/wav``, ``audio/ogg``,
     ``audio/mp4``) are accepted, listed with their filename, and downloaded
     with their own Content-Type, which is what the card's blob URL plays.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app

PLAYER_CONTENT_TYPE = "application/x-player"

# The first bytes of an MPEG audio frame; the server never decodes audio.
MP3_BYTES = b"\xff\xfb\x90\x64" + b"\x00" * 64


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def room(client):
    ns = client.post("/admin/namespaces", headers={"X-Admin-Token": "test-admin-token"}).json()
    alice = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns["secret"]},
        json={"metadata": {"display_name": "Alice"}},
    ).json()
    created = client.post(
        f"/{ns['ns']}/rooms",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"display_name": "Listening"},
    ).json()
    return {"ns": ns["ns"], "room_id": created["room_id"], "secret": alice["secret"]}


def _post(client, room, payload):
    return client.post(
        f"/{room['ns']}/rooms/{room['room_id']}/messages",
        headers={"X-Inbox-Secret": room["secret"]},
        json=payload,
    )


def test_url_player_is_stored_verbatim(client, room):
    body = json.dumps(
        {
            "title": "Samples",
            "tracks": [
                {"title": "One", "src": "https://example.test/one.mp3"},
                {"title": "Two", "src": "https://example.test/two.mp3", "duration": 4.2},
            ],
        }
    )
    sent = _post(client, room, {"body": body, "content_type": PLAYER_CONTENT_TYPE})
    assert sent.status_code == 200, sent.text

    listed = client.get(
        f"/{room['ns']}/rooms/{room['room_id']}/messages",
        headers={"X-Inbox-Secret": room["secret"]},
    ).json()["messages"]
    got = next(m for m in listed if m["mid"] == sent.json()["mid"])
    assert got["content_type"] == PLAYER_CONTENT_TYPE
    assert got["body"] == body


@pytest.mark.parametrize(
    ("filename", "content_type"),
    [
        ("clip.mp3", "audio/mpeg"),
        ("clip.wav", "audio/wav"),
        ("clip.ogg", "audio/ogg"),
        ("clip.m4a", "audio/mp4"),
    ],
)
def test_attachment_player_round_trip(client, room, filename, content_type):
    body = json.dumps({"title": "Attached", "tracks": [{"attachment": filename}]})
    sent = _post(
        client,
        room,
        {
            "body": body,
            "content_type": PLAYER_CONTENT_TYPE,
            "attachments": [
                {
                    "filename": filename,
                    "content_type": content_type,
                    "data": base64.b64encode(MP3_BYTES).decode(),
                }
            ],
        },
    )
    assert sent.status_code == 200, sent.text
    att = sent.json()["attachments"][0]
    assert att["filename"] == filename
    assert att["content_type"] == content_type

    raw = client.get(
        f"/{room['ns']}/attachments/{att['id']}/download",
        headers={"X-Inbox-Secret": room["secret"]},
    )
    assert raw.status_code == 200
    assert raw.headers["content-type"].startswith(content_type)
    assert raw.content == MP3_BYTES
