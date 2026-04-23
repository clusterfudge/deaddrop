"""Integration test: ContextVar propagation to DB executor threads."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from deadrop import db
from deadrop.api import app
from deadrop.metrics import _request_query_buffer


@pytest.fixture
def client():
    os.environ["SLOW_REQUEST_THRESHOLD_MS"] = "0"
    yield TestClient(app)
    os.environ.pop("SLOW_REQUEST_THRESHOLD_MS", None)


@pytest.fixture
def room_setup():
    ns = db.create_namespace(metadata={"display_name": "CtxVar Test"})
    alice = db.create_identity(ns["ns"], metadata={"display_name": "Alice"})
    room = db.create_room(ns["ns"], alice["id"], display_name="Test Room")
    return {"ns": ns["ns"], "alice": alice, "room": room}


def test_post_populates_db_queries(client, room_setup, capsys):
    """POST through full HTTP stack should show non-empty db_queries in slow_request."""
    ns = room_setup["ns"]
    alice = room_setup["alice"]
    room = room_setup["room"]

    import deadrop.api as api_mod

    custom_executor = ThreadPoolExecutor(max_workers=2)
    original_get = api_mod._get_db_executor
    api_mod._get_db_executor = lambda: custom_executor

    try:
        resp = client.post(
            f"/{ns}/rooms/{room['room_id']}/messages",
            json={"body": "buffer check", "content_type": "text/plain"},
            headers={"X-Inbox-Secret": alice["secret"]},
        )
    finally:
        api_mod._get_db_executor = original_get
        custom_executor.shutdown(wait=False)

    assert resp.status_code == 200

    captured = capsys.readouterr()
    assert "slow_request" in captured.out, "No slow_request log in stdout"
    assert "db_queries=[]" not in captured.out, (
        f"db_queries is empty — ContextVar not propagating.\n{captured.out}"
    )
    assert "send_room_message" in captured.out, (
        f"Expected send_room_message in db_queries.\n{captured.out}"
    )


def test_buffer_cleaned(client, room_setup):
    ns = room_setup["ns"]
    alice = room_setup["alice"]
    room = room_setup["room"]
    client.get(
        f"/{ns}/rooms/{room['room_id']}/messages", headers={"X-Inbox-Secret": alice["secret"]}
    )
    assert _request_query_buffer.get() is None
