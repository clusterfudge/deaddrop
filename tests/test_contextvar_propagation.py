"""Integration test: ContextVar propagation to DB executor threads."""

import asyncio
import contextvars
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


def test_post_populates_db_queries(client, room_setup):
    """POST through full HTTP stack populates db_queries via ContextVar propagation."""
    ns = room_setup["ns"]
    alice = room_setup["alice"]
    room = room_setup["room"]

    # Patch both read and write executors on the db module so the custom
    # executor is used for all DB operations in this request.
    custom_executor = ThreadPoolExecutor(max_workers=2)
    original_read = db.get_read_executor
    original_write = db.get_write_executor
    db.get_read_executor = lambda: custom_executor
    db.get_write_executor = lambda: custom_executor

    try:
        resp = client.post(
            f"/{ns}/rooms/{room['room_id']}/messages",
            json={"body": "buffer check", "content_type": "text/plain"},
            headers={"X-Inbox-Secret": alice["secret"]},
        )
    finally:
        db.get_read_executor = original_read
        db.get_write_executor = original_write
        custom_executor.shutdown(wait=False)

    assert resp.status_code == 200
    assert "X-Response-Time-Ms" in resp.headers


def test_contextvar_propagation_unit():
    """Unit test: ctx.run propagates ContextVars to custom executor threads."""
    test_var: contextvars.ContextVar[list] = contextvars.ContextVar("test", default=None)

    def thread_fn():
        buf = test_var.get()
        if buf is not None:
            buf.append("from_thread")

    async def run():
        buf = []
        test_var.set(buf)
        executor = ThreadPoolExecutor(max_workers=1)
        loop = asyncio.get_event_loop()
        ctx = contextvars.copy_context()
        await loop.run_in_executor(executor, ctx.run, thread_fn)
        executor.shutdown(wait=False)
        return buf

    assert asyncio.run(run()) == ["from_thread"]


def test_buffer_cleaned(client, room_setup):
    """Buffer is None outside request context."""
    ns = room_setup["ns"]
    alice = room_setup["alice"]
    room = room_setup["room"]
    client.get(
        f"/{ns}/rooms/{room['room_id']}/messages",
        headers={"X-Inbox-Secret": alice["secret"]},
    )
    assert _request_query_buffer.get() is None
