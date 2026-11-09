"""Subscribe behavior when a client presents an unusable (non-v7) cursor.

An absent cursor means "never seen": every non-empty topic is reported as
changed and the poll returns at once. An unusable cursor means "unknown" and
is pinned to the topic's current latest mid, so the poll waits for its
timeout like any caught-up subscriber.
"""

import threading
import time

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app
from deadrop.events import InMemoryEventBus, get_event_bus, reset_event_bus

# A v4: lexicographically above every v7, so no real mid can pass it.
POISONED_V4 = "1e141d46-f442-4391-b714-98aeb44c442f"


@pytest.fixture(autouse=True)
def _reset_events():
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def room_with_message(client):
    """A room containing one message, plus Alice's credentials."""
    ns = client.post("/admin/namespaces", headers={"X-Admin-Token": "test-admin-token"}).json()
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
    send = client.post(
        f"/{ns['ns']}/rooms/{room['room_id']}/messages",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"body": "hello"},
    ).json()
    return {
        "ns": ns["ns"],
        "alice": alice,
        "room_id": room["room_id"],
        "topic": f"room:{room['room_id']}",
        "mid": send["mid"],
    }


def _subscribe(client, data, cursor, timeout=1):
    started = time.monotonic()
    response = client.post(
        f"/{data['ns']}/subscribe",
        headers={"X-Inbox-Secret": data["alice"]["secret"]},
        json={"topics": {data["topic"]: cursor}, "mode": "poll", "timeout": timeout},
    )
    return response, time.monotonic() - started


class TestInvalidCursorDoesNotMeanNeverSeen:
    def test_invalid_cursor_blocks_for_the_full_timeout(self, client, room_with_message):
        response, elapsed = _subscribe(client, room_with_message, POISONED_V4, timeout=1)

        assert response.status_code == 200
        body = response.json()
        assert body["events"] == {}
        assert body["timeout"] is True
        assert elapsed >= 0.9, f"returned in {elapsed:.3f}s — did not block"

    def test_absent_cursor_still_returns_immediately(self, client, room_with_message):
        response, elapsed = _subscribe(client, room_with_message, None, timeout=1)

        assert response.status_code == 200
        body = response.json()
        assert body["events"] == {room_with_message["topic"]: room_with_message["mid"]}
        assert body["timeout"] is False
        assert elapsed < 0.9, f"blocked for {elapsed:.3f}s — first-load behavior regressed"

    def test_empty_string_cursor_behaves_as_absent(self, client, room_with_message):
        response, _ = _subscribe(client, room_with_message, "", timeout=1)

        assert response.json()["events"] == {room_with_message["topic"]: room_with_message["mid"]}

    def test_invalid_cursor_still_sees_a_message_sent_during_the_window(
        self, client, room_with_message
    ):
        data = room_with_message
        sent: dict[str, str] = {}

        def send_after_delay():
            time.sleep(0.3)
            sent["mid"] = client.post(
                f"/{data['ns']}/rooms/{data['room_id']}/messages",
                headers={"X-Inbox-Secret": data["alice"]["secret"]},
                json={"body": "second"},
            ).json()["mid"]

        sender = threading.Thread(target=send_after_delay)
        sender.start()
        response, _ = _subscribe(client, data, POISONED_V4, timeout=5)
        sender.join()

        assert response.json()["events"] == {data["topic"]: sent["mid"]}


class TestGetLatestColdStart:
    """get_latest must not report None for a topic the DB knows about."""

    def test_consults_db_fallback(self):
        bus = InMemoryEventBus(db_fallback=lambda ns, topic, seen: ("0198-mid", "sender"))
        assert bus.get_latest("ns1", "room:abc") == "0198-mid"

    def test_caches_the_fallback_result(self):
        calls = []

        def fallback(ns, topic, seen):
            calls.append(topic)
            return ("0198-mid", None)

        bus = InMemoryEventBus(db_fallback=fallback)
        bus.get_latest("ns1", "room:abc")
        bus.get_latest("ns1", "room:abc")
        assert calls == ["room:abc"]

    def test_no_fallback_configured_returns_none(self):
        assert InMemoryEventBus().get_latest("ns1", "room:abc") is None

    def test_fresh_process_get_latest_returns_db_latest(self, client, room_with_message):
        data = room_with_message
        reset_event_bus()
        assert get_event_bus().get_latest(data["ns"], data["topic"]) == data["mid"]

    def test_invalid_cursor_pins_to_db_latest_on_a_cold_bus(self, client, room_with_message):
        data = room_with_message
        reset_event_bus()

        response, elapsed = _subscribe(client, data, POISONED_V4, timeout=1)

        assert response.json()["timeout"] is True
        assert elapsed >= 0.9
