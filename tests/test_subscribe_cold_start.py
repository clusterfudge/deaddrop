"""Test: subscribe detects messages that existed before the event bus started.

Regression test for the cold-start bug where InMemoryEventBus._latest is
empty on process start. Messages posted before the current process (or
before the event bus was created) are invisible to subscribe() because
_check_changes() only consults the in-memory dict, never the DB.

Symptom: deaddrop watcher's long-poll returns timeout=true indefinitely
even though GET /rooms/{id}/messages?after={cursor} returns the message.
"""

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app
from deadrop.events import reset_event_bus


@pytest.fixture(autouse=True)
def _reset_events():
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def setup_with_room(client, admin_headers):
    """Create a namespace, two identities, and a room."""
    ns_resp = client.post("/admin/namespaces", headers=admin_headers)
    ns = ns_resp.json()
    ns_id = ns["ns"]
    ns_secret = ns["secret"]

    alice = client.post(
        f"/{ns_id}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Alice"}},
    ).json()

    bob = client.post(
        f"/{ns_id}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Bob"}},
    ).json()

    room = client.post(
        f"/{ns_id}/rooms",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"display_name": "Test Room"},
    ).json()

    client.post(
        f"/{ns_id}/rooms/{room['room_id']}/members",
        headers={"X-Inbox-Secret": alice["secret"]},
        json={"identity_id": bob["id"]},
    )

    return {
        "ns": ns_id,
        "alice": alice,
        "bob": bob,
        "room_id": room["room_id"],
    }


class TestSubscribeColdStart:
    """Subscribe must detect pre-existing messages after event bus restart."""

    def test_subscribe_detects_message_after_event_bus_reset(self, client, setup_with_room):
        """The core bug: message exists in DB, event bus restarted,
        subscribe should still detect it."""
        data = setup_with_room
        ns = data["ns"]
        room_id = data["room_id"]
        alice_secret = data["alice"]["secret"]
        bob_secret = data["bob"]["secret"]

        # Alice sends a message (this publishes to the event bus)
        msg_resp = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            headers={"X-Inbox-Secret": alice_secret},
            json={"body": "Hello from Alice"},
        )
        assert msg_resp.status_code == 200
        msg = msg_resp.json()
        alice_mid = msg["mid"]

        # Bob reads it and advances his cursor
        bob_messages = client.get(
            f"/{ns}/rooms/{room_id}/messages",
            headers={"X-Inbox-Secret": bob_secret},
        )
        assert bob_messages.status_code == 200

        # Alice sends a second message
        msg2_resp = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            headers={"X-Inbox-Secret": alice_secret},
            json={"body": "Are you there?"},
        )
        assert msg2_resp.status_code == 200
        assert "mid" in msg2_resp.json()  # second message persisted; we'll pick it up post-restart

        # *** SIMULATE SERVER RESTART ***
        # Reset the event bus — this is what happens when the process restarts.
        # _latest is now empty. The messages still exist in the DB.
        reset_event_bus()

        # Bob subscribes with his cursor at alice_mid (before the second message).
        # The second message EXISTS in the DB but the event bus doesn't know about it.
        sub_resp = client.post(
            f"/{ns}/subscribe",
            headers={"X-Inbox-Secret": bob_secret},
            json={
                "topics": {f"room:{room_id}": alice_mid},
                "mode": "poll",
                "timeout": 1,  # immediate check, don't block
            },
        )
        assert sub_resp.status_code == 200
        result = sub_resp.json()

        # BUG: without the fix, this returns {"events": {}, "timeout": true}
        # because _check_changes sees no entry in _latest for this topic.
        # With the fix, it should detect that the DB has a newer message.
        assert result["timeout"] is False, (
            f"Subscribe should detect the pre-existing message, got: {result}"
        )
        events = result["events"]
        assert f"room:{room_id}" in events, f"Room topic should be in events, got: {events}"

    def test_subscribe_no_false_positive_when_cursor_is_current(self, client, setup_with_room):
        """After reset, subscribe with cursor AT latest should NOT fire."""
        data = setup_with_room
        ns = data["ns"]
        room_id = data["room_id"]
        alice_secret = data["alice"]["secret"]
        bob_secret = data["bob"]["secret"]

        # Alice sends a message
        msg_resp = client.post(
            f"/{ns}/rooms/{room_id}/messages",
            headers={"X-Inbox-Secret": alice_secret},
            json={"body": "Hello"},
        )
        assert msg_resp.status_code == 200
        latest_mid = msg_resp.json()["mid"]

        # Reset event bus (simulate restart)
        reset_event_bus()

        # Bob subscribes with cursor AT the latest message — nothing new
        sub_resp = client.post(
            f"/{ns}/subscribe",
            headers={"X-Inbox-Secret": bob_secret},
            json={
                "topics": {f"room:{room_id}": latest_mid},
                "mode": "poll",
                "timeout": 1,
            },
        )
        assert sub_resp.status_code == 200
        result = sub_resp.json()

        # Should timeout (no new messages)
        assert result["timeout"] is True, (
            f"Subscribe should NOT fire when cursor is at latest, got: {result}"
        )

    def test_subscribe_inbox_detects_message_after_reset(self, client, setup_with_room):
        """Inbox subscribe also needs cold-start detection."""
        data = setup_with_room
        ns = data["ns"]
        alice_secret = data["alice"]["secret"]
        bob_secret = data["bob"]["secret"]
        bob_id = data["bob"]["id"]

        # Alice sends a DM to Bob
        dm_resp = client.post(
            f"/{ns}/send",
            headers={"X-Inbox-Secret": alice_secret},
            json={"to": bob_id, "body": "Hey Bob, DM"},
        )
        assert dm_resp.status_code == 200
        dm_mid = dm_resp.json()["mid"]

        # Alice sends another DM
        dm2_resp = client.post(
            f"/{ns}/send",
            headers={"X-Inbox-Secret": alice_secret},
            json={"to": bob_id, "body": "Second DM"},
        )
        assert dm2_resp.status_code == 200
        assert (
            "mid" in dm2_resp.json()
        )  # second DM persisted; cold-start subscribe should surface it

        # Reset event bus
        reset_event_bus()

        # Bob subscribes to inbox with cursor at first DM
        sub_resp = client.post(
            f"/{ns}/subscribe",
            headers={"X-Inbox-Secret": bob_secret},
            json={
                "topics": {f"inbox:{bob_id}": dm_mid},
                "mode": "poll",
                "timeout": 1,
            },
        )
        assert sub_resp.status_code == 200
        result = sub_resp.json()

        assert result["timeout"] is False, (
            f"Inbox subscribe should detect pre-existing DM, got: {result}"
        )
