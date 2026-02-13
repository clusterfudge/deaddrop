"""Tests for subscribe methods on the Python client."""

import pytest

from deadrop.client import Deaddrop
from deadrop.events import reset_event_bus


@pytest.fixture(autouse=True)
def _reset_events():
    """Reset event bus between tests."""
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture
def client():
    """Fresh in-memory client."""
    c = Deaddrop.in_memory()
    yield c
    c.close()


@pytest.fixture
def setup(client):
    """Create namespace with Alice and Bob + a room."""
    result = client.quick_setup("Test", ["Alice", "Bob"])
    ns = result["namespace"]["ns"]
    ns_secret = result["namespace"]["secret"]
    alice = result["identities"]["Alice"]
    bob = result["identities"]["Bob"]

    room = client.create_room(ns, alice["secret"], display_name="Test Room")
    client.add_room_member(ns, room["room_id"], bob["id"], alice["secret"])

    return {
        "ns": ns,
        "ns_secret": ns_secret,
        "alice": alice,
        "bob": bob,
        "room": room,
    }


class TestSubscribePoll:
    """Tests for poll-mode subscribe on the client."""

    def test_subscribe_timeout_no_events(self, client, setup):
        """Subscribe with no activity returns timeout."""
        data = setup
        result = client.subscribe(
            data["ns"],
            data["alice"]["secret"],
            {f"inbox:{data['alice']['id']}": None},
            timeout=1,
        )
        assert result["timeout"] is True
        assert result["events"] == {}

    def test_subscribe_returns_existing_changes(self, client, setup):
        """Subscribe returns events for topics that already have messages."""
        data = setup

        # Send a message first
        msg = client.send_message(
            data["ns"],
            data["alice"]["secret"],
            data["bob"]["id"],
            "Hello Bob!",
        )

        # Now Bob subscribes — should see the inbox event immediately
        # Note: for local backend, send_message doesn't go through the API
        # so the event bus won't have the event. We need to publish manually.
        import asyncio

        from deadrop.events import get_event_bus

        bus = get_event_bus()
        asyncio.run(bus.publish(data["ns"], f"inbox:{data['bob']['id']}", msg["mid"]))

        result = client.subscribe(
            data["ns"],
            data["bob"]["secret"],
            {f"inbox:{data['bob']['id']}": None},
            timeout=1,
        )
        assert result["timeout"] is False
        assert f"inbox:{data['bob']['id']}" in result["events"]

    def test_subscribe_validates_inbox_ownership(self, client, setup):
        """Cannot subscribe to another identity's inbox."""
        data = setup
        with pytest.raises(ValueError, match="another identity's inbox"):
            client.subscribe(
                data["ns"],
                data["alice"]["secret"],
                {f"inbox:{data['bob']['id']}": None},
                timeout=1,
            )

    def test_subscribe_validates_room_membership(self, client, setup):
        """Cannot subscribe to a room you're not a member of."""
        data = setup

        # Create a room that only Alice is in
        private_room = client.create_room(
            data["ns"], data["alice"]["secret"], display_name="Private"
        )

        # Remove bob from the original room for this test, use the private room
        with pytest.raises(ValueError, match="Not a member"):
            client.subscribe(
                data["ns"],
                data["bob"]["secret"],
                {f"room:{private_room['room_id']}": None},
                timeout=1,
            )

    def test_subscribe_invalid_secret(self, client, setup):
        """Subscribe with bad secret raises error."""
        data = setup
        with pytest.raises(ValueError, match="Invalid"):
            client.subscribe(
                data["ns"],
                "bad-secret-value",
                {"inbox:fakeid": None},
                timeout=1,
            )


class TestListenAll:
    """Tests for the listen_all generator."""

    def test_listen_all_yields_events(self, client, setup):
        """listen_all yields events as they arrive."""
        data = setup

        import asyncio
        import threading

        from deadrop.events import get_event_bus

        bus = get_event_bus()
        mid = "01961234-0000-7000-8000-000000000001"

        def publish_after_delay():
            import time

            time.sleep(0.2)
            loop = asyncio.new_event_loop()
            loop.run_until_complete(bus.publish(data["ns"], f"room:{data['room']['room_id']}", mid))
            loop.close()

        thread = threading.Thread(target=publish_after_delay)
        thread.start()

        gen = client.listen_all(
            data["ns"],
            data["alice"]["secret"],
            {f"room:{data['room']['room_id']}": None},
            timeout=3,
        )

        topic, latest_mid = next(gen)
        thread.join()

        assert topic == f"room:{data['room']['room_id']}"
        assert latest_mid == mid
