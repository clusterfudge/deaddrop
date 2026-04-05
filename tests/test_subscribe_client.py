"""Tests for subscribe methods on the Python client."""

from unittest.mock import patch

import pytest

from deadrop.backends import AuthenticationError, DeaddropAPIError
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


class TestListenAllBackoff:
    """Tests for exponential backoff in listen_all."""

    def test_auth_error_raises_immediately_by_default(self, client, setup):
        """With default max_retries=0, auth errors cause immediate failure on first retry."""
        data = setup
        # max_retries=0 means: fail fast on auth errors (no retries)
        # But we need at least 1 retry attempt to trigger the raise.
        # Actually, max_retries=0 means the check `if max_retries and ...` is False
        # so it will retry forever. Let's use max_retries=1 for fail-fast.

        with patch.object(client, "subscribe") as mock_sub:
            mock_sub.side_effect = AuthenticationError("Forbidden", status_code=403)

            gen = client.listen_all(
                data["ns"],
                data["alice"]["secret"],
                {f"room:{data['room']['room_id']}": None},
                timeout=1,
                max_retries=1,
            )

            with pytest.raises(AuthenticationError):
                next(gen)

    @patch("deadrop.client.time.sleep")
    def test_auth_error_backoff_timing(self, mock_sleep, client, setup):
        """Auth errors trigger exponential backoff before retries."""
        data = setup

        call_count = 0

        def fail_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise AuthenticationError("Forbidden", status_code=403)
            # 4th call succeeds
            return {
                "events": {f"room:{data['room']['room_id']}": "mid-1"},
                "timeout": False,
            }

        with patch.object(client, "subscribe", side_effect=fail_then_succeed):
            gen = client.listen_all(
                data["ns"],
                data["alice"]["secret"],
                {f"room:{data['room']['room_id']}": None},
                timeout=1,
                # max_retries=0 means retry indefinitely
            )
            topic, mid = next(gen)

        assert topic == f"room:{data['room']['room_id']}"
        assert mid == "mid-1"

        # Should have slept 3 times with exponential backoff: 1s, 2s, 4s
        assert mock_sleep.call_count == 3
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0, 4.0]

    @patch("deadrop.client.time.sleep")
    def test_backoff_caps_at_max_delay(self, mock_sleep, client, setup):
        """Backoff delay caps at 300 seconds."""
        data = setup

        call_count = 0

        def fail_many_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 12:
                raise DeaddropAPIError("Server Error", status_code=500)
            return {
                "events": {f"room:{data['room']['room_id']}": "mid-1"},
                "timeout": False,
            }

        with patch.object(client, "subscribe", side_effect=fail_many_then_succeed):
            gen = client.listen_all(
                data["ns"],
                data["alice"]["secret"],
                {f"room:{data['room']['room_id']}": None},
                timeout=1,
            )
            next(gen)

        delays = [call.args[0] for call in mock_sleep.call_args_list]
        # After 9 retries, 2^8 = 256s. After 10, min(512, 300) = 300
        assert all(d <= 300.0 for d in delays)
        # The last few should all be 300
        assert delays[-1] == 300.0

    @patch("deadrop.client.time.sleep")
    def test_success_resets_error_counter(self, mock_sleep, client, setup):
        """A successful subscribe resets the consecutive error counter."""
        data = setup

        call_count = 0

        def alternating(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise DeaddropAPIError("Server Error", status_code=500)
            if call_count == 2:
                return {
                    "events": {f"room:{data['room']['room_id']}": "mid-1"},
                    "timeout": False,
                }
            if call_count == 3:
                raise DeaddropAPIError("Server Error", status_code=500)
            if call_count == 4:
                return {
                    "events": {f"room:{data['room']['room_id']}": "mid-2"},
                    "timeout": False,
                }
            raise StopIteration  # shouldn't reach here

        with patch.object(client, "subscribe", side_effect=alternating):
            gen = client.listen_all(
                data["ns"],
                data["alice"]["secret"],
                {f"room:{data['room']['room_id']}": None},
                timeout=1,
            )
            topic1, mid1 = next(gen)
            topic2, mid2 = next(gen)

        assert mid1 == "mid-1"
        assert mid2 == "mid-2"

        # Both errors should have delay of 1.0 (reset after success)
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 1.0]

    @patch("deadrop.client.time.sleep")
    def test_max_retries_raises_after_limit(self, mock_sleep, client, setup):
        """Raises after max_retries consecutive errors."""
        data = setup

        with patch.object(client, "subscribe") as mock_sub:
            mock_sub.side_effect = AuthenticationError("Forbidden", status_code=403)

            gen = client.listen_all(
                data["ns"],
                data["alice"]["secret"],
                {f"room:{data['room']['room_id']}": None},
                timeout=1,
                max_retries=3,
            )

            with pytest.raises(AuthenticationError):
                next(gen)

            # Should have called subscribe 3 times
            assert mock_sub.call_count == 3
            # Sleeps happen between retries: after attempt 1, after attempt 2,
            # but on attempt 3 we hit max_retries and raise before sleeping
            assert mock_sleep.call_count == 2

    @patch("deadrop.client.time.sleep")
    def test_network_errors_trigger_backoff(self, mock_sleep, client, setup):
        """OSError (network errors) also trigger backoff."""
        data = setup

        call_count = 0

        def network_then_ok(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise OSError("Connection refused")
            return {
                "events": {f"room:{data['room']['room_id']}": "mid-1"},
                "timeout": False,
            }

        with patch.object(client, "subscribe", side_effect=network_then_ok):
            gen = client.listen_all(
                data["ns"],
                data["alice"]["secret"],
                {f"room:{data['room']['room_id']}": None},
                timeout=1,
            )
            next(gen)

        assert mock_sleep.call_count == 2
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1.0, 2.0]
