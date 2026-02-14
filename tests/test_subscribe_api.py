"""Tests for the subscribe API endpoint."""

import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from deadrop.api import app
from deadrop.events import get_event_bus, reset_event_bus


@pytest.fixture(autouse=True)
def _reset_events():
    """Reset event bus between tests."""
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def admin_headers():
    """Admin auth headers."""
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def setup_namespace(client, admin_headers):
    """Create a namespace and return its info."""
    response = client.post("/admin/namespaces", headers=admin_headers)
    return response.json()


@pytest.fixture
def setup_identities(client, setup_namespace):
    """Create namespace with two identities."""
    ns = setup_namespace
    ns_secret = ns["secret"]

    alice = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Alice"}},
    ).json()

    bob = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Bob"}},
    ).json()

    return {
        "ns": ns["ns"],
        "ns_secret": ns_secret,
        "alice": alice,
        "bob": bob,
    }


@pytest.fixture
def setup_with_room(client, setup_identities):
    """Create identities and a room with both as members."""
    data = setup_identities

    room = client.post(
        f"/{data['ns']}/rooms",
        headers={"X-Inbox-Secret": data["alice"]["secret"]},
        json={"display_name": "Test Room"},
    ).json()

    # Add Bob to the room
    client.post(
        f"/{data['ns']}/rooms/{room['room_id']}/members",
        headers={"X-Inbox-Secret": data["alice"]["secret"]},
        json={"identity_id": data["bob"]["id"]},
    )

    return {**data, "room": room}


class TestSubscribeAuth:
    """Tests for authentication and authorization."""

    def test_subscribe_requires_auth(self, client, setup_identities):
        """Subscribe without auth header returns 401."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            json={"topics": {f"inbox:{data['alice']['id']}": None}},
        )
        assert response.status_code == 401

    def test_subscribe_wrong_namespace(self, client, admin_headers, setup_identities):
        """Identity from ns1 cannot subscribe in ns2."""
        data = setup_identities

        # Create a second namespace
        ns2 = client.post("/admin/namespaces", headers=admin_headers).json()

        response = client.post(
            f"/{ns2['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"topics": {f"inbox:{data['alice']['id']}": None}},
        )
        assert response.status_code == 403


class TestSubscribeTopicValidation:
    """Tests for topic key validation."""

    def test_subscribe_own_inbox_allowed(self, client, setup_identities):
        """Can subscribe to own inbox."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"inbox:{data['alice']['id']}": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 200

    def test_subscribe_other_inbox_forbidden(self, client, setup_identities):
        """Cannot subscribe to another identity's inbox."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"inbox:{data['bob']['id']}": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 403
        assert "another identity's inbox" in response.json()["detail"]

    def test_subscribe_room_member_allowed(self, client, setup_with_room):
        """Can subscribe to a room you're a member of."""
        data = setup_with_room
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"room:{data['room']['room_id']}": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 200

    def test_subscribe_room_non_member_forbidden(self, client, setup_identities):
        """Cannot subscribe to a room you're not a member of."""
        data = setup_identities

        # Alice creates a room (only Alice is a member)
        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Private Room"},
        ).json()

        # Bob tries to subscribe
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={
                "topics": {f"room:{room['room_id']}": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 403
        assert "Not a member" in response.json()["detail"]

    def test_subscribe_invalid_topic_format(self, client, setup_identities):
        """Malformed topic key returns 400."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {"bad-topic-no-colon": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 400
        assert "Invalid topic format" in response.json()["detail"]

    def test_subscribe_unknown_topic_type(self, client, setup_identities):
        """Unknown topic type returns 400."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {"channel:abc": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 400
        assert "Unknown topic type" in response.json()["detail"]

    def test_subscribe_empty_topics(self, client, setup_identities):
        """Empty topics dict returns 400."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"topics": {}, "timeout": 1},
        )
        assert response.status_code == 400

    def test_subscribe_room_wrong_namespace(self, client, admin_headers, setup_identities):
        """Cannot subscribe to a room from a different namespace."""
        data = setup_identities

        # Create room in ns1
        room = client.post(
            f"/{data['ns']}/rooms",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"display_name": "Room in NS1"},
        ).json()

        # Create ns2 with new identity
        ns2 = client.post("/admin/namespaces", headers=admin_headers).json()
        charlie = client.post(
            f"/{ns2['ns']}/identities",
            headers={"X-Namespace-Secret": ns2["secret"]},
            json={"metadata": {"display_name": "Charlie"}},
        ).json()

        # Charlie in ns2 tries to subscribe to room in ns1
        response = client.post(
            f"/{ns2['ns']}/subscribe",
            headers={"X-Inbox-Secret": charlie["secret"]},
            json={
                "topics": {f"room:{room['room_id']}": None},
                "timeout": 1,
            },
        )
        assert response.status_code in (403, 404)


class TestSubscribePollMode:
    """Tests for poll mode subscribe behavior."""

    def test_subscribe_poll_timeout(self, client, setup_identities):
        """Subscribe with no activity returns timeout."""
        data = setup_identities
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"inbox:{data['alice']['id']}": None},
                "timeout": 1,
            },
        )
        assert response.status_code == 200
        result = response.json()
        assert result["events"] == {}
        assert result["timeout"] is True

    def test_subscribe_poll_immediate_return(self, client, setup_with_room):
        """If topic already has changes, return immediately."""
        data = setup_with_room
        event_bus = get_event_bus()

        # Pre-publish an event
        asyncio.run(
            event_bus.publish(
                data["ns"],
                f"room:{data['room']['room_id']}",
                "01961234-0000-7000-8000-000000000001",
            )
        )

        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"room:{data['room']['room_id']}": None},
                "timeout": 5,
            },
        )
        assert response.status_code == 200
        result = response.json()
        assert f"room:{data['room']['room_id']}" in result["events"]
        assert result["timeout"] is False

    def test_subscribe_poll_receives_event(self, client, setup_with_room):
        """Subscribe blocks and receives event when published."""
        data = setup_with_room
        event_bus = get_event_bus()

        mid = "01961234-0000-7000-8000-000000000001"

        # Publish from a background thread after a small delay
        def delayed_publish():
            import time

            time.sleep(0.2)
            loop = asyncio.new_event_loop()
            loop.run_until_complete(
                event_bus.publish(data["ns"], f"room:{data['room']['room_id']}", mid)
            )
            loop.close()

        thread = threading.Thread(target=delayed_publish)
        thread.start()

        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"room:{data['room']['room_id']}": None},
                "timeout": 5,
            },
        )
        thread.join()

        assert response.status_code == 200
        result = response.json()
        assert result["events"] == {f"room:{data['room']['room_id']}": mid}
        assert result["timeout"] is False

    def test_subscribe_multiple_topics_mixed(self, client, setup_with_room):
        """Subscribe to inbox + room; only changed topic returned."""
        data = setup_with_room
        event_bus = get_event_bus()

        mid = "01961234-0000-7000-8000-000000000001"

        # Pre-publish only to the room
        asyncio.run(event_bus.publish(data["ns"], f"room:{data['room']['room_id']}", mid))

        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {
                    f"inbox:{data['alice']['id']}": None,
                    f"room:{data['room']['room_id']}": None,
                },
                "timeout": 1,
            },
        )
        assert response.status_code == 200
        result = response.json()
        assert f"room:{data['room']['room_id']}" in result["events"]
        assert f"inbox:{data['alice']['id']}" not in result["events"]

    def test_subscribe_with_cursor_no_new_messages(self, client, setup_with_room):
        """Subscribe with cursor matching latest returns timeout."""
        data = setup_with_room
        event_bus = get_event_bus()

        mid = "01961234-0000-7000-8000-000000000001"

        asyncio.run(event_bus.publish(data["ns"], f"room:{data['room']['room_id']}", mid))

        # Subscribe with cursor AT the latest — no new messages
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={
                "topics": {f"room:{data['room']['room_id']}": mid},
                "timeout": 1,
            },
        )
        assert response.status_code == 200
        result = response.json()
        assert result["events"] == {}
        assert result["timeout"] is True


class TestEventPublishIntegration:
    """Tests that sending messages triggers subscription events."""

    def test_send_dm_triggers_inbox_event(self, client, setup_identities):
        """Sending a DM publishes an event on the recipient's inbox topic."""
        data = setup_identities
        event_bus = get_event_bus()

        # Alice sends a message to Bob
        send_resp = client.post(
            f"/{data['ns']}/send",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"to": data["bob"]["id"], "body": "Hello Bob!"},
        )
        assert send_resp.status_code == 200
        sent_mid = send_resp.json()["mid"]

        # The event bus should now have the inbox topic updated
        latest = event_bus.get_latest(data["ns"], f"inbox:{data['bob']['id']}")
        assert latest == sent_mid

    def test_send_room_message_triggers_room_event(self, client, setup_with_room):
        """Sending a room message publishes an event on the room topic."""
        data = setup_with_room
        event_bus = get_event_bus()

        # Alice sends a room message
        send_resp = client.post(
            f"/{data['ns']}/rooms/{data['room']['room_id']}/messages",
            headers={"X-Inbox-Secret": data["alice"]["secret"]},
            json={"body": "Hello room!"},
        )
        assert send_resp.status_code == 200
        sent_mid = send_resp.json()["mid"]

        # The event bus should now have the room topic updated
        latest = event_bus.get_latest(data["ns"], f"room:{data['room']['room_id']}")
        assert latest == sent_mid

    def test_subscribe_then_send_dm_receives_event(self, client, setup_identities):
        """Subscribe to inbox, then send a DM — subscriber gets the event."""
        data = setup_identities

        sent_mid = None

        def send_dm_after_delay():
            """Send a DM from Alice to Bob after a small delay."""
            nonlocal sent_mid
            import time

            time.sleep(0.3)
            resp = client.post(
                f"/{data['ns']}/send",
                headers={"X-Inbox-Secret": data["alice"]["secret"]},
                json={"to": data["bob"]["id"], "body": "Hello!"},
            )
            sent_mid = resp.json()["mid"]

        thread = threading.Thread(target=send_dm_after_delay)
        thread.start()

        # Bob subscribes to his inbox
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={
                "topics": {f"inbox:{data['bob']['id']}": None},
                "timeout": 5,
            },
        )
        thread.join()

        assert response.status_code == 200
        result = response.json()
        assert result["timeout"] is False
        assert f"inbox:{data['bob']['id']}" in result["events"]
        assert result["events"][f"inbox:{data['bob']['id']}"] == sent_mid

    def test_subscribe_then_send_room_message_receives_event(self, client, setup_with_room):
        """Subscribe to room, then send a message — subscriber gets the event."""
        data = setup_with_room
        room_id = data["room"]["room_id"]

        sent_mid = None

        def send_room_msg_after_delay():
            nonlocal sent_mid
            import time

            time.sleep(0.3)
            resp = client.post(
                f"/{data['ns']}/rooms/{room_id}/messages",
                headers={"X-Inbox-Secret": data["alice"]["secret"]},
                json={"body": "Hello room!"},
            )
            sent_mid = resp.json()["mid"]

        thread = threading.Thread(target=send_room_msg_after_delay)
        thread.start()

        # Bob subscribes to the room
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={
                "topics": {f"room:{room_id}": None},
                "timeout": 5,
            },
        )
        thread.join()

        assert response.status_code == 200
        result = response.json()
        assert result["timeout"] is False
        assert f"room:{room_id}" in result["events"]
        assert result["events"][f"room:{room_id}"] == sent_mid

    def test_subscribe_multi_topic_one_fires(self, client, setup_with_room):
        """Subscribe to inbox + room, only room gets a message."""
        data = setup_with_room
        room_id = data["room"]["room_id"]

        sent_mid = None

        def send_room_msg_after_delay():
            nonlocal sent_mid
            import time

            time.sleep(0.3)
            resp = client.post(
                f"/{data['ns']}/rooms/{room_id}/messages",
                headers={"X-Inbox-Secret": data["alice"]["secret"]},
                json={"body": "Room only"},
            )
            sent_mid = resp.json()["mid"]

        thread = threading.Thread(target=send_room_msg_after_delay)
        thread.start()

        # Bob subscribes to both inbox and room
        response = client.post(
            f"/{data['ns']}/subscribe",
            headers={"X-Inbox-Secret": data["bob"]["secret"]},
            json={
                "topics": {
                    f"inbox:{data['bob']['id']}": None,
                    f"room:{room_id}": None,
                },
                "timeout": 5,
            },
        )
        thread.join()

        assert response.status_code == 200
        result = response.json()
        assert result["timeout"] is False
        # Only room should have an event
        assert f"room:{room_id}" in result["events"]
        assert f"inbox:{data['bob']['id']}" not in result["events"]
