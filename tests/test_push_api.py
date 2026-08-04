"""Tests for the Web Push HTTP surface.

Delivery is stubbed — a route-level test proves auth, ownership scoping and
payload plumbing; it cannot prove anything about a real push service.
"""

import time

import pytest
from fastapi.testclient import TestClient

from deadrop import db, notifier, push
from deadrop.api import app

ENDPOINT = "https://web.push.apple.com/QABC123"
OTHER_ENDPOINT = "https://updates.push.services.mozilla.com/wpush/v2/XYZ"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def live_client():
    """A client whose event loop survives between requests.

    A bare ``TestClient`` spins up (and tears down) a portal per request,
    which destroys the task the send route schedules. The watcher hooks are
    exactly the thing that has to outlive a request, so they need the
    context-managed client.
    """
    with TestClient(app) as instance:
        yield instance


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def identities(client, admin_headers):
    """A namespace with two identities."""
    ns = client.post("/admin/namespaces", headers=admin_headers).json()
    alice = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns["secret"]},
        json={"metadata": {"display_name": "Alice"}},
    ).json()
    bob = client.post(
        f"/{ns['ns']}/identities",
        headers={"X-Namespace-Secret": ns["secret"]},
        json={"metadata": {"display_name": "Bob"}},
    ).json()
    return {"ns": ns["ns"], "alice": alice, "bob": bob}


@pytest.fixture
def configured(monkeypatch):
    """Enable push with a real generated keypair."""
    public, private = push.generate_vapid_keys()
    monkeypatch.setenv("DEADROP_PUSH_ENABLED", "1")
    monkeypatch.setenv("DEADROP_VAPID_PUBLIC_KEY", public)
    monkeypatch.setenv("DEADROP_VAPID_PRIVATE_KEY", private)
    monkeypatch.setenv("DEADROP_VAPID_SUBJECT", "mailto:ops@example.com")
    return public


@pytest.fixture
def disabled(monkeypatch):
    monkeypatch.delenv("DEADROP_PUSH_ENABLED", raising=False)
    monkeypatch.delenv("DEADROP_VAPID_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("DEADROP_VAPID_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("DEADROP_VAPID_SUBJECT", raising=False)


def _wait_until(predicate, timeout=5.0):
    """Wait for a watcher state change driven by a background task.

    Arming happens in a task the send route schedules; TestClient returns
    before that task has necessarily run. The event loop lives on the
    portal thread, so sleeping here lets it progress.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _subscribe_body(endpoint=ENDPOINT):
    return {
        "endpoint": endpoint,
        "keys": {"p256dh": "BFakeKeyMaterial", "auth": "ZmFrZS1hdXRo"},
        "user_agent": "Mozilla/5.0 (iPhone)",
    }


class TestVapidPublicKeyRoute:
    def test_reports_disabled_without_config(self, client, disabled):
        body = client.get("/push/vapid-public-key").json()
        assert body == {"enabled": False, "public_key": None, "debounce_seconds": 120.0}

    def test_exposes_the_public_key_when_configured(self, client, configured):
        body = client.get("/push/vapid-public-key").json()
        assert body["enabled"] is True
        assert body["public_key"] == configured

    def test_requires_no_auth(self, client, configured):
        assert client.get("/push/vapid-public-key").status_code == 200


class TestSubscriptionCRUD:
    def test_register_and_list(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}

        created = client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())
        assert created.status_code == 200
        assert created.json()["endpoint"] == ENDPOINT

        listed = client.get(f"/{ns}/push/subscriptions", headers=headers).json()["subscriptions"]
        assert [s["endpoint"] for s in listed] == [ENDPOINT]
        assert listed[0]["user_agent"] == "Mozilla/5.0 (iPhone)"

    def test_listing_never_returns_key_material(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())

        row = client.get(f"/{ns}/push/subscriptions", headers=headers).json()["subscriptions"][0]
        assert "p256dh" not in row
        assert "auth" not in row

    def test_re_registering_the_same_endpoint_is_idempotent(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())

        listed = client.get(f"/{ns}/push/subscriptions", headers=headers).json()["subscriptions"]
        assert len(listed) == 1

    def test_multiple_devices_coexist(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())
        client.post(
            f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body(OTHER_ENDPOINT)
        )

        listed = client.get(f"/{ns}/push/subscriptions", headers=headers).json()["subscriptions"]
        assert len(listed) == 2

    def test_delete_removes_the_row(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())

        deleted = client.delete(
            f"/{ns}/push/subscriptions", headers=headers, params={"endpoint": ENDPOINT}
        )
        assert deleted.status_code == 200
        assert (
            client.get(f"/{ns}/push/subscriptions", headers=headers).json()["subscriptions"] == []
        )

    def test_delete_unknown_endpoint_is_404(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        response = client.delete(
            f"/{ns}/push/subscriptions",
            headers={"X-Inbox-Secret": alice["secret"]},
            params={"endpoint": ENDPOINT},
        )
        assert response.status_code == 404


class TestSubscriptionAuth:
    def test_register_requires_a_secret(self, client, identities):
        response = client.post(f"/{identities['ns']}/push/subscriptions", json=_subscribe_body())
        assert response.status_code == 401

    def test_register_rejects_a_foreign_secret(self, client, identities, admin_headers):
        other = client.post("/admin/namespaces", headers=admin_headers).json()
        stranger = client.post(
            f"/{other['ns']}/identities",
            headers={"X-Namespace-Secret": other["secret"]},
            json={},
        ).json()

        response = client.post(
            f"/{identities['ns']}/push/subscriptions",
            headers={"X-Inbox-Secret": stranger["secret"]},
            json=_subscribe_body(),
        )
        assert response.status_code == 403

    def test_one_identity_cannot_delete_anothers_subscription(self, client, identities):
        ns = identities["ns"]
        client.post(
            f"/{ns}/push/subscriptions",
            headers={"X-Inbox-Secret": identities["alice"]["secret"]},
            json=_subscribe_body(),
        )

        response = client.delete(
            f"/{ns}/push/subscriptions",
            headers={"X-Inbox-Secret": identities["bob"]["secret"]},
            params={"endpoint": ENDPOINT},
        )
        assert response.status_code == 404
        assert db.list_push_subscriptions(ns, identities["alice"]["id"])


class TestEndpointValidation:
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://push.example.com/x",  # not https
            "https://localhost/x",
            "https://127.0.0.1/x",
            "https://internal.local/x",
            "https://nodothost/x",
            "file:///etc/passwd",
        ],
    )
    def test_rejects_endpoints_that_are_not_public_https(self, client, identities, endpoint):
        response = client.post(
            f"/{identities['ns']}/push/subscriptions",
            headers={"X-Inbox-Secret": identities["alice"]["secret"]},
            json=_subscribe_body(endpoint),
        )
        assert response.status_code == 400

    def test_rejects_an_absurdly_long_endpoint(self, client, identities):
        response = client.post(
            f"/{identities['ns']}/push/subscriptions",
            headers={"X-Inbox-Secret": identities["alice"]["secret"]},
            json=_subscribe_body("https://push.example.com/" + "x" * 2100),
        )
        assert response.status_code == 400


class _StubSender:
    def __init__(self, ok=True, status=201):
        self.calls = []
        self.ok = ok
        self.status = status

    async def __call__(self, subscription, payload, cfg):
        self.calls.append((subscription, payload))
        return push.PushResult(
            endpoint=subscription["endpoint"],
            status_code=self.status,
            ok=self.ok,
            gone=False,
        )


@pytest.fixture
def stub_sender():
    sender = _StubSender()
    notifier.set_watcher(notifier.UnreadWatcher(sender=sender))
    yield sender
    notifier.set_watcher(None)


class TestTestPushRoute:
    def test_sends_to_every_registered_device(self, client, identities, configured, stub_sender):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())
        client.post(
            f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body(OTHER_ENDPOINT)
        )

        response = client.post(f"/{ns}/push/test", headers=headers)

        assert response.status_code == 200
        assert response.json() == {"sent": 2, "total": 2, "errors": []}
        _, payload = stub_sender.calls[0]
        assert payload["web_push"] == 8030
        assert payload["notification"]["title"] == "Deadrop"

    def test_reports_failures_without_raising(self, client, identities, configured):
        sender = _StubSender(ok=False, status=403)
        notifier.set_watcher(notifier.UnreadWatcher(sender=sender))
        try:
            ns, alice = identities["ns"], identities["alice"]
            headers = {"X-Inbox-Secret": alice["secret"]}
            client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())

            body = client.post(f"/{ns}/push/test", headers=headers).json()
            assert body["sent"] == 0
            assert len(body["errors"]) == 1
        finally:
            notifier.set_watcher(None)

    def test_503_when_push_is_not_configured(self, client, identities, disabled):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())

        assert client.post(f"/{ns}/push/test", headers=headers).status_code == 503

    def test_404_without_a_subscription(self, client, identities, configured):
        response = client.post(
            f"/{identities['ns']}/push/test",
            headers={"X-Inbox-Secret": identities["alice"]["secret"]},
        )
        assert response.status_code == 404


class TestRoomMessageHook:
    def test_sending_a_message_notifies_immediately(
        self, live_client, identities, configured, stub_sender
    ):
        """The send path delivers on the leading edge and opens the window."""
        ns, alice, bob = identities["ns"], identities["alice"], identities["bob"]
        alice_headers = {"X-Inbox-Secret": alice["secret"]}
        watcher = notifier.get_watcher()

        room = live_client.post(
            f"/{ns}/rooms", headers=alice_headers, json={"display_name": "twin"}
        ).json()
        live_client.post(
            f"/{ns}/rooms/{room['room_id']}/members",
            headers=alice_headers,
            json={"identity_id": bob["id"]},
        )
        live_client.post(
            f"/{ns}/push/subscriptions",
            headers={"X-Inbox-Secret": bob["secret"]},
            json=_subscribe_body(),
        )

        response = live_client.post(
            f"/{ns}/rooms/{room['room_id']}/messages",
            headers=alice_headers,
            json={"body": "PR is green"},
        )

        assert response.status_code == 200
        assert _wait_until(lambda: len(stub_sender.calls) == 1)
        # The window is open, so a second message would be held.
        assert (room["room_id"], bob["id"]) in watcher.cooldown_keys

    def test_send_succeeds_when_push_is_disabled(
        self, live_client, identities, disabled, stub_sender
    ):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        room = live_client.post(f"/{ns}/rooms", headers=headers, json={"display_name": "r"}).json()

        response = live_client.post(
            f"/{ns}/rooms/{room['room_id']}/messages", headers=headers, json={"body": "hi"}
        )

        assert response.status_code == 200
        assert notifier.get_watcher().pending_keys == set()
        assert stub_sender.calls == []


class TestReadCursorHook:
    def test_advancing_the_cursor_drops_the_coalesced_push(
        self, live_client, identities, configured
    ):
        ns, alice, bob = identities["ns"], identities["alice"], identities["bob"]
        alice_headers = {"X-Inbox-Secret": alice["secret"]}
        bob_headers = {"X-Inbox-Secret": bob["secret"]}

        sender = _StubSender()
        watcher = notifier.UnreadWatcher(sender=sender)
        notifier.set_watcher(watcher)
        try:
            room = live_client.post(
                f"/{ns}/rooms", headers=alice_headers, json={"display_name": "twin"}
            ).json()
            live_client.post(
                f"/{ns}/rooms/{room['room_id']}/members",
                headers=alice_headers,
                json={"identity_id": bob["id"]},
            )
            live_client.post(
                f"/{ns}/push/subscriptions", headers=bob_headers, json=_subscribe_body()
            )

            live_client.post(
                f"/{ns}/rooms/{room['room_id']}/messages",
                headers=alice_headers,
                json={"body": "PR is green"},
            )
            assert _wait_until(lambda: len(sender.calls) == 1)

            # The second message lands inside the window, so it is held for
            # the follow-up push the read cursor is about to cancel.
            message = live_client.post(
                f"/{ns}/rooms/{room['room_id']}/messages",
                headers=alice_headers,
                json={"body": "and merged"},
            ).json()
            assert _wait_until(lambda: (room["room_id"], bob["id"]) in watcher.pending_keys)

            read = live_client.post(
                f"/{ns}/rooms/{room['room_id']}/read",
                headers=bob_headers,
                json={"last_read_mid": message["mid"]},
            )

            assert read.status_code == 200
            assert watcher.pending_keys == set()
            assert len(sender.calls) == 1
        finally:
            notifier.set_watcher(None)


class TestPrefsRoute:
    def test_defaults_to_enabled_with_a_zero_badge(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        body = client.get(f"/{ns}/push/prefs", headers={"X-Inbox-Secret": alice["secret"]}).json()
        assert body == {"enabled": True, "badge": 0}

    def test_switch_round_trips(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}

        put = client.put(f"/{ns}/push/prefs", headers=headers, json={"enabled": False})
        assert put.json() == {"ok": True, "enabled": False}
        assert client.get(f"/{ns}/push/prefs", headers=headers).json()["enabled"] is False

        client.put(f"/{ns}/push/prefs", headers=headers, json={"enabled": True})
        assert client.get(f"/{ns}/push/prefs", headers=headers).json()["enabled"] is True

    def test_switching_off_keeps_the_subscription(self, client, identities):
        ns, alice = identities["ns"], identities["alice"]
        headers = {"X-Inbox-Secret": alice["secret"]}
        client.post(f"/{ns}/push/subscriptions", headers=headers, json=_subscribe_body())

        client.put(f"/{ns}/push/prefs", headers=headers, json={"enabled": False})

        listed = client.get(f"/{ns}/push/subscriptions", headers=headers).json()["subscriptions"]
        assert [s["endpoint"] for s in listed] == [ENDPOINT]

    def test_switch_is_per_identity(self, client, identities):
        ns, alice, bob = identities["ns"], identities["alice"], identities["bob"]
        client.put(
            f"/{ns}/push/prefs",
            headers={"X-Inbox-Secret": alice["secret"]},
            json={"enabled": False},
        )
        bob_prefs = client.get(
            f"/{ns}/push/prefs", headers={"X-Inbox-Secret": bob["secret"]}
        ).json()
        assert bob_prefs["enabled"] is True

    def test_requires_auth(self, client, identities):
        ns = identities["ns"]
        assert client.get(f"/{ns}/push/prefs").status_code == 401
        assert client.put(f"/{ns}/push/prefs", json={"enabled": True}).status_code == 401
        wrong = client.get(f"/{ns}/push/prefs", headers={"X-Inbox-Secret": "wrong"})
        assert wrong.status_code == 403

    def test_badge_counts_unread_room_messages(self, client, identities):
        ns, alice, bob = identities["ns"], identities["alice"], identities["bob"]
        alice_headers = {"X-Inbox-Secret": alice["secret"]}
        room = client.post(
            f"/{ns}/rooms", headers=alice_headers, json={"display_name": "twin"}
        ).json()
        client.post(
            f"/{ns}/rooms/{room['room_id']}/members",
            headers=alice_headers,
            json={"identity_id": bob["id"]},
        )
        for body in ("one", "two"):
            client.post(
                f"/{ns}/rooms/{room['room_id']}/messages",
                headers=alice_headers,
                json={"body": body},
            )

        prefs = client.get(f"/{ns}/push/prefs", headers={"X-Inbox-Secret": bob["secret"]}).json()
        assert prefs["badge"] == 2


class TestSubscribeRouteRegistersAWaiter:
    """A long-poll on /subscribe is what "foreground" means to the watcher."""

    def test_the_poll_route_registers_a_waiter_while_it_waits(
        self, live_client, identities, monkeypatch
    ):
        ns, alice = identities["ns"], identities["alice"]
        observed: list[bool] = []

        class ObservingBus:
            """Records the waiter registry as seen from inside the wait."""

            async def subscribe(self, namespace, topics, timeout=30.0):
                observed.append(notifier.has_open_waiter(namespace, alice["id"]))
                return {}

        monkeypatch.setattr("deadrop.events.get_event_bus", lambda: ObservingBus())

        response = live_client.post(
            f"/{ns}/subscribe",
            headers={"X-Inbox-Secret": alice["secret"]},
            json={"topics": {f"inbox:{alice['id']}": None}, "timeout": 1},
        )

        assert response.status_code == 200
        assert observed == [True]
        # Balanced: the count does not outlive the request.
        assert (ns, alice["id"]) not in notifier._open_waiters

    def test_open_waiter_suppresses_a_pending_room_push(
        self, live_client, identities, configured, stub_sender
    ):
        ns, alice, bob = identities["ns"], identities["alice"], identities["bob"]
        alice_headers = {"X-Inbox-Secret": alice["secret"]}
        bob_headers = {"X-Inbox-Secret": bob["secret"]}

        watcher = notifier.UnreadWatcher(
            sender=stub_sender,
            config=push.PushConfig(
                enabled=True,
                public_key="pub",
                private_key="priv",
                subject="mailto:ops@example.com",
                debounce_seconds=0.05,
            ),
        )
        notifier.set_watcher(watcher)
        try:
            room = live_client.post(
                f"/{ns}/rooms", headers=alice_headers, json={"display_name": "twin"}
            ).json()
            live_client.post(
                f"/{ns}/rooms/{room['room_id']}/members",
                headers=alice_headers,
                json={"identity_id": bob["id"]},
            )
            live_client.post(
                f"/{ns}/push/subscriptions", headers=bob_headers, json=_subscribe_body()
            )

            with notifier.open_waiter(ns, bob["id"]):
                live_client.post(
                    f"/{ns}/rooms/{room['room_id']}/messages",
                    headers=alice_headers,
                    json={"body": "PR is green"},
                )
                assert _wait_until(
                    lambda: (room["room_id"], bob["id"]) not in watcher.cooldown_keys
                )

            assert stub_sender.calls == []
        finally:
            notifier.set_watcher(None)
