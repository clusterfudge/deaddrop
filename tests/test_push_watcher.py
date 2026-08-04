"""Tests for the internal unread watcher.

These run against the real in-memory DB (rooms, members, cursors,
subscriptions) with only the push *sender* stubbed — there is no push
service to talk to. Timers are configured in tens of milliseconds.
"""

import asyncio
import uuid

import pytest
from uuid_extensions import uuid7str

from deadrop import db, notifier, push


def _cfg(debounce=0.05) -> push.PushConfig:
    return push.PushConfig(
        enabled=True,
        public_key="pub",
        private_key="priv",
        subject="mailto:ops@example.com",
        debounce_seconds=debounce,
    )


class RecordingSender:
    """Stands in for push.send_web_push and records what it was asked to send."""

    def __init__(self, gone: bool = False, ok: bool = True):
        self.sent: list[tuple[dict, dict]] = []
        self.gone = gone
        self.ok = ok

    async def __call__(self, subscription, payload, cfg):
        self.sent.append((subscription, payload))
        return push.PushResult(
            endpoint=subscription["endpoint"],
            status_code=410 if self.gone else 201,
            ok=self.ok and not self.gone,
            gone=self.gone,
        )


@pytest.fixture
def room():
    """A namespace with two identities and a room containing both."""
    ns = db.create_namespace(slug="twin")
    alice = db.create_identity(ns["ns"], metadata={"display_name": "Alice"})
    bob = db.create_identity(ns["ns"], metadata={"display_name": "Bob"})
    created = db.create_room(ns["ns"], display_name="twin", created_by=alice["id"])
    db.add_room_member(created["room_id"], bob["id"])
    return {
        "ns": ns["ns"],
        "slug": ns["slug"],
        "room_id": created["room_id"],
        "alice": alice["id"],
        "bob": bob["id"],
    }


def _subscribe(room, identity_id, endpoint="https://push.example.com/sub/1"):
    return db.upsert_push_subscription(
        ns=room["ns"],
        identity_id=identity_id,
        endpoint=endpoint,
        p256dh="p256dh-value",
        auth="auth-value",
    )


def _send(room, sender_id, body="hello"):
    return db.send_room_message(room_id=room["room_id"], from_id=sender_id, body=body)


class TestIsCaughtUp:
    """The three cursor states, kept distinct."""

    def test_absent_cursor_is_unread(self):
        assert notifier.is_caught_up(None, uuid7str()) is False
        assert notifier.is_caught_up("", uuid7str()) is False

    def test_invalid_cursor_is_treated_as_caught_up(self):
        # A UUIDv4 sorts above every v7, so reading it as "never seen"
        # would make the room permanently unread and push forever.
        v4 = str(uuid.uuid4())
        assert notifier.is_caught_up(v4, uuid7str()) is True

    def test_garbage_cursor_is_treated_as_caught_up(self):
        assert notifier.is_caught_up("pending-1717171717", uuid7str()) is True
        assert notifier.is_caught_up("not-a-uuid", uuid7str()) is True

    def test_older_v7_cursor_is_behind(self):
        older = uuid7str()
        newer = uuid7str()
        assert notifier.is_caught_up(older, newer) is False

    def test_equal_or_newer_v7_cursor_is_caught_up(self):
        mid = uuid7str()
        assert notifier.is_caught_up(mid, mid) is True
        later = uuid7str()
        assert notifier.is_caught_up(later, mid) is True


class TestPreview:
    def test_collapses_whitespace(self):
        assert notifier._preview("hello\n\n  world", "text/plain") == "hello world"

    def test_truncates_long_bodies(self):
        out = notifier._preview("x" * 500, "text/plain")
        assert len(out) == notifier._BODY_LIMIT
        assert out.endswith("…")

    def test_empty_body_gets_a_placeholder(self):
        assert notifier._preview("", "text/plain") == "New message"


@pytest.mark.asyncio
class TestWatcherFires:
    async def test_push_sent_after_the_unread_window(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())
        message = _send(room, room["alice"], "PR is green")

        await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"], "twin")
        await asyncio.sleep(0.2)

        assert len(sender.sent) == 1
        subscription, payload = sender.sent[0]
        assert subscription["identity_id"] == room["bob"]
        notification = payload["notification"]
        assert notification["title"] == "Alice in twin"
        assert notification["body"] == "PR is green"
        assert notification["navigate"] == f"/app/twin/room/{room['room_id']}"
        assert notification["tag"] == f"room:{room['room_id']}"

    async def test_sender_does_not_notify_itself(self, room):
        _subscribe(room, room["alice"], "https://push.example.com/sub/alice")
        _subscribe(room, room["bob"], "https://push.example.com/sub/bob")
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())
        message = _send(room, room["alice"])

        await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        await asyncio.sleep(0.2)

        assert [s["identity_id"] for s, _ in sender.sent] == [room["bob"]]

    async def test_every_device_of_a_recipient_is_notified(self, room):
        _subscribe(room, room["bob"], "https://push.example.com/sub/phone")
        _subscribe(room, room["bob"], "https://push.example.com/sub/laptop")
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert len(sender.sent) == 2

    async def test_successful_delivery_records_last_ok_at(self, room):
        _subscribe(room, room["bob"])
        watcher = notifier.UnreadWatcher(sender=RecordingSender(), config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        stored = db.list_push_subscriptions(room["ns"], room["bob"])[0]
        assert stored["last_ok_at"] is not None


@pytest.mark.asyncio
class TestWatcherSuppresses:
    async def test_no_subscriptions_is_a_no_op(self, room):
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert sender.sent == []

    async def test_cursor_advance_cancels_the_pending_push(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.3))
        message = _send(room, room["alice"])

        await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        assert (room["room_id"], room["bob"]) in watcher.pending_keys

        cancelled = watcher.on_read_cursor(room["room_id"], room["bob"], message["mid"])
        await asyncio.sleep(0.5)

        assert cancelled is True
        assert sender.sent == []
        assert watcher.pending_keys == set()

    async def test_stale_cursor_does_not_cancel(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.2))
        older = _send(room, room["alice"], "first")
        newer = _send(room, room["alice"], "second")

        await watcher.on_room_message(room["ns"], room["room_id"], older, room["alice"])
        # Bob read the first message but not the second.
        assert watcher.on_read_cursor(room["room_id"], room["bob"], older["mid"]) is True

        await watcher.on_room_message(room["ns"], room["room_id"], newer, room["alice"])
        db.update_room_read_cursor(room["room_id"], room["bob"], older["mid"])
        await asyncio.sleep(0.4)

        assert len(sender.sent) == 1

    async def test_cursor_written_to_the_db_suppresses_at_fire_time(self, room):
        """The DB re-check catches a read that happened without on_read_cursor."""
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.2))
        message = _send(room, room["alice"])

        await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        db.update_room_read_cursor(room["room_id"], room["bob"], message["mid"])
        await asyncio.sleep(0.4)

        assert sender.sent == []

    async def test_invalid_stored_cursor_is_treated_as_caught_up(self, room):
        """A poisoned v4 cursor must silence push, not spam it."""
        _subscribe(room, room["bob"])
        # Write a UUIDv4 straight into the cursor column, bypassing the
        # API's v7 validation the way legacy clients once did.
        conn = db.get_connection()
        conn.execute(
            "UPDATE room_members SET last_read_mid = ? WHERE room_id = ? AND identity_id = ?",
            (str(uuid.uuid4()), room["room_id"], room["bob"]),
            name="test.poison_cursor",
        )
        conn.commit()

        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert sender.sent == []
        assert watcher.pending_keys == set()

    async def test_reactions_do_not_notify(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())
        original = _send(room, room["bob"], "ship it")
        reaction = db.send_room_message(
            room_id=room["room_id"],
            from_id=room["alice"],
            body="👍",
            content_type="reaction",
            reference_mid=original["mid"],
        )

        task = watcher.on_room_message(room["ns"], room["room_id"], reaction, room["alice"], "twin")
        await asyncio.sleep(0.2)

        assert task is None
        assert sender.sent == []

    async def test_push_disabled_is_a_no_op(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=push.PushConfig(enabled=False))

        task = watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert task is None
        assert sender.sent == []


@pytest.mark.asyncio
class TestDebounce:
    async def test_a_burst_produces_one_push(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.2))

        for i in range(5):
            await watcher.on_room_message(
                room["ns"], room["room_id"], _send(room, room["alice"], f"msg {i}"), room["alice"]
            )
        await asyncio.sleep(0.5)

        assert len(sender.sent) == 1
        assert sender.sent[0][1]["notification"]["body"] == "msg 4 (+4 more)"


@pytest.mark.asyncio
class TestPruning:
    async def test_gone_subscription_is_deleted(self, room):
        _subscribe(room, room["bob"])
        watcher = notifier.UnreadWatcher(sender=RecordingSender(gone=True), config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert db.list_push_subscriptions(room["ns"], room["bob"]) == []


@pytest.mark.asyncio
class TestShutdown:
    async def test_shutdown_cancels_pending_timers(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=5.0))

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        assert watcher.pending_keys

        await watcher.shutdown()

        assert watcher.pending_keys == set()
        assert sender.sent == []


class TestBodyCap:
    def test_preview_caps_at_one_hundred_characters(self):
        # The lock screen is the product surface; 100 is the agreed cap.
        assert notifier._BODY_LIMIT == 100
        assert len(notifier._preview("y" * 400, "text/plain")) == 100


@pytest.mark.asyncio
class TestForegroundSuppression:
    """An attached long-poll waiter means a client will render the message."""

    async def test_open_waiter_suppresses_the_push(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        with notifier.open_waiter(room["ns"], room["bob"]):
            await watcher.on_room_message(
                room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
            )
            await asyncio.sleep(0.2)

        assert sender.sent == []

    async def test_waiter_for_another_identity_does_not_suppress(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        with notifier.open_waiter(room["ns"], room["alice"]):
            await watcher.on_room_message(
                room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
            )
            await asyncio.sleep(0.2)

        assert len(sender.sent) == 1

    async def test_a_just_closed_waiter_still_suppresses(self, room):
        # Poll mode ends the moment anything is published in the namespace,
        # so the message being notified about closes the poll that should
        # have suppressed it. The grace window is what makes the check work
        # for poll clients at all.
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        with notifier.open_waiter(room["ns"], room["bob"]):
            pass
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert sender.sent == []

    async def test_push_resumes_once_the_grace_window_expires(self, room, monkeypatch):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        monkeypatch.setattr(notifier, "_WAITER_GRACE_SECONDS", 0.01)
        with notifier.open_waiter(room["ns"], room["bob"]):
            pass
        await asyncio.sleep(0.05)
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert len(sender.sent) == 1

    async def test_nested_waiters_are_counted(self, room):
        # One identity, two attached clients: the outer close must not
        # un-suppress while the inner one is still waiting.
        with notifier.open_waiter(room["ns"], room["bob"]):
            with notifier.open_waiter(room["ns"], room["bob"]):
                assert notifier.has_open_waiter(room["ns"], room["bob"]) is True
            assert notifier.has_open_waiter(room["ns"], room["bob"]) is True
        assert notifier.has_open_waiter(room["ns"], room["bob"]) is True
        # The count itself is balanced; what remains is the grace window.
        assert (room["ns"], room["bob"]) not in notifier._open_waiters


@pytest.mark.asyncio
class TestIdentityPreference:
    async def test_disabled_identity_gets_no_push(self, room):
        _subscribe(room, room["bob"])
        db.set_push_enabled(room["ns"], room["bob"], False)
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert sender.sent == []
        # The switch is not a subscription delete: the device is still known.
        assert len(db.list_push_subscriptions(room["ns"], room["bob"])) == 1

    async def test_re_enabling_restores_push_without_resubscribing(self, room):
        _subscribe(room, room["bob"])
        db.set_push_enabled(room["ns"], room["bob"], False)
        db.set_push_enabled(room["ns"], room["bob"], True)
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert len(sender.sent) == 1

    async def test_other_identity_switch_is_independent(self, room):
        _subscribe(room, room["bob"])
        db.set_push_enabled(room["ns"], room["alice"], False)
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.2)

        assert len(sender.sent) == 1


@pytest.mark.asyncio
class TestBadge:
    async def test_payload_carries_the_unread_total(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        _send(room, room["alice"], "one")
        _send(room, room["alice"], "two")
        message = _send(room, room["alice"], "three")
        await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        await asyncio.sleep(0.2)

        assert len(sender.sent) == 1
        assert sender.sent[0][1]["notification"]["app_badge"] == 3

    async def test_read_messages_do_not_count_toward_the_badge(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg())

        first = _send(room, room["alice"], "read this one")
        db.update_room_read_cursor(room["room_id"], room["bob"], first["mid"])
        message = _send(room, room["alice"], "but not this one")
        await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        await asyncio.sleep(0.2)

        assert sender.sent[0][1]["notification"]["app_badge"] == 1


class TestBadgeCount:
    """db.count_unread_for_identity is the single definition of the badge."""

    def test_counts_across_every_room(self, room):
        second = db.create_room(room["ns"], display_name="other", created_by=room["alice"])
        db.add_room_member(second["room_id"], room["bob"])
        _send(room, room["alice"], "in twin")
        db.send_room_message(room_id=second["room_id"], from_id=room["alice"], body="in other")

        assert db.count_unread_for_identity(room["ns"], room["bob"]) == 2

    def test_zero_when_caught_up(self, room):
        message = _send(room, room["alice"], "hi")
        db.update_room_read_cursor(room["room_id"], room["bob"], message["mid"])

        assert db.count_unread_for_identity(room["ns"], room["bob"]) == 0

    def test_non_v7_cursor_counts_as_unset(self, room):
        # Matches db.get_room_unread_count: an uncomparable cursor means the
        # room has never been read, so the whole room counts.
        _send(room, room["alice"], "hi")
        db.get_connection().execute(
            "UPDATE room_members SET last_read_mid = ? WHERE room_id = ? AND identity_id = ?",
            (str(uuid.uuid4()), room["room_id"], room["bob"]),
            name="test.poison_cursor",
        )
        db.get_connection().commit()

        assert db.count_unread_for_identity(room["ns"], room["bob"]) == 1

    def test_identity_with_no_rooms_has_no_badge(self, room):
        stranger = db.create_identity(room["ns"], metadata={"display_name": "Nobody"})
        assert db.count_unread_for_identity(room["ns"], stranger["id"]) == 0


class TestPushPrefs:
    def test_absent_row_means_enabled(self, room):
        assert db.get_push_enabled(room["ns"], room["bob"]) is True

    def test_set_and_read_back(self, room):
        db.set_push_enabled(room["ns"], room["bob"], False)
        assert db.get_push_enabled(room["ns"], room["bob"]) is False
        db.set_push_enabled(room["ns"], room["bob"], True)
        assert db.get_push_enabled(room["ns"], room["bob"]) is True
