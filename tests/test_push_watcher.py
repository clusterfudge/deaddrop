"""Tests for the internal unread watcher.

These run against the real in-memory DB (rooms, members, cursors,
subscriptions) with only the push *sender* stubbed — there is no push
service to talk to. Cooldown windows are configured in tens of
milliseconds.
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

    async def test_cursor_advance_cancels_the_follow_up(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))
        first = _send(room, room["alice"], "first")
        second = _send(room, room["alice"], "second")

        await watcher.on_room_message(room["ns"], room["room_id"], first, room["alice"])
        await asyncio.sleep(0.1)
        await watcher.on_room_message(room["ns"], room["room_id"], second, room["alice"])
        assert (room["room_id"], room["bob"]) in watcher.pending_keys

        cancelled = watcher.on_read_cursor(room["room_id"], room["bob"], second["mid"])
        await asyncio.sleep(0.7)

        assert cancelled is True
        assert len(sender.sent) == 1  # the leading push only
        assert watcher.pending_keys == set()

    async def test_stale_cursor_does_not_cancel_the_follow_up(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))
        older = _send(room, room["alice"], "first")
        newer = _send(room, room["alice"], "second")

        await watcher.on_room_message(room["ns"], room["room_id"], older, room["alice"])
        await asyncio.sleep(0.1)
        assert len(sender.sent) == 1
        await watcher.on_room_message(room["ns"], room["room_id"], newer, room["alice"])
        # Bob read the first message but not the second.
        assert watcher.on_read_cursor(room["room_id"], room["bob"], older["mid"]) is False
        db.update_room_read_cursor(room["room_id"], room["bob"], older["mid"])
        await asyncio.sleep(0.7)

        assert len(sender.sent) == 2

    async def test_cursor_written_to_the_db_suppresses_at_fire_time(self, room):
        """The DB re-check catches a read that happened without on_read_cursor."""
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))
        first = _send(room, room["alice"], "one")
        second = _send(room, room["alice"], "two")

        await watcher.on_room_message(room["ns"], room["room_id"], first, room["alice"])
        await asyncio.sleep(0.1)
        await watcher.on_room_message(room["ns"], room["room_id"], second, room["alice"])
        db.update_room_read_cursor(room["room_id"], room["bob"], second["mid"])
        await asyncio.sleep(0.7)

        assert len(sender.sent) == 1  # the leading push only

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
class TestThrottle:
    """Leading edge, then a cooldown that coalesces whatever arrives in it."""

    async def test_first_message_pushes_immediately(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=5.0))

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "PR is green"), room["alice"]
        )
        await asyncio.sleep(0.1)

        assert len(sender.sent) == 1
        assert sender.sent[0][1]["notification"]["body"] == "PR is green"

    async def test_cooldown_suppresses_an_immediate_second_push(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=5.0))

        # Written up front: a send on this thread races the watcher's reads.
        messages = [_send(room, room["alice"], body) for body in ("one", "two")]

        for message in messages:
            await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        await asyncio.sleep(0.1)

        assert len(sender.sent) == 1
        assert (room["room_id"], room["bob"]) in watcher.pending_keys

    async def test_burst_lands_as_one_follow_up_when_the_window_expires(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))

        messages = [_send(room, room["alice"], f"msg {i}") for i in range(5)]

        for message in messages:
            await watcher.on_room_message(room["ns"], room["room_id"], message, room["alice"])
        await asyncio.sleep(0.1)
        assert len(sender.sent) == 1
        assert sender.sent[0][1]["notification"]["body"] == "msg 0"

        await asyncio.sleep(0.7)

        assert len(sender.sent) == 2
        assert sender.sent[1][1]["notification"]["body"] == "msg 4 (+3 more)"

    async def test_a_reaction_in_the_window_does_not_inflate_the_count(self, room):
        # A thumbs-up is not a message the follow-up should claim to cover.
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))

        first = _send(room, room["alice"], "msg 0")
        await watcher.on_room_message(room["ns"], room["room_id"], first, room["alice"])
        await asyncio.sleep(0.1)

        for emoji in ("\U0001f44d", "\U0001f680", "\u2764\ufe0f"):
            reaction = db.send_room_message(
                room_id=room["room_id"],
                from_id=room["alice"],
                body=emoji,
                content_type="reaction",
                reference_mid=first["mid"],
            )
            # Returns None (not a task): reactions never enter the throttle.
            assert (
                watcher.on_room_message(room["ns"], room["room_id"], reaction, room["alice"])
                is None
            )
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "msg 1"), room["alice"]
        )
        await asyncio.sleep(0.7)

        assert len(sender.sent) == 2
        assert sender.sent[1][1]["notification"]["body"] == "msg 1"

    async def test_a_window_of_only_reactions_sends_no_follow_up(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.2))

        first = _send(room, room["alice"], "msg 0")
        await watcher.on_room_message(room["ns"], room["room_id"], first, room["alice"])
        await asyncio.sleep(0.05)
        reaction = db.send_room_message(
            room_id=room["room_id"],
            from_id=room["alice"],
            body="\U0001f44d",
            content_type="reaction",
            reference_mid=first["mid"],
        )
        assert watcher.on_room_message(room["ns"], room["room_id"], reaction, room["alice"]) is None
        await asyncio.sleep(0.4)

        assert len(sender.sent) == 1

    async def test_quiet_window_sends_no_follow_up(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.1))

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"]), room["alice"]
        )
        await asyncio.sleep(0.7)

        assert len(sender.sent) == 1
        assert watcher.pending_keys == set()
        assert watcher.cooldown_keys == set()

    async def test_the_follow_up_opens_a_fresh_window(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))

        first, second, third = (_send(room, room["alice"], b) for b in ("one", "two", "three"))

        await watcher.on_room_message(room["ns"], room["room_id"], first, room["alice"])
        await watcher.on_room_message(room["ns"], room["room_id"], second, room["alice"])
        await asyncio.sleep(0.7)
        assert len(sender.sent) == 2  # leading + follow-up

        await watcher.on_room_message(room["ns"], room["room_id"], third, room["alice"])
        await asyncio.sleep(0.1)

        assert len(sender.sent) == 2  # still held by the follow-up's window

    async def test_the_cooldown_is_per_identity(self, room):
        carol = db.create_identity(room["ns"], metadata={"display_name": "Carol"})
        _subscribe(room, room["bob"], "https://push.example.com/sub/bob")
        _subscribe(room, carol["id"], "https://push.example.com/sub/carol")
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=5.0))

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "one"), room["alice"]
        )
        await asyncio.sleep(0.1)
        db.add_room_member(room["room_id"], carol["id"])
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "two"), room["alice"]
        )
        await asyncio.sleep(0.1)

        # Bob's window holds his second message; Carol's first is unthrottled.
        assert [s["identity_id"] for s, _ in sender.sent] == [room["bob"], carol["id"]]

    async def test_suppression_still_applies_to_the_follow_up(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=0.5))

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "one"), room["alice"]
        )
        await asyncio.sleep(0.1)
        db.set_push_enabled(room["ns"], room["bob"], False)
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "two"), room["alice"]
        )
        await asyncio.sleep(0.7)

        assert len(sender.sent) == 1


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
    async def test_shutdown_drops_the_pending_follow_up(self, room):
        _subscribe(room, room["bob"])
        sender = RecordingSender()
        watcher = notifier.UnreadWatcher(sender=sender, config=_cfg(debounce=5.0))

        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "one"), room["alice"]
        )
        await asyncio.sleep(0.05)
        await watcher.on_room_message(
            room["ns"], room["room_id"], _send(room, room["alice"], "two"), room["alice"]
        )
        assert watcher.pending_keys

        await watcher.shutdown()

        assert watcher.pending_keys == set()
        assert watcher.cooldown_keys == set()
        assert len(sender.sent) == 1


class TestBodyCap:
    def test_preview_caps_at_one_hundred_characters(self):
        # The lock screen is the product surface; 100 is the agreed cap.
        assert notifier._BODY_LIMIT == 100
        assert len(notifier._preview("y" * 400, "text/plain")) == 100


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
