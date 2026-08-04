"""Unread-message watcher — decides when a message becomes a push.

The rule: a message notifies each recipient immediately, then holds that
recipient's channel closed for a cooldown window. A notification goes out
when the recipient has not read the message, they have push enabled, and
they hold at least one Web Push subscription. An interactive client that
renders the message marks it read, which drops the coalesced follow-up.

Read state is the only staleness signal. An open connection is not one: an
identity routinely holds several idle browser tabs, and none of them imply
the message was seen.

Rooms and direct messages share the throttle, the preference gate and the
payload shape, and differ only in where read state lives:

=========  ================================  =========================
scope      read state                        deep link
=========  ================================  =========================
room       ``room_members.last_read_mid``    ``/app/<slug>/room/<id>``
dm         ``messages.read_at``              ``/app/<slug>/<peer>``
=========  ================================  =========================

A DM is read as a side effect of fetching the inbox, which marks every
message it returns; there is no cursor to compare, so the trigger message
itself is re-read before delivery.

Cursor semantics
----------------
Three room-cursor states, deliberately kept distinct:

===================  ==========================================
cursor               interpretation
===================  ==========================================
absent / empty       never read the room — the message is unread
valid UUIDv7         compare against the message id
present but not v7   unknowable — treat as caught up
===================  ==========================================

The third row is the load-bearing one. A poisoned (non-v7) cursor can
never compare greater than a v7 message id, so reading it as "never seen"
would make the room permanently unread and push on every message forever.
The read paths in ``db.py`` already treat a non-v7 stored cursor as unset
for *counting*; here the same value must mean *suppress*.

Throttle
--------
Leading edge plus a coalesced trailing edge, per (conversation, identity),
where a conversation is a room or a DM peer:

* the first message delivers straight away and opens a
  ``debounce_seconds`` window,
* every message arriving inside that window folds into one follow-up push
  delivered when the window expires, which opens the next window,
* a window that ends quiet sends nothing and closes the throttle, so the
  next message is again immediate.

A chatty room therefore notifies at most once per window, and the reader
hears about the first message the moment it lands.

Suppression
-----------
Two independent reasons not to send, checked at each delivery:

* the recipient has read the trigger message (or it is gone),
* the identity has turned push off (``push_prefs``).

The windows and the coalesced state are in-process. A restart loses
whatever follow-up was pending; the next message delivers immediately.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass

from . import db, instrument, push

logger = logging.getLogger(__name__)

# UUID v7, the only cursor format we can order against message ids.
# api.py holds its own copy for request validation; duplicating two lines
# here keeps this module free of an import cycle back into the app.
_UUID7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)

# Notification bodies are truncated for the lock screen.
_BODY_LIMIT = 100


def is_caught_up(cursor: str | None, mid: str) -> bool:
    """Has the reader already seen ``mid``?

    An invalid cursor answers True: we cannot order it against ``mid``, and
    the safe failure mode for a notification is silence, not a loop.
    """
    if not cursor:
        return False
    if not _UUID7_RE.match(cursor):
        return True
    return cursor >= mid


def _preview(body: str, content_type: str | None) -> str:
    """One-line lock-screen preview of a message body."""
    if content_type and content_type.startswith("image/"):
        return "📎 Attachment"
    text = " ".join((body or "").split())
    if not text:
        return "New message"
    if len(text) > _BODY_LIMIT:
        return text[: _BODY_LIMIT - 1] + "…"
    return text


async def _read(fn, *args):
    """Run a DB read on the read executor, off the event loop."""
    loop = asyncio.get_running_loop()
    call = functools.partial(fn, *args)
    return await loop.run_in_executor(db.get_read_executor(), lambda: db._execute_with_retry(call))


async def _write(fn, *args):
    """Run a DB write on the write executor, off the event loop."""
    loop = asyncio.get_running_loop()
    call = functools.partial(fn, *args)
    return await loop.run_in_executor(db.get_write_executor(), lambda: db._execute_with_retry(call))


@dataclass
class _Notification:
    """One push for a (conversation, identity), covering ``count`` messages."""

    ns: str
    identity_id: str
    kind: str
    """``room`` or ``dm`` — selects the read-state check and the deep link."""
    conv_id: str
    """Room id, or for a DM the peer identity that sent it."""
    trigger_mid: str
    title: str
    preview: str
    count: int = 1

    @property
    def scope(self) -> str:
        """Conversation identifier, used as the throttle key and the tag."""
        return f"{self.kind}:{self.conv_id}"

    @property
    def key(self) -> tuple[str, str]:
        return (self.scope, self.identity_id)

    @property
    def path(self) -> str:
        """Deep-link path below ``/app/<slug>/``."""
        return f"room/{self.conv_id}" if self.kind == "room" else self.conv_id


class UnreadWatcher:
    """Schedules Web Push for room and direct messages that go unread."""

    def __init__(
        self,
        sender=None,
        config: push.PushConfig | None = None,
    ) -> None:
        """
        Args:
            sender: Async ``(subscription, payload, cfg) -> PushResult``.
                Defaults to :func:`deadrop.push.send_web_push`.
            config: Fixed configuration. When omitted the environment is
                re-read on every message so a restart isn't needed to
                change the delay.
        """
        self._sender = sender or push.send_web_push
        self._config = config
        self._pending: dict[tuple[str, str], _Notification] = {}
        self._cooldown: dict[tuple[str, str], asyncio.Task] = {}
        self._tasks: set[asyncio.Task] = set()

    @property
    def sender(self):
        """The delivery callable, so other call sites share the test stub."""
        return self._sender

    @property
    def config(self) -> push.PushConfig:
        return self._config if self._config is not None else push.load_config()

    @property
    def pending_keys(self) -> set[tuple[str, str]]:
        """Keys holding a coalesced follow-up. For tests and diagnostics."""
        return set(self._pending)

    @property
    def cooldown_keys(self) -> set[tuple[str, str]]:
        """Keys inside a cooldown window. For tests and diagnostics."""
        return set(self._cooldown)

    # -- entry points ----------------------------------------------------

    def on_room_message(
        self,
        ns: str,
        room_id: str,
        message: dict,
        sender_id: str,
        room_name: str | None = None,
    ) -> asyncio.Task | None:
        """Notify every recipient of a room message, subject to the throttle.

        Reactions are skipped: they carry no text and arrive in bursts.

        Returns the fan-out task (tests await it); ``None`` when push is
        disabled, which is the default.
        """
        cfg = self.config
        if not cfg.configured:
            return None
        if message.get("content_type") == "reaction":
            return None

        task = asyncio.create_task(self._fan_out(ns, room_id, message, sender_id, room_name, cfg))
        self._track(task)
        return task

    def on_direct_message(self, ns: str, message: dict, sender_id: str) -> asyncio.Task | None:
        """Notify the recipient of a 1:1 message, subject to the throttle.

        ``message`` carries ``mid``, ``to``, ``body`` and ``content_type``.

        Returns the delivery task (tests await it); ``None`` when push is
        disabled, which is the default.
        """
        cfg = self.config
        if not cfg.configured:
            return None
        if message.get("content_type") == "reaction":
            return None

        task = asyncio.create_task(self._fan_out_dm(ns, message, sender_id, cfg))
        self._track(task)
        return task

    def on_read_cursor(self, room_id: str, identity_id: str, cursor: str | None) -> bool:
        """Drop a coalesced follow-up when its reader has caught up.

        The cooldown window itself keeps running: the reader has already
        been notified once, so the next message still respects the hold.

        Returns True if a follow-up was dropped.
        """
        key = (f"room:{room_id}", identity_id)
        held = self._pending.get(key)
        if held is None:
            return False
        if not is_caught_up(cursor, held.trigger_mid):
            return False
        self._pending.pop(key, None)
        instrument.sink.counter("push.cancelled")
        return True

    def on_inbox_read(self, identity_id: str, mids: Iterable[str]) -> int:
        """Drop coalesced DM follow-ups whose trigger message was just read.

        A DM has no cursor to compare against: the inbox fetch marks the
        rows it returns, so the mids it marked are what cancels. The
        cooldown window keeps running, as it does for a room.

        Returns the number of follow-ups dropped.
        """
        read = set(mids)
        if not read:
            return 0
        dropped = 0
        for key, held in list(self._pending.items()):
            if key[1] != identity_id or held.kind != "dm":
                continue
            if held.trigger_mid not in read:
                continue
            self._pending.pop(key, None)
            instrument.sink.counter("push.cancelled")
            dropped += 1
        return dropped

    async def shutdown(self) -> None:
        """Cancel every in-flight window and fan-out."""
        self._pending.clear()
        for task in list(self._cooldown.values()):
            task.cancel()
        self._cooldown.clear()
        pending = [t for t in self._tasks if not t.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tasks.clear()

    # -- internals -------------------------------------------------------

    def _track(self, task: asyncio.Task) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _fan_out(
        self,
        ns: str,
        room_id: str,
        message: dict,
        sender_id: str,
        room_name: str | None,
        cfg: push.PushConfig,
    ) -> None:
        mid = message.get("mid")
        if not mid:
            return
        try:
            members = await _read(db.list_room_members, room_id)
        except Exception:
            logger.warning("push fan-out could not list members of %s", room_id, exc_info=True)
            return

        sender_label = sender_id
        for member in members:
            if member["identity_id"] == sender_id:
                sender_label = member.get("metadata", {}).get("display_name") or sender_id
                break

        preview = _preview(message.get("body", ""), message.get("content_type"))
        label = room_name or "Deadrop"

        for member in members:
            identity_id = member["identity_id"]
            if identity_id == sender_id:
                continue
            if is_caught_up(member.get("last_read_mid"), mid):
                # Cursor is already past this message (or unusable) — the
                # recipient is not behind, so nothing to notify about.
                continue
            self._notify(
                _Notification(
                    ns=ns,
                    identity_id=identity_id,
                    kind="room",
                    conv_id=room_id,
                    trigger_mid=mid,
                    title=f"{sender_label} in {label}",
                    preview=preview,
                ),
                cfg,
            )

    async def _fan_out_dm(
        self,
        ns: str,
        message: dict,
        sender_id: str,
        cfg: push.PushConfig,
    ) -> None:
        mid = message.get("mid")
        to_id = message.get("to")
        if not mid or not to_id or to_id == sender_id:
            return

        sender_label = sender_id
        try:
            identity = await _read(db.get_identity, ns, sender_id)
        except Exception:
            logger.warning("push fan-out could not read identity %s", sender_id, exc_info=True)
            identity = None
        if identity:
            sender_label = identity.get("metadata", {}).get("display_name") or sender_id

        self._notify(
            _Notification(
                ns=ns,
                identity_id=to_id,
                kind="dm",
                conv_id=sender_id,
                trigger_mid=mid,
                title=sender_label,
                preview=_preview(message.get("body", ""), message.get("content_type")),
            ),
            cfg,
        )

    def _notify(self, notification: _Notification, cfg: push.PushConfig) -> None:
        key = notification.key
        if key not in self._cooldown:
            task = asyncio.create_task(self._send_then_hold(key, notification, cfg))
            self._cooldown[key] = task
            self._track(task)
            return

        # Inside the window: fold into the single follow-up sent when it
        # expires, describing the newest message and how many it covers.
        held = self._pending.get(key)
        if held is not None:
            notification.count = held.count + 1
        self._pending[key] = notification
        instrument.sink.counter("push.throttled")

    async def _send_then_hold(
        self, key: tuple[str, str], notification: _Notification, cfg: push.PushConfig
    ) -> None:
        """Deliver now, then keep the window open while messages coalesce."""
        try:
            await self._deliver(notification, cfg)
            while True:
                await asyncio.sleep(cfg.debounce_seconds)
                held = self._pending.pop(key, None)
                if held is None:
                    return
                await self._deliver(held, cfg)
        finally:
            if self._cooldown.get(key) is asyncio.current_task():
                del self._cooldown[key]
            self._pending.pop(key, None)

    async def _deliver(self, notification: _Notification, cfg: push.PushConfig) -> None:
        try:
            await self._fire(notification, cfg)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning(
                "push delivery failed for scope=%s identity=%s",
                notification.scope,
                notification.identity_id,
                exc_info=True,
            )

    async def _already_read(self, note: _Notification) -> bool:
        """Has the recipient seen the trigger message, or can't we tell?

        A room compares the member's cursor; a DM re-reads the row, whose
        ``read_at`` the inbox fetch sets. A message or membership that has
        gone away answers True: there is nothing left to point at.
        """
        if note.kind == "dm":
            message = await _read(db.get_message, note.ns, note.identity_id, note.trigger_mid)
            return message is None or message.get("read_at") is not None
        member = await _read(db.get_room_member_info, note.conv_id, note.identity_id)
        if member is None:
            return True
        return is_caught_up(member.get("last_read_mid"), note.trigger_mid)

    async def _fire(self, note: _Notification, cfg: push.PushConfig) -> None:
        if await self._already_read(note):
            instrument.sink.counter("push.suppressed.read")
            return

        if not await _read(db.get_push_enabled, note.ns, note.identity_id):
            instrument.sink.counter("push.suppressed.disabled")
            return

        subscriptions = await _read(db.list_push_subscriptions, note.ns, note.identity_id)
        if not subscriptions:
            return

        slug = await self._namespace_slug(note.ns)
        badge = await self._badge(note.ns, note.identity_id)
        payload = push.build_payload(
            title=note.title,
            body=self._body(note),
            navigate=f"/app/{slug}/{note.path}",
            tag=note.scope,
            badge=badge,
        )

        results = await asyncio.gather(
            *(self._sender(sub, payload, cfg) for sub in subscriptions),
            return_exceptions=True,
        )

        delivered = 0
        for result in results:
            if isinstance(result, BaseException):
                logger.warning("push sender raised", exc_info=result)
                continue
            if result.gone:
                instrument.sink.counter("push.pruned")
                await _write(db.delete_push_subscription, result.endpoint)
            elif result.ok:
                delivered += 1
                await _write(db.touch_push_subscription, result.endpoint)

        if delivered:
            instrument.sink.counter("push.sent", delivered)

    def _body(self, note: _Notification) -> str:
        if note.count > 1:
            return f"{note.preview} (+{note.count - 1} more)"
        return note.preview

    async def _badge(self, ns: str, identity_id: str) -> int | None:
        """Unread total for the app icon, or None if it can't be computed.

        A failure here must not cost the notification, so the badge is
        dropped rather than raised.
        """
        try:
            return await _read(db.count_unread_for_identity, ns, identity_id)
        except Exception:
            logger.warning("badge count failed for %s/%s", ns, identity_id, exc_info=True)
            return None

    async def _namespace_slug(self, ns: str) -> str:
        """Namespace slug for the deep link, falling back to the raw ns id."""
        try:
            namespace = await _read(db.get_namespace, ns)
        except Exception:
            return ns
        if namespace:
            return namespace.get("slug") or ns
        return ns


# --- Global singleton ---

_watcher: UnreadWatcher | None = None


def get_watcher() -> UnreadWatcher:
    """Get (or lazily create) the process-wide watcher."""
    global _watcher
    if _watcher is None:
        _watcher = UnreadWatcher()
    return _watcher


def set_watcher(watcher: UnreadWatcher | None) -> None:
    """Replace the process-wide watcher (tests)."""
    global _watcher
    _watcher = watcher


async def shutdown_watcher() -> None:
    """Cancel pending work and drop the singleton."""
    global _watcher
    if _watcher is not None:
        await _watcher.shutdown()
        _watcher = None
