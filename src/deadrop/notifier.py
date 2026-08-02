"""Unread-message watcher — decides when a room message becomes a push.

The rule: a room message arms a timer per recipient. If that recipient's
read cursor has not advanced past the message when the timer expires, and
they hold at least one Web Push subscription, they get a notification.
An interactive client that renders the message advances the cursor, which
disarms the timer.

Cursor semantics
----------------
Three cursor states, deliberately kept distinct:

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

Storm control
-------------
At most one push per (room, identity) per cooldown window regardless of
message volume. A burst re-uses the timer armed by the first message
rather than pushing the deadline out, so a chatty room notifies once at
``unread_seconds`` after the burst started, not once per message and not
never.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
import time
from dataclasses import dataclass, field

from . import db, instrument, push

logger = logging.getLogger(__name__)

# UUID v7, the only cursor format we can order against message ids.
# api.py holds its own copy for request validation; duplicating two lines
# here keeps this module free of an import cycle back into the app.
_UUID7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)

# Notification bodies are truncated for the lock screen.
_BODY_LIMIT = 140


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
class _Armed:
    """A pending notification for one (room, identity)."""

    ns: str
    room_id: str
    identity_id: str
    trigger_mid: str
    room_name: str
    sender_label: str
    preview: str
    count: int = 1
    task: asyncio.Task | None = field(default=None, repr=False)


class UnreadWatcher:
    """Schedules Web Push for room messages that go unread."""

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
        self._armed: dict[tuple[str, str], _Armed] = {}
        self._last_push: dict[tuple[str, str], float] = {}
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
        """Keys with an armed timer. Exposed for tests and diagnostics."""
        return set(self._armed)

    # -- entry points ----------------------------------------------------

    def on_room_message(
        self,
        ns: str,
        room_id: str,
        message: dict,
        sender_id: str,
        room_name: str | None = None,
    ) -> asyncio.Task | None:
        """Arm notification timers for every recipient of a room message.

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

    def on_read_cursor(self, room_id: str, identity_id: str, cursor: str | None) -> bool:
        """Disarm a pending notification when its reader has caught up.

        Returns True if a timer was cancelled.
        """
        key = (room_id, identity_id)
        armed = self._armed.get(key)
        if armed is None:
            return False
        if not is_caught_up(cursor, armed.trigger_mid):
            return False
        self._armed.pop(key, None)
        if armed.task is not None:
            armed.task.cancel()
        instrument.sink.counter("push.cancelled")
        return True

    async def shutdown(self) -> None:
        """Cancel every in-flight timer and fan-out."""
        for armed in list(self._armed.values()):
            if armed.task is not None:
                armed.task.cancel()
        self._armed.clear()
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
            self._arm(
                _Armed(
                    ns=ns,
                    room_id=room_id,
                    identity_id=identity_id,
                    trigger_mid=mid,
                    room_name=label,
                    sender_label=sender_label,
                    preview=preview,
                ),
                cfg,
            )

    def _arm(self, armed: _Armed, cfg: push.PushConfig) -> None:
        key = (armed.room_id, armed.identity_id)
        existing = self._armed.get(key)
        if existing is not None:
            # A timer is already counting down for this reader. Refresh the
            # preview so the notification describes the newest message, but
            # leave the deadline alone: a chatty room must still notify.
            existing.count += 1
            existing.preview = armed.preview
            existing.sender_label = armed.sender_label
            return

        self._armed[key] = armed
        task = asyncio.create_task(self._wait_and_fire(key, cfg))
        armed.task = task
        self._track(task)
        instrument.sink.counter("push.armed")

    async def _wait_and_fire(self, key: tuple[str, str], cfg: push.PushConfig) -> None:
        try:
            await asyncio.sleep(cfg.unread_seconds)
        except asyncio.CancelledError:
            return

        armed = self._armed.pop(key, None)
        if armed is None:
            return

        try:
            await self._fire(armed, cfg)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning(
                "push delivery failed for room=%s identity=%s",
                armed.room_id,
                armed.identity_id,
                exc_info=True,
            )

    async def _fire(self, armed: _Armed, cfg: push.PushConfig) -> None:
        key = (armed.room_id, armed.identity_id)

        member = await _read(db.get_room_member_info, armed.room_id, armed.identity_id)
        if member is None:
            return
        if is_caught_up(member.get("last_read_mid"), armed.trigger_mid):
            instrument.sink.counter("push.suppressed.read")
            return

        now = time.monotonic()
        last = self._last_push.get(key)
        if last is not None and now - last < cfg.cooldown_seconds:
            instrument.sink.counter("push.suppressed.cooldown")
            return

        subscriptions = await _read(db.list_push_subscriptions, armed.ns, armed.identity_id)
        if not subscriptions:
            return

        slug = await self._room_slug(armed.ns)
        payload = push.build_payload(
            title=f"{armed.sender_label} in {armed.room_name}",
            body=self._body(armed),
            navigate=f"/app/{slug}/room/{armed.room_id}",
            tag=f"room:{armed.room_id}",
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
            self._last_push[key] = now
            instrument.sink.counter("push.sent", delivered)
            self._sweep(cfg)

    def _body(self, armed: _Armed) -> str:
        if armed.count > 1:
            return f"{armed.preview} (+{armed.count - 1} more)"
        return armed.preview

    async def _room_slug(self, ns: str) -> str:
        """Namespace slug for the deep link, falling back to the raw ns id."""
        try:
            namespace = await _read(db.get_namespace, ns)
        except Exception:
            return ns
        if namespace:
            return namespace.get("slug") or ns
        return ns

    def _sweep(self, cfg: push.PushConfig) -> None:
        """Drop cooldown entries that can no longer suppress anything."""
        horizon = time.monotonic() - (cfg.cooldown_seconds * 2)
        for key in [k for k, ts in self._last_push.items() if ts < horizon]:
            self._last_push.pop(key, None)


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
