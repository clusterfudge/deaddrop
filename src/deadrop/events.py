"""Event bus for subscription/notification system.

Provides a pub/sub mechanism for notifying clients when topics (inboxes, rooms)
have new messages. Clients subscribe with a vector clock (map of topic -> last_seen_mid)
and receive events when any subscribed topic has changes.

Architecture:
    - EventBus ABC defines the interface (swappable for Redis later)
    - InMemoryEventBus uses asyncio primitives for single-instance deployments
    - Events are lightweight notifications (topic + latest_mid), not payloads
    - Clients fetch actual content via existing REST endpoints

Topic key format:
    - "inbox:{identity_id}" for direct message inboxes
    - "room:{room_id}" for chat rooms
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import AsyncIterator

logger = logging.getLogger(__name__)


class EventBus(ABC):
    """Abstract event bus for topic change notifications.

    Implementations must be async-compatible. The interface is designed
    to be backed by Redis pub/sub later without changing callers.
    """

    @abstractmethod
    async def publish(self, namespace: str, topic: str, mid: str) -> None:
        """Publish that a topic has a new message.

        Args:
            namespace: Namespace ID
            topic: Topic key (e.g., "inbox:abc123" or "room:def456")
            mid: The new message ID (UUIDv7, lexicographically sortable)
        """

    @abstractmethod
    async def subscribe(
        self,
        namespace: str,
        topics: dict[str, str | None],
        timeout: float = 30.0,
    ) -> dict[str, str]:
        """Block until any subscribed topic has changes, or timeout.

        Compares the caller's last_seen_mid for each topic against the
        server's latest_mid. Returns immediately if any topic has unseen
        messages; otherwise waits for a publish event or timeout.

        Args:
            namespace: Namespace ID
            topics: Map of topic_key -> last_seen_mid (None = never seen)
            timeout: Max seconds to wait (0 = check and return immediately)

        Returns:
            Map of topic_key -> latest_mid for topics that have changes.
            Empty dict if timeout reached with no changes.
        """

    @abstractmethod
    async def stream(
        self,
        namespace: str,
        topics: dict[str, str | None],
    ) -> AsyncIterator[dict[str, str]]:
        """Stream events as they occur.

        Yields dicts of {topic_key: latest_mid} for each change.
        First yields any immediately-available changes, then waits.

        Args:
            namespace: Namespace ID
            topics: Map of topic_key -> last_seen_mid (None = never seen)

        Yields:
            Single-entry dicts: {"topic": topic_key, "latest_mid": mid}
        """
        # Make this an async generator at the ABC level
        yield {}  # pragma: no cover

    @abstractmethod
    def get_latest(self, namespace: str, topic: str) -> str | None:
        """Get the latest known mid for a topic.

        Args:
            namespace: Namespace ID
            topic: Topic key

        Returns:
            Latest message ID, or None if no messages published for this topic.
        """


class InMemoryEventBus(EventBus):
    """In-memory event bus using asyncio primitives.

    Suitable for single-instance deployments. Uses asyncio.Condition
    for efficient waiter notification (no busy-polling).

    Thread safety: all operations go through asyncio, which is single-threaded
    within an event loop. The Condition provides synchronization for concurrent
    coroutines.
    """

    def __init__(self) -> None:
        # latest_mid per (namespace, topic)
        self._latest: dict[str, dict[str, str]] = defaultdict(dict)
        # One condition per namespace for waiter notification
        self._conditions: dict[str, asyncio.Condition] = {}

    def _get_condition(self, namespace: str) -> asyncio.Condition:
        """Get or create a Condition for a namespace."""
        if namespace not in self._conditions:
            self._conditions[namespace] = asyncio.Condition()
        return self._conditions[namespace]

    async def publish(self, namespace: str, topic: str, mid: str) -> None:
        """Publish a new message event for a topic."""
        condition = self._get_condition(namespace)
        async with condition:
            self._latest[namespace][topic] = mid
            condition.notify_all()

    def _check_changes(
        self,
        namespace: str,
        topics: dict[str, str | None],
    ) -> dict[str, str]:
        """Check which topics have changes beyond the caller's cursors.

        UUIDv7 message IDs are lexicographically sortable, so string
        comparison is valid for determining "newer than".
        """
        changes: dict[str, str] = {}
        ns_latest = self._latest.get(namespace, {})

        for topic, last_seen in topics.items():
            latest = ns_latest.get(topic)
            if latest is None:
                # No messages published for this topic yet
                continue
            if last_seen is None:
                # Caller has never seen this topic — any message is new
                changes[topic] = latest
            elif latest > last_seen:
                # There are messages newer than what the caller has seen
                changes[topic] = latest

        return changes

    async def subscribe(
        self,
        namespace: str,
        topics: dict[str, str | None],
        timeout: float = 30.0,
    ) -> dict[str, str]:
        """Block until any topic has changes, or timeout."""
        # Immediate check — avoid acquiring condition if possible
        changes = self._check_changes(namespace, topics)
        if changes:
            return changes

        if timeout <= 0:
            return {}

        condition = self._get_condition(namespace)
        async with condition:
            # Re-check under the lock (another publish may have happened)
            changes = self._check_changes(namespace, topics)
            if changes:
                return changes

            # Wait for notification or timeout
            try:
                await asyncio.wait_for(
                    condition.wait(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                pass

            # Check again after wake-up
            return self._check_changes(namespace, topics)

    async def stream(
        self,
        namespace: str,
        topics: dict[str, str | None],
    ) -> AsyncIterator[dict[str, str]]:
        """Stream events as they occur."""
        # Track our own cursor so we don't re-yield the same change
        cursors = dict(topics)

        # First, yield any immediately-available changes
        changes = self._check_changes(namespace, cursors)
        for topic, mid in changes.items():
            cursors[topic] = mid
            yield {"topic": topic, "latest_mid": mid}

        # Then wait for new events
        condition = self._get_condition(namespace)
        while True:
            async with condition:
                await condition.wait()

            # Check what changed
            changes = self._check_changes(namespace, cursors)
            for topic, mid in changes.items():
                cursors[topic] = mid
                yield {"topic": topic, "latest_mid": mid}

    def get_latest(self, namespace: str, topic: str) -> str | None:
        """Get the latest known mid for a topic."""
        return self._latest.get(namespace, {}).get(topic)


# --- Global singleton ---

_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance.

    Creates an InMemoryEventBus on first call. Use set_event_bus()
    to swap in a different implementation (e.g., for testing or Redis).
    """
    global _event_bus
    if _event_bus is None:
        _event_bus = InMemoryEventBus()
    return _event_bus


def set_event_bus(bus: EventBus) -> None:
    """Replace the global event bus instance.

    Useful for testing or swapping to a Redis-backed implementation.
    """
    global _event_bus
    _event_bus = bus


def reset_event_bus() -> None:
    """Reset the global event bus (for testing)."""
    global _event_bus
    _event_bus = None
