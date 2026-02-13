"""Tests for the event bus system."""

import asyncio

import pytest

from deadrop.events import InMemoryEventBus, get_event_bus, reset_event_bus, set_event_bus


@pytest.fixture
def bus():
    """Create a fresh InMemoryEventBus for each test."""
    return InMemoryEventBus()


@pytest.fixture(autouse=True)
def _reset_global_bus():
    """Reset the global event bus between tests."""
    reset_event_bus()
    yield
    reset_event_bus()


class TestPublishAndSubscribe:
    """Tests for basic publish/subscribe behavior."""

    @pytest.mark.asyncio
    async def test_publish_then_subscribe_returns_immediately(self, bus):
        """If a topic has changes, subscribe returns without blocking."""
        await bus.publish("ns1", "room:abc", "01961234-0000-7000-8000-000000000001")

        result = await bus.subscribe(
            "ns1",
            {"room:abc": None},
            timeout=5.0,
        )

        assert result == {"room:abc": "01961234-0000-7000-8000-000000000001"}

    @pytest.mark.asyncio
    async def test_subscribe_with_current_cursor_blocks_then_receives(self, bus):
        """Subscribe with up-to-date cursor blocks, then unblocks on publish."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        mid2 = "01961234-0000-7000-8000-000000000002"

        await bus.publish("ns1", "room:abc", mid1)

        async def delayed_publish():
            await asyncio.sleep(0.1)
            await bus.publish("ns1", "room:abc", mid2)

        task = asyncio.create_task(delayed_publish())
        result = await bus.subscribe(
            "ns1",
            {"room:abc": mid1},
            timeout=5.0,
        )
        await task

        assert result == {"room:abc": mid2}

    @pytest.mark.asyncio
    async def test_subscribe_timeout_returns_empty(self, bus):
        """Subscribe with no activity returns empty dict on timeout."""
        result = await bus.subscribe(
            "ns1",
            {"room:abc": None},
            timeout=0.1,
        )

        assert result == {}

    @pytest.mark.asyncio
    async def test_subscribe_zero_timeout_returns_immediately(self, bus):
        """Subscribe with timeout=0 checks and returns without waiting."""
        result = await bus.subscribe(
            "ns1",
            {"room:abc": None},
            timeout=0,
        )
        assert result == {}

    @pytest.mark.asyncio
    async def test_subscribe_zero_timeout_with_changes(self, bus):
        """Subscribe with timeout=0 returns changes if they exist."""
        await bus.publish("ns1", "room:abc", "01961234-0000-7000-8000-000000000001")

        result = await bus.subscribe(
            "ns1",
            {"room:abc": None},
            timeout=0,
        )
        assert result == {"room:abc": "01961234-0000-7000-8000-000000000001"}

    @pytest.mark.asyncio
    async def test_subscribe_multiple_topics_one_changed(self, bus):
        """Subscribe to multiple topics; only the changed one is returned."""
        mid1 = "01961234-0000-7000-8000-000000000001"

        await bus.publish("ns1", "room:abc", mid1)

        result = await bus.subscribe(
            "ns1",
            {
                "room:abc": None,
                "room:def": None,
                "inbox:xyz": None,
            },
            timeout=0,
        )

        assert result == {"room:abc": mid1}

    @pytest.mark.asyncio
    async def test_subscribe_multiple_topics_multiple_changed(self, bus):
        """Multiple topics with changes are all returned."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        mid2 = "01961234-0000-7000-8000-000000000002"

        await bus.publish("ns1", "room:abc", mid1)
        await bus.publish("ns1", "inbox:xyz", mid2)

        result = await bus.subscribe(
            "ns1",
            {
                "room:abc": None,
                "inbox:xyz": None,
                "room:def": None,
            },
            timeout=0,
        )

        assert result == {"room:abc": mid1, "inbox:xyz": mid2}

    @pytest.mark.asyncio
    async def test_subscribe_no_change_when_cursor_matches(self, bus):
        """No changes when cursor matches latest."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        await bus.publish("ns1", "room:abc", mid1)

        result = await bus.subscribe(
            "ns1",
            {"room:abc": mid1},
            timeout=0,
        )

        assert result == {}


class TestNamespaceIsolation:
    """Tests that namespaces are isolated from each other."""

    @pytest.mark.asyncio
    async def test_publish_in_one_namespace_not_visible_in_another(self, bus):
        """Publishing in ns1 doesn't affect subscribers in ns2."""
        await bus.publish("ns1", "room:abc", "01961234-0000-7000-8000-000000000001")

        result = await bus.subscribe(
            "ns2",
            {"room:abc": None},
            timeout=0,
        )

        assert result == {}

    @pytest.mark.asyncio
    async def test_publish_wakes_only_same_namespace_subscribers(self, bus):
        """Publishing wakes subscribers in the same namespace only."""
        mid = "01961234-0000-7000-8000-000000000001"

        ns1_result = None
        ns2_result = None

        async def subscribe_ns1():
            nonlocal ns1_result
            ns1_result = await bus.subscribe("ns1", {"room:abc": None}, timeout=0.5)

        async def subscribe_ns2():
            nonlocal ns2_result
            ns2_result = await bus.subscribe("ns2", {"room:abc": None}, timeout=0.2)

        async def publish_ns1():
            await asyncio.sleep(0.05)
            await bus.publish("ns1", "room:abc", mid)

        await asyncio.gather(subscribe_ns1(), subscribe_ns2(), publish_ns1())

        assert ns1_result == {"room:abc": mid}
        assert ns2_result == {}


class TestConcurrentSubscribers:
    """Tests for multiple concurrent subscribers."""

    @pytest.mark.asyncio
    async def test_multiple_subscribers_all_notified(self, bus):
        """Multiple subscribers on the same topic all get notified."""
        mid = "01961234-0000-7000-8000-000000000001"

        results = []

        async def subscriber(idx):
            result = await bus.subscribe("ns1", {"room:abc": None}, timeout=2.0)
            results.append((idx, result))

        async def publisher():
            await asyncio.sleep(0.1)
            await bus.publish("ns1", "room:abc", mid)

        await asyncio.gather(
            subscriber(1),
            subscriber(2),
            subscriber(3),
            publisher(),
        )

        assert len(results) == 3
        for idx, result in results:
            assert result == {"room:abc": mid}, f"Subscriber {idx} got wrong result"

    @pytest.mark.asyncio
    async def test_subscribers_different_topics_in_same_namespace(self, bus):
        """Subscribers to different topics in the same namespace."""
        mid = "01961234-0000-7000-8000-000000000001"

        room_result = None
        inbox_result = None

        async def room_subscriber():
            nonlocal room_result
            room_result = await bus.subscribe("ns1", {"room:abc": None}, timeout=0.5)

        async def inbox_subscriber():
            nonlocal inbox_result
            inbox_result = await bus.subscribe("ns1", {"inbox:xyz": None}, timeout=0.3)

        async def publisher():
            await asyncio.sleep(0.05)
            await bus.publish("ns1", "room:abc", mid)

        await asyncio.gather(room_subscriber(), inbox_subscriber(), publisher())

        assert room_result == {"room:abc": mid}
        assert inbox_result == {}


class TestPublishUpdatesLatest:
    """Tests that publish correctly updates the latest mid."""

    @pytest.mark.asyncio
    async def test_latest_mid_updates_on_publish(self, bus):
        """Each publish updates the latest mid for the topic."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        mid2 = "01961234-0000-7000-8000-000000000002"

        await bus.publish("ns1", "room:abc", mid1)
        assert bus.get_latest("ns1", "room:abc") == mid1

        await bus.publish("ns1", "room:abc", mid2)
        assert bus.get_latest("ns1", "room:abc") == mid2

    @pytest.mark.asyncio
    async def test_get_latest_nonexistent(self, bus):
        """get_latest returns None for unknown topics."""
        assert bus.get_latest("ns1", "room:abc") is None
        assert bus.get_latest("unknown_ns", "room:abc") is None

    @pytest.mark.asyncio
    async def test_publish_creates_topic(self, bus):
        """First publish on a topic creates it."""
        mid = "01961234-0000-7000-8000-000000000001"
        assert bus.get_latest("ns1", "room:new") is None

        await bus.publish("ns1", "room:new", mid)
        assert bus.get_latest("ns1", "room:new") == mid


class TestStream:
    """Tests for the SSE-style streaming interface."""

    @pytest.mark.asyncio
    async def test_stream_yields_existing_changes(self, bus):
        """Stream immediately yields changes for topics with unseen messages."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        await bus.publish("ns1", "room:abc", mid1)

        stream = bus.stream("ns1", {"room:abc": None})
        event = await asyncio.wait_for(stream.__anext__(), timeout=1.0)

        assert event == {"topic": "room:abc", "latest_mid": mid1}

    @pytest.mark.asyncio
    async def test_stream_waits_for_new_events(self, bus):
        """Stream waits and yields when new events arrive."""
        mid1 = "01961234-0000-7000-8000-000000000001"

        async def delayed_publish():
            await asyncio.sleep(0.1)
            await bus.publish("ns1", "room:abc", mid1)

        publish_task = asyncio.create_task(delayed_publish())

        stream = bus.stream("ns1", {"room:abc": None})
        event = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
        await publish_task

        assert event == {"topic": "room:abc", "latest_mid": mid1}

    @pytest.mark.asyncio
    async def test_stream_yields_multiple_events(self, bus):
        """Stream yields multiple events as they occur."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        mid2 = "01961234-0000-7000-8000-000000000002"

        async def publish_sequence():
            await asyncio.sleep(0.05)
            await bus.publish("ns1", "room:abc", mid1)
            await asyncio.sleep(0.05)
            await bus.publish("ns1", "inbox:xyz", mid2)

        publish_task = asyncio.create_task(publish_sequence())

        events = []
        stream = bus.stream("ns1", {"room:abc": None, "inbox:xyz": None})

        for _ in range(2):
            event = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
            events.append(event)

        await publish_task

        topics = {e["topic"] for e in events}
        assert "room:abc" in topics
        assert "inbox:xyz" in topics

    @pytest.mark.asyncio
    async def test_stream_does_not_repeat_same_change(self, bus):
        """Stream doesn't re-yield a change after cursor is advanced."""
        mid1 = "01961234-0000-7000-8000-000000000001"
        mid2 = "01961234-0000-7000-8000-000000000002"

        await bus.publish("ns1", "room:abc", mid1)

        async def publish_later():
            await asyncio.sleep(0.1)
            await bus.publish("ns1", "room:abc", mid2)

        publish_task = asyncio.create_task(publish_later())

        stream = bus.stream("ns1", {"room:abc": None})

        event1 = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
        assert event1["latest_mid"] == mid1

        event2 = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
        assert event2["latest_mid"] == mid2

        await publish_task


class TestGlobalSingleton:
    """Tests for the global event bus singleton."""

    def test_get_event_bus_returns_instance(self):
        """get_event_bus creates an InMemoryEventBus."""
        bus = get_event_bus()
        assert isinstance(bus, InMemoryEventBus)

    def test_get_event_bus_returns_same_instance(self):
        """get_event_bus returns the same instance on repeated calls."""
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    def test_set_event_bus_replaces_global(self):
        """set_event_bus replaces the global instance."""
        original = get_event_bus()
        new_bus = InMemoryEventBus()
        set_event_bus(new_bus)
        assert get_event_bus() is new_bus
        assert get_event_bus() is not original

    def test_reset_event_bus_clears_global(self):
        """reset_event_bus clears the global so next get creates fresh."""
        bus1 = get_event_bus()
        reset_event_bus()
        bus2 = get_event_bus()
        assert bus1 is not bus2
