"""Multi-client stream fanout tests for InMemoryEventBus.

These tests exercise the "multiple clients, same user" scenario: when a
user has several active sessions (desktop tab + mobile, or two desktop
tabs), every session has an open SSE stream consuming from the event bus.
All streams must receive every publish — if even one misses an event,
that session's view goes stale until the next publish.

The test class is specifically hunting two failure modes:

1. **Race between yield and re-waiting**: A stream yields an event,
   control returns to the caller (SSE framer), control comes back to the
   stream, and only THEN does the generator re-enter `condition.wait()`.
   If a `publish()` + `notify_all()` lands in that gap, the generator
   misses the wake-up because it isn't on the condition's waiter queue
   yet. A cursor re-check before each `wait()` closes this hole.

2. **Missed wakeup when publish races the first wait()**: After the
   initial `_check_changes` in `stream()`, the generator enters
   `condition.wait()`. If a publish happens between those two steps,
   the notify_all is lost and the stream blocks until the next publish.
"""

from __future__ import annotations

import asyncio

import pytest

from deadrop.events import InMemoryEventBus


def _mid(i: int) -> str:
    return f"01961234-0000-7000-8000-{i:012d}"


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


class TestMultiClientStream:
    """Fanout tests: every stream consumer must see every publish."""

    @pytest.mark.asyncio
    async def test_two_streams_both_see_rapid_publishes(self, bus):
        """
        Two concurrent streams on the same topic. Publish N messages
        back-to-back. Both streams must eventually observe the final
        mid — coalescing of intermediate events is acceptable (the event
        bus is a "latest mid" signal, not a durable queue), but losing
        the tail means a client's UI is permanently stale.

        This is the "desktop + mobile both connected" case.
        """
        N = 10
        topic = "room:multi"
        final_mid = _mid(N)

        async def consume_until(stream, target):
            last = None
            while last != target:
                evt = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
                last = evt["latest_mid"]
            return last

        stream_a = bus.stream("ns1", {topic: None})
        stream_b = bus.stream("ns1", {topic: None})

        async def publisher():
            # Small delay so both streams are parked in condition.wait()
            await asyncio.sleep(0.05)
            for i in range(1, N + 1):
                await bus.publish("ns1", topic, _mid(i))
                # No sleep between publishes — maximize the race.

        task_a = asyncio.create_task(consume_until(stream_a, final_mid))
        task_b = asyncio.create_task(consume_until(stream_b, final_mid))
        pub_task = asyncio.create_task(publisher())

        await pub_task

        last_a = await asyncio.wait_for(task_a, timeout=3.0)
        last_b = await asyncio.wait_for(task_b, timeout=3.0)

        assert last_a == final_mid, f"Stream A never observed final mid. Got {last_a}"
        assert last_b == final_mid, f"Stream B never observed final mid. Got {last_b}"

    @pytest.mark.asyncio
    async def test_stream_sees_publish_that_races_first_wait(self, bus):
        """
        Publish happens in the gap between stream's initial
        `_check_changes` and its first `condition.wait()`. The publish
        must be delivered, not swallowed.

        We simulate the race by publishing immediately after creating
        the stream iterator but before pulling from it.
        """
        topic = "room:race"

        stream = bus.stream("ns1", {topic: None})

        # Drive the stream just far enough to do its initial
        # _check_changes (which finds nothing — topic is empty) but not
        # far enough to be sitting in condition.wait(). We emulate that
        # by publishing *before* calling __anext__, and requiring that
        # the first __anext__ resolves without timing out.
        await bus.publish("ns1", topic, _mid(1))

        evt = await asyncio.wait_for(stream.__anext__(), timeout=1.0)
        assert evt["latest_mid"] == _mid(1)

    @pytest.mark.asyncio
    async def test_second_stream_joining_late_still_gets_events(self, bus):
        """
        Stream A is already consuming. Stream B joins after one publish
        has happened. Subsequent publishes must reach both streams.
        """
        topic = "room:late"

        stream_a = bus.stream("ns1", {topic: None})

        await bus.publish("ns1", topic, _mid(1))
        first_a = await asyncio.wait_for(stream_a.__anext__(), timeout=1.0)
        assert first_a["latest_mid"] == _mid(1)

        # Stream B joins with cursor at mid(1) — should not re-see mid(1)
        stream_b = bus.stream("ns1", {topic: _mid(1)})

        async def publisher():
            await asyncio.sleep(0.05)
            await bus.publish("ns1", topic, _mid(2))

        pub_task = asyncio.create_task(publisher())

        evt_a = await asyncio.wait_for(stream_a.__anext__(), timeout=2.0)
        evt_b = await asyncio.wait_for(stream_b.__anext__(), timeout=2.0)

        await pub_task

        assert evt_a["latest_mid"] == _mid(2)
        assert evt_b["latest_mid"] == _mid(2)

    @pytest.mark.asyncio
    async def test_publish_during_yield_not_lost(self, bus):
        """
        Between a stream's `yield` and its next `condition.wait()`, a
        publish arrives. The stream must still see it.

        We force the ordering by:
          1. Publishing mid(1).
          2. Pulling from the stream — this yields mid(1) and (in the
             buggy version) loops back to `wait()` without re-checking.
          3. Publishing mid(2) synchronously (no await sleep between
             steps 2 and 3 — we stay on the same task boundary).
          4. Pulling again — must get mid(2) within a short timeout.

        The bug: step 3's notify_all fires while the generator is
        scheduled but not yet back in wait(), so the notification is
        lost. Step 4 then blocks until a timeout.
        """
        topic = "room:yield-race"

        stream = bus.stream("ns1", {topic: None})

        # First event
        await bus.publish("ns1", topic, _mid(1))
        evt1 = await asyncio.wait_for(stream.__anext__(), timeout=1.0)
        assert evt1["latest_mid"] == _mid(1)

        # Second publish — the generator has yielded but not necessarily
        # resumed wait(). Give the event loop many chances to schedule
        # the generator, then publish while it's in its "between-yields"
        # state. A cursor re-check before wait() guarantees delivery.
        for _ in range(5):
            await asyncio.sleep(0)  # yield to event loop

        await bus.publish("ns1", topic, _mid(2))

        evt2 = await asyncio.wait_for(stream.__anext__(), timeout=1.0)
        assert evt2["latest_mid"] == _mid(2)

    @pytest.mark.asyncio
    async def test_stress_two_streams_100_publishes(self, bus):
        """
        Stress test: two streams, 100 rapid publishes. Both streams must
        end with the final mid. This is the closest synthetic analog to
        "desktop tab + mobile both open, active conversation."
        """
        N = 100
        topic = "room:stress"

        stream_a = bus.stream("ns1", {topic: None})
        stream_b = bus.stream("ns1", {topic: None})

        async def consume_until_final(stream):
            last = None
            while last != _mid(N):
                evt = await asyncio.wait_for(stream.__anext__(), timeout=2.0)
                last = evt["latest_mid"]
            return last

        async def publisher():
            await asyncio.sleep(0.02)
            for i in range(1, N + 1):
                await bus.publish("ns1", topic, _mid(i))

        task_a = asyncio.create_task(consume_until_final(stream_a))
        task_b = asyncio.create_task(consume_until_final(stream_b))
        pub_task = asyncio.create_task(publisher())

        await pub_task
        final_a = await asyncio.wait_for(task_a, timeout=5.0)
        final_b = await asyncio.wait_for(task_b, timeout=5.0)

        assert final_a == _mid(N)
        assert final_b == _mid(N)
