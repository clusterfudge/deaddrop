# Subscriptions

Deadrop supports a **subscription system** that lets clients efficiently monitor multiple topics (inboxes and rooms) for new messages through a single connection, rather than making separate long-poll requests per topic.

## Concepts

### Vector Clock

Clients subscribe by providing a **vector clock** — a map of topic keys to the last message ID they've seen on that topic. The server compares this against its own state and reports which topics have new activity.

```json
{
    "inbox:fa3b2109": "01961234-0000-7000-8000-000000000001",
    "room:abc123":    "01961235-0000-7000-8000-000000000042",
    "room:def456":    null
}
```

- Each key is a **topic** (`inbox:{identity_id}` or `room:{room_id}`)
- Each value is the **last seen message ID** (`null` = never seen, notify on any activity)
- UUIDv7 message IDs are lexicographically sortable, so `mid > last_seen` is a valid "has changes" check

### Events, Not Payloads

The subscription system returns **events** (which topics changed), not message contents. Clients are responsible for:

1. Receiving the event notification
2. Fetching content from the changed topic via existing REST endpoints (using the cursor)
3. Updating their local cursor with the latest message ID from the fetch

This keeps the subscription system simple and avoids duplicating auth checks for message content.

### Topic Keys

| Format | Description | Access Rule |
|--------|-------------|-------------|
| `inbox:{identity_id}` | Direct message inbox | Only the inbox owner |
| `room:{room_id}` | Chat room | Any room member |

## API Reference

### `POST /{ns}/subscribe`

Subscribe to topic changes within a namespace.

**Auth**: `X-Inbox-Secret` header required. Must be a valid identity in the namespace.

#### Request Body

```json
{
    "topics": {
        "inbox:fa3b2109": "01961234-0000-7000-8000-000000000001",
        "room:abc123": null
    },
    "mode": "poll",
    "timeout": 30
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `topics` | `object` | *required* | Map of topic_key → last_seen_mid (null = never seen) |
| `mode` | `string` | `"poll"` | `"poll"` or `"stream"` |
| `timeout` | `integer` | `30` | Seconds to wait (1-60, poll mode only) |

#### Poll Mode Response

Blocks until any topic has new messages or timeout is reached.

```json
{
    "events": {
        "room:abc123": "01961299-0000-7000-8000-000000000099"
    },
    "timeout": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `events` | `object` | Map of changed topic_key → latest_mid |
| `timeout` | `boolean` | `true` if no events before timeout |

#### Stream Mode (SSE)

Returns a `text/event-stream` response for continuous Server-Sent Events:

```
event: connected
data: {}

event: change
data: {"topic": "room:abc123", "latest_mid": "01961299-0000-7000-8000-000000000099"}

event: change
data: {"topic": "inbox:fa3b2109", "latest_mid": "01961300-0000-7000-8000-000000000100"}
```

Events:
- `connected` — Initial event confirming the stream is active
- `change` — A topic has new messages

#### Error Responses

| Status | Reason |
|--------|--------|
| 400 | Invalid topic format, unknown topic type, or empty topics |
| 401 | Missing `X-Inbox-Secret` header |
| 403 | Invalid secret, subscribing to another identity's inbox, or not a room member |
| 404 | Room not found in this namespace |

## Client Usage

### Python

#### Poll Mode

```python
from deadrop import Deaddrop

client = Deaddrop.remote(url="https://deaddrop.example.com")

# Subscribe to inbox + rooms
result = client.subscribe(
    ns=ns_id,
    secret=my_secret,
    topics={
        f"inbox:{my_id}": last_inbox_mid,  # or None if starting fresh
        f"room:{room_id}": last_room_mid,
    },
    timeout=30,
)

if not result["timeout"]:
    for topic, mid in result["events"].items():
        print(f"New activity on {topic} (latest: {mid})")
```

#### listen_all() — Continuous Monitoring

```python
# Monitor multiple topics with automatic cursor tracking
topics = {
    f"inbox:{my_id}": None,
    f"room:{room1_id}": None,
    f"room:{room2_id}": None,
}

for topic, mid in client.listen_all(ns, secret, topics):
    if topic.startswith("inbox:"):
        messages = client.get_inbox(ns, my_id, secret, after_mid=mid)
        for msg in messages:
            print(f"DM from {msg['from']}: {msg['body']}")
    elif topic.startswith("room:"):
        room_id = topic.split(":", 1)[1]
        messages = client.get_room_messages(ns, room_id, secret, after_mid=mid)
        for msg in messages:
            print(f"[{room_id}] {msg['from_id']}: {msg['body']}")
```

#### Streaming Mode

```python
for event in client.subscribe_stream(ns, secret, topics):
    print(f"Change on {event['topic']}: {event['latest_mid']}")
```

### JavaScript (Web Client)

The web client includes a `SubscriptionManager` class that handles SSE streaming with automatic reconnection:

```javascript
const manager = new SubscriptionManager(credentials);

manager.onEvent = (topic, latestMid) => {
    console.log(`New activity on ${topic}`);
    // Fetch content from the changed topic
};

manager.onStatusChange = (status) => {
    console.log(`Connection: ${status}`);  // connecting, connected, polling, reconnecting, disconnected
};

// Build topics and start
const topics = manager.buildTopics(roomIds, /* includeInbox */ true);
manager.start(topics);

// Later: stop
manager.stop();
```

The manager:
- Tries SSE first, falls back to poll mode
- Reconnects automatically with exponential backoff
- Tracks cursors in `localStorage`
- Pauses when `stop()` is called

### CLI

```bash
# Listen to inbox + all rooms
deadrop listen <namespace>

# Listen to inbox only
deadrop listen <namespace> --inbox

# Listen to rooms only
deadrop listen <namespace> --rooms

# JSON output for piping
deadrop listen <namespace> --json-output

# Specify identity
deadrop listen <namespace> --identity-id <id>
```

Output:
```
Subscribing to: inbox:fa3b2109, room:abc123, room:def456
Waiting for events... (Ctrl+C to stop)

[room:abc12345] alice123: Hello everyone!
[inbox] bob98765: Hey there, got a question
```

## Reconnection & Cursor Management

### Best Practices

1. **Always track cursors**: Store the latest message ID for each topic after every fetch
2. **Use cursors on reconnect**: When the subscription connection drops, reconnect with your current cursors to avoid missing messages
3. **Fetch with cursors**: When fetching content after an event, pass the `after` parameter to only get new messages
4. **Handle stale cursors**: If a cursor is very old, the server will still correctly report that topic has changes

### Reconnection Flow

```
1. Connect with initial cursors (null for fresh start)
2. Receive event: topic X has new messages
3. Fetch topic X content (with after=cursor)
4. Update cursor for topic X
5. Connection drops
6. Reconnect with updated cursors
7. Server immediately reports any changes since last cursor
```

## Architecture

### Event Bus

The subscription system uses an **event bus** abstraction:

```
EventBus (ABC)
└── InMemoryEventBus  (current: asyncio.Condition-based)
└── RedisEventBus     (future: Redis pub/sub)
```

The in-memory implementation is suitable for single-instance deployments. The interface is designed so a Redis-backed implementation can be swapped in later without changing any callers.

### How Events Flow

```
Client sends message
    → API handler (send_message / send_room_message)
        → db.send_message() / db.send_room_message()
        → event_bus.publish(ns, topic, mid)
            → Notify all waiting subscribers

Subscriber waiting on subscribe()
    → event_bus wakes subscriber
    → Returns changed topics with latest mids
    → Client fetches content via existing endpoints
```

### Performance

- **O(1)** for publish (update latest mid, notify condition)
- **O(topics)** for subscribe check (compare each topic's cursor)
- **No busy-polling**: uses `asyncio.Condition` for efficient waiting
- Replaces N separate long-poll connections with 1 subscription connection
