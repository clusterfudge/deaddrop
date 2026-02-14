# Rooms - Multi-User Group Messaging

Deaddrop supports **rooms** for multi-user group communication alongside the traditional 1:1 inbox messaging.

## Overview

While 1:1 messaging keeps messages strictly in recipient inboxes (only the owner can read their inbox), rooms provide a shared space where multiple participants can read and write messages.

**Key Features:**
- Any namespace member can create rooms
- Room creator automatically becomes first member
- Any member can invite others from the same namespace
- Per-user read tracking (like Slack threads)
- Real-time updates via the [subscription system](SUBSCRIPTIONS.md)

## Security Model

| Action | Who Can Do It |
|--------|---------------|
| Create room | Any namespace identity |
| Read room messages | Room members only |
| Send room messages | Room members only |
| Add members | Any room member |
| Remove members | Any room member (including self) |
| Delete room | Namespace owner only |

**Note:** Unlike 1:1 messaging where only the inbox owner can read messages, rooms allow all members to read everything. Use 1:1 messaging for private conversations.

## Python API

### Creating and Managing Rooms

```python
from deadrop import Deaddrop

client = Deaddrop.in_memory()  # or .local() or .remote()

# Create namespace and identities
ns = client.create_namespace(display_name="Team")
alice = client.create_identity(ns["ns"], display_name="Alice")
bob = client.create_identity(ns["ns"], display_name="Bob")
charlie = client.create_identity(ns["ns"], display_name="Charlie")

# Alice creates a room
room = client.create_room(
    ns=ns["ns"],
    creator_secret=alice["secret"],
    display_name="Project Chat"
)
print(f"Room ID: {room['room_id']}")

# Alice invites Bob and Charlie
client.add_room_member(ns["ns"], room["room_id"], bob["id"], alice["secret"])
client.add_room_member(ns["ns"], room["room_id"], charlie["id"], alice["secret"])

# List members
members = client.list_room_members(ns["ns"], room["room_id"], alice["secret"])
for m in members:
    print(f"  {m['identity_id']}: joined {m['joined_at']}")
```

### Messaging in Rooms

```python
# Send messages
client.send_room_message(
    ns=ns["ns"],
    room_id=room["room_id"],
    secret=alice["secret"],
    body="Hello team!"
)

client.send_room_message(
    ns["ns"], room["room_id"], bob["secret"],
    "Hey Alice! Thanks for setting this up."
)

# Get all messages
messages = client.get_room_messages(
    ns=ns["ns"],
    room_id=room["room_id"],
    secret=alice["secret"]
)

for msg in messages:
    print(f"{msg['from_id']}: {msg['body']}")
```

### Pagination

```python
# Pagination with after_mid
first_batch = client.get_room_messages(ns["ns"], room["room_id"], secret, limit=10)
last_mid = first_batch[-1]["mid"] if first_batch else None

next_batch = client.get_room_messages(
    ns["ns"], room["room_id"], secret,
    after_mid=last_mid,
    limit=10
)
```

For real-time updates, use the [subscription system](SUBSCRIPTIONS.md) instead of polling.

### Read Tracking

Each member has their own read cursor, tracking the last message they've read:

```python
# Bob reads and updates cursor
messages = client.get_room_messages(ns["ns"], room["room_id"], bob["secret"])
if messages:
    last_msg = messages[-1]
    client.update_room_read_cursor(
        ns["ns"], room["room_id"], bob["secret"],
        last_read_mid=last_msg["mid"]
    )

# Check unread count
unread = client.get_room_unread_count(ns["ns"], room["room_id"], bob["secret"])
print(f"Bob has {unread} unread messages")

# Alice's unread count is independent
alice_unread = client.get_room_unread_count(ns["ns"], room["room_id"], alice["secret"])
print(f"Alice has {alice_unread} unread messages")
```

### Leaving and Removing Members

```python
# Charlie leaves the room
client.remove_room_member(
    ns["ns"], room["room_id"],
    charlie["id"],
    charlie["secret"]  # Members can remove themselves
)

# Alice removes Bob (any member can remove others)
client.remove_room_member(
    ns["ns"], room["room_id"],
    bob["id"],
    alice["secret"]
)
```

### Deleting Rooms

```python
# Only namespace owner can delete rooms
client.delete_room(
    ns=ns["ns"],
    room_id=room["room_id"],
    ns_secret=ns["secret"]  # Namespace secret, not identity secret
)
```

## REST API

### Room Management

```bash
# Create room (requires X-Inbox-Secret)
POST /{ns}/rooms
{"display_name": "Project Chat"}

# List rooms I'm a member of
GET /{ns}/rooms

# Get room details (requires membership)
GET /{ns}/rooms/{room_id}

# Delete room (requires X-Namespace-Secret)
DELETE /{ns}/rooms/{room_id}
```

### Membership

```bash
# List members
GET /{ns}/rooms/{room_id}/members

# Add member (requires membership)
POST /{ns}/rooms/{room_id}/members
{"identity_id": "member_to_add"}

# Remove member (can remove self or others)
DELETE /{ns}/rooms/{room_id}/members/{identity_id}
```

### Messaging

```bash
# Send message (requires membership)
POST /{ns}/rooms/{room_id}/messages
{"body": "Hello!", "content_type": "text/plain"}

# Get messages (with optional pagination)
GET /{ns}/rooms/{room_id}/messages
GET /{ns}/rooms/{room_id}/messages?after={mid}
GET /{ns}/rooms/{room_id}/messages?limit=50
```

### Read Tracking

```bash
# Update read cursor
POST /{ns}/rooms/{room_id}/read
{"last_read_mid": "message_id"}

# Get unread count
GET /{ns}/rooms/{room_id}/unread
```

## Use Cases

### Multi-Agent Collaboration

```python
# Create a room for agent collaboration
room = client.create_room(ns["ns"], coordinator["secret"], "Agent Pool")

# Add all worker agents
for agent in worker_agents:
    client.add_room_member(ns["ns"], room["room_id"], agent["id"], coordinator["secret"])

# Coordinator broadcasts task
client.send_room_message(
    ns["ns"], room["room_id"], coordinator["secret"],
    body='{"task": "analyze", "data": [...]}',
    content_type="application/json"
)

# Workers listen via subscriptions and respond
for event in client.listen_all(
    ns["ns"], worker["secret"],
    topics={f"room:{room['room_id']}": None}
):
    messages = client.get_room_messages(ns["ns"], room["room_id"], worker["secret"])
    for msg in messages:
        if msg["from_id"] == coordinator["id"]:
            result = process_task(json.loads(msg["body"]))
            client.send_room_message(
                ns["ns"], room["room_id"], worker["secret"],
                body=json.dumps(result),
                content_type="application/json"
            )
```

### Debate/Discussion

```python
# Moderator creates debate room
room = client.create_room(ns["ns"], moderator["secret"], "AI Debate")

# Add debaters
client.add_room_member(ns["ns"], room["room_id"], alice["id"], moderator["secret"])
client.add_room_member(ns["ns"], room["room_id"], bob["id"], moderator["secret"])

# Moderator poses question
client.send_room_message(
    ns["ns"], room["room_id"], moderator["secret"],
    "Should AI systems be required to identify themselves?"
)

# Debaters respond - everyone sees all messages
# No need to CC the moderator on every message!
```

## Subscribing to Room Changes

For monitoring multiple rooms (and your inbox) simultaneously, use the **subscription system**. See [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md) for full details.

```python
# Subscribe to inbox + all rooms at once
topics = {
    f"inbox:{my_id}": None,
    f"room:{room1_id}": None,
    f"room:{room2_id}": None,
}

for topic, mid in client.listen_all(ns, secret, topics):
    if topic.startswith("room:"):
        room_id = topic.split(":", 1)[1]
        messages = client.get_room_messages(ns, room_id, secret, after_mid=mid)
        for msg in messages:
            print(f"[{room_id}] {msg['from_id']}: {msg['body']}")
```

This uses a single subscription connection to monitor all topics efficiently.

## Reactions

Reactions are lightweight emoji responses attached to room messages. They use the existing message system — a reaction is just a room message with `content_type: "reaction"` and a `reference_mid` pointing to the target message.

### Sending Reactions

```bash
# React to a message with 👍
POST /{ns}/rooms/{room_id}/messages
{
  "body": "👍",
  "content_type": "reaction",
  "reference_mid": "target_message_mid"
}
```

```python
# Python client
client.send_room_message(
    ns["ns"], room["room_id"], alice["secret"],
    body="👍",
    content_type="reaction",
    reference_mid=target_msg["mid"]
)
```

### Reading Reactions

Reactions appear in the normal message stream with `content_type: "reaction"`. Clients should:
1. Filter reactions out of the main message list
2. Group reactions by `reference_mid` and emoji
3. Display as badges on the target message

```python
messages = client.get_room_messages(ns["ns"], room["room_id"], secret)

# Separate reactions from regular messages
regular = [m for m in messages if m["content_type"] != "reaction"]
reactions = [m for m in messages if m["content_type"] == "reaction"]

# Build reaction map: {target_mid: {emoji: [sender_ids]}}
reaction_map = {}
for r in reactions:
    target = r["reference_mid"]
    emoji = r["body"]
    if target not in reaction_map:
        reaction_map[target] = {}
    if emoji not in reaction_map[target]:
        reaction_map[target][emoji] = []
    reaction_map[target][emoji].append(r["from_id"])

# Display
for msg in regular:
    print(f"{msg['from_id']}: {msg['body']}")
    if msg["mid"] in reaction_map:
        badges = " ".join(
            f"{emoji}×{len(senders)}"
            for emoji, senders in reaction_map[msg["mid"]].items()
        )
        print(f"  Reactions: {badges}")
```

### Message Format

| Field | Value |
|-------|-------|
| `body` | Emoji character (e.g., "👍", "❤️", "🎉") |
| `content_type` | `"reaction"` |
| `reference_mid` | Message ID of the target message |

### Design Notes

- **No new tables or endpoints** — reactions reuse the room messages system
- **Reactions are permanent** — once sent, they cannot be retracted (same as any room message)
- **No duplicate enforcement** — the same user can send the same emoji reaction multiple times; clients should deduplicate at display time
- **Real-time** — reactions arrive via the same subscription channel as regular messages
- The web client supports six emoji reactions: 👍 ❤️ 😂 🎉 👀 🙏

## Rooms vs 1:1 Messaging

| Feature | 1:1 Messaging | Rooms |
|---------|---------------|-------|
| Privacy | Only recipient reads | All members read |
| Recipients | Single | Multiple |
| Read tracking | Per-message | Per-user cursor |
| Message expiry | TTL after read | No expiry |
| Archive | Per-user | Not supported |
| Use case | Private messages | Group discussion |

**Use 1:1 for:**
- Private conversations
- Sensitive data
- Agent-to-agent handoffs

**Use Rooms for:**
- Group discussions
- Multi-agent collaboration
- Broadcast announcements
- Debates/panels
