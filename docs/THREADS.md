# Threads

Deadrop rooms support Slack-style flat threads: any top-level message can become the root of a thread, and replies are a flat chronological list under that root.

## Model

A thread reply is a regular `room_messages` row with `reference_mid` pointing to the thread root. Replies always point to a top-level message — there is no nesting.

```
Main timeline:
  msg-A: "Let's plan the release"        ← top-level (reference_mid = NULL)
  msg-F: "Deploy schedule?"              ← top-level (reference_mid = NULL)

Thread on msg-A:
  msg-B: "I'll handle the API"           ← reply (reference_mid = msg-A)
  msg-C: "What about migration?"         ← reply (reference_mid = msg-A)
  msg-D: "Schema looks complex"          ← reply (reference_mid = msg-A)
```

Reactions continue to use `reference_mid` with `content_type="reaction"`. The distinction is:
- **Reply**: `reference_mid` is set, `content_type` is NOT `"reaction"`
- **Reaction**: `reference_mid` is set, `content_type` IS `"reaction"`
- **Top-level message**: `reference_mid` is NULL

## Schema

No new columns. The existing `reference_mid` column (added in migration 003) and `reference_mid` index handle everything.

Server-side validation ensures replies point to top-level messages only. If `reference_mid` targets a reply (a message that itself has `reference_mid` set and isn't a reaction), the server redirects it to the root — following Slack's behavior where all replies are flat under the root.

## API

### Sending a reply

Same endpoint, set `reference_mid`:

```
POST /{ns}/rooms/{room_id}/messages
{
  "body": "I agree with this",
  "reference_mid": "<root_mid>"
}
```

### Getting a thread

```
GET /{ns}/rooms/{room_id}/threads/{root_mid}
→ {
    "root": { ...message... },
    "replies": [ ...messages ordered by created_at... ],
    "reply_count": 3
  }
```

### Room messages (main timeline)

By default, `GET /{ns}/rooms/{room_id}/messages` returns all messages including replies (for backward compatibility). Pass `?include_replies=false` to get only top-level messages with thread metadata:

```json
{
  "mid": "...",
  "body": "Let's plan the release",
  "reply_count": 3,
  "last_reply_at": "2025-01-15T10:30:00Z",
  "is_thread_reply": false,
  ...
}
```

To get only top-level messages with thread metadata, pass `?include_replies=false`. The web UI uses this by default to show a clean timeline.

### Response fields

Messages include:
- `is_thread_reply` (bool): true if this message is a reply in a thread
- `reply_count` (int): number of replies (only on top-level messages, 0 if no thread)
- `last_reply_at` (str | null): timestamp of most recent reply

## Python client

```python
# Send a reply
client.send_room_message(ns, room_id, secret, body, reference_mid=root_mid)

# Get a thread
client.get_thread(ns, room_id, secret, root_mid)

# Get all room messages (default, backward-compatible)
client.get_room_messages(ns, room_id, secret)

# Get top-level only, with thread metadata (reply_count, last_reply_at)
client.get_room_messages(ns, room_id, secret, include_replies=False)
```

## Web UI

**Main timeline**: Top-level messages only. Messages with replies show a thread indicator:

```
┌──────────────────────────────────────┐
│ Alice                                │
│ Let's plan the release               │
│ 👍 2  +    ↩ Reply                   │
│ 💬 3 replies                  2m ago │
└──────────────────────────────────────┘
```

**Thread panel**: Clicking the thread indicator or reply button opens a panel showing the root message and all replies chronologically.

## Design exploration notes

We evaluated three approaches before settling on flat threads:

1. **Materialized path (`thread_path`)** — stores full ancestry as a string column (e.g., `/root_mid/parent_mid/child_mid`). Enables elegant subtree queries and server-side tree-order sorting via `ORDER BY thread_path`. However: unbounded string growth (37 bytes per nesting level), larger index entries, and the client needs the full thread for the panel anyway — making server-side tree ordering redundant.

2. **`thread_root_mid` + `depth`** — fixed-size denormalized columns. Handles arbitrary nesting with simple "get full thread" queries (`WHERE thread_root_mid = ?`). Client reconstructs the tree from `reference_mid` pointers in memory. Reasonable tradeoff, but the nesting UX gets unwieldy and the use case doesn't need it.

3. **Flat threads (Slack-style)** — `reference_mid` only, no new columns. All queries are simple indexed lookups. No tree reconstruction needed. Covers the actual use case for both human chat and agent conversations.

Flat threads win because zero schema changes are needed, all queries are trivial, and the UX is straightforward. If nesting is ever needed, `reference_mid` already supports it — we'd just relax the validation rule.
