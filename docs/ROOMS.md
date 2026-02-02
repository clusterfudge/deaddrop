# Rooms - Multi-User Group Messaging

Deaddrop supports **rooms** for multi-user group communication alongside the traditional 1:1 inbox messaging.

## Overview

While 1:1 messaging keeps messages strictly in recipient inboxes (only the owner can read their inbox), rooms provide a shared space where multiple participants can read and write messages.

**Key Features:**
- Any namespace member can create rooms
- Room creator automatically becomes first member
- Any member can invite others from the same namespace
- Per-user read tracking (like Slack threads)
- Long-polling support for real-time updates

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

### Pagination and Long-Polling

```python
# Pagination with after_mid
first_batch = client.get_room_messages(ns["ns"], room["room_id"], secret, limit=10)
last_mid = first_batch[-1]["mid"] if first_batch else None

next_batch = client.get_room_messages(
    ns["ns"], room["room_id"], secret,
    after_mid=last_mid,
    limit=10
)

# Long-polling: wait for new messages
messages = client.get_room_messages(
    ns["ns"], room["room_id"], secret,
    after_mid=last_mid,
    wait=30  # Wait up to 30 seconds
)

# Convenience method
messages = client.wait_for_room_messages(
    ns["ns"], room["room_id"], secret,
    timeout=30,
    after_mid=last_mid
)

# Generator for continuous listening
for msg in client.listen_room(ns["ns"], room["room_id"], secret, timeout=30):
    print(f"New message from {msg['from_id']}: {msg['body']}")
    if msg["body"] == "quit":
        break
```

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

# Get messages (with optional pagination and long-polling)
GET /{ns}/rooms/{room_id}/messages
GET /{ns}/rooms/{room_id}/messages?after={mid}
GET /{ns}/rooms/{room_id}/messages?limit=50
GET /{ns}/rooms/{room_id}/messages?wait=30
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

# Workers listen and respond
for msg in client.listen_room(ns["ns"], room["room_id"], worker["secret"]):
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

## End-to-End Encryption

Rooms support optional end-to-end encryption with forward secrecy. When encryption is enabled:

- All messages are encrypted with a symmetric key (epoch key)
- The epoch key rotates on every membership change
- Past messages cannot be decrypted by new members (forward secrecy)
- Removed members cannot decrypt new messages (post-compromise security)
- All room members must have registered public keys

### Enabling Encryption

Create an encrypted room by setting `encryption_enabled=True`:

```python
# Creator must have a keypair first
client.register_pubkey(ns["ns"], alice["id"], alice["secret"])

# Create encrypted room
room = client.create_room(
    ns=ns["ns"],
    creator_secret=alice["secret"],
    display_name="Secure Channel",
    encryption_enabled=True
)

print(f"Encrypted: {room['encryption_enabled']}")
print(f"Current epoch: {room['current_epoch_number']}")  # Epoch 0
```

### Epoch Rotation

The epoch key rotates automatically on membership changes:

```python
# Bob must have a keypair to join encrypted rooms
client.register_pubkey(ns["ns"], bob["id"], bob["secret"])

# Adding Bob rotates to epoch 1
client.add_room_member(ns["ns"], room["room_id"], bob["id"], alice["secret"])
# Room is now at epoch 1

# Removing Bob rotates to epoch 2
client.remove_room_member(ns["ns"], room["room_id"], bob["id"], alice["secret"])
# Room is now at epoch 2, Bob cannot decrypt new messages
```

You can also manually rotate the key (room creator only):

```python
# Manual rotation for suspected key compromise
result = client.rotate_room_epoch(ns["ns"], room["room_id"], alice["secret"])
print(f"New epoch: {result['epoch']['epoch_number']}")
```

### Security Properties

**Forward Secrecy:**
- Each epoch uses a one-way key derivation function (HKDF)
- New members only get the current epoch key
- Previous epoch keys cannot be derived from the current key
- New members cannot decrypt historical messages

**Post-Compromise Security:**
- When a member is removed, the epoch rotates
- The removed member doesn't receive the new epoch key
- They cannot decrypt any messages sent after removal

**Cryptographic Details:**
- Message encryption: XSalsa20-Poly1305 (NaCl SecretBox)
- Message signing: Ed25519 (inside encrypted envelope)
- Key derivation: HKDF with SHA256
- Key distribution: NaCl Box (X25519 Diffie-Hellman)

### Epoch Mismatch Handling

If a client sends a message with a stale epoch number, the server returns HTTP 409:

```python
# Alice fetches epoch 3 key
epoch_info = client.get_room_epoch(ns["ns"], room["room_id"], alice["secret"])
# epoch_info["epoch"]["epoch_number"] == 3

# Meanwhile, Charlie joins (rotates to epoch 4)

# Alice tries to send with epoch 3 → gets 409 error
# Response includes: {"expected_epoch": 4, "provided_epoch": 3}

# Alice fetches epoch 4 key and retries
new_epoch = client.get_room_epoch(ns["ns"], room["room_id"], alice["secret"])
# Now she can send successfully
```

The CLI handles this automatically with a retry.

### CLI Commands

```bash
# Create encrypted room
deadrop room room-create my_ns "Secret Project" --encrypted

# Show epoch info
deadrop room room-epoch my_ns <room_id>
deadrop room room-epoch my_ns <room_id> 5  # Show epoch 5

# Manual rotation
deadrop room room-rotate my_ns <room_id>

# Send encrypted message (auto-encrypts, handles 409 retry)
deadrop room room-send my_ns <room_id> "Hello secure world!"

# Read and decrypt messages
deadrop room room-messages my_ns <room_id>
deadrop room room-messages my_ns <room_id> --no-decrypt  # Show ciphertext
```

### API Endpoints

```bash
# Get current epoch + your encrypted key
GET /{ns}/rooms/{room_id}/epoch
→ {"epoch": {...}, "encrypted_epoch_key": "..."}

# Get specific epoch (for historical messages)
GET /{ns}/rooms/{room_id}/epoch/{epoch_number}

# Manual rotation (room creator only)
POST /{ns}/rooms/{room_id}/rotate

# Send encrypted message
POST /{ns}/rooms/{room_id}/messages
{
    "body": "<base64 ciphertext>",
    "encrypted": true,
    "epoch_number": 5,
    "encryption_meta": {"algorithm": "xsalsa20-poly1305+ed25519", "nonce": "..."},
    "signature": "<base64 signature>"
}

# Epoch mismatch returns 409
HTTP 409
{"error": "epoch_mismatch", "expected_epoch": 6, "provided_epoch": 5}
```

### Limitations

- **No migration**: Existing unencrypted rooms cannot be converted to encrypted
- **Pubkey required at join time**: All members must have registered keypairs before joining
- **No offline key delivery**: Members must be able to receive the epoch key when it rotates
- **Performance**: O(N) key encryption per rotation (practical for <1000 members)

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
