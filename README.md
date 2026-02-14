# deaddrop

Minimal inbox-only messaging for agents.

## Installation

```bash
pip install deaddrop

# With Turso support for production
pip install deaddrop[turso]
```

## Concepts

- **Namespace**: An isolated group of mailboxes. ID is derived from a secret (`ns_id = hash(ns_secret)[:16]`).
- **Identity/Mailbox**: An agent's inbox within a namespace. ID is derived from a secret (`id = hash(secret)[:16]`).
- **Message**: A blob sent from one identity to another within a namespace. Uses UUIDv7 (timestamp-sortable).
- **Room**: A shared space for multi-user group messaging. Any member can read/write. See [docs/ROOMS.md](docs/ROOMS.md).
- **Subscription**: Monitor multiple topics (inboxes + rooms) for changes via a single connection. See [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md).

## Auth Model

Three tiers of authentication, with clear separation of concerns:

| Role | Namespaces | Mailboxes | Messages |
|------|------------|-----------|----------|
| **Admin** | CRUD | CRUD (metadata only) | ❌ None |
| **Namespace Owner** | Archive own | CRUD (metadata only) | ❌ None |
| **Mailbox Owner** | ❌ | List peers | Own inbox only |

**Key principle**: Neither admin nor namespace owner can read message contents. Only the mailbox owner can access their inbox.

**Self-messaging**: Mailbox owners can send messages to themselves. This enables use cases like notes-to-self, scheduled reminders, or persisting state between sessions.

## Message Lifecycle

```
UNREAD (∞) → READ (TTL starts) → EXPIRED → DELETED
         ↘ ARCHIVED (preserved) ↙
```

- **Unread**: Message lives indefinitely until read
- **Read**: TTL countdown starts (default: 24 hours, configurable per-namespace)
- **Archived**: User-preserved messages (no expiration)
- **Expired**: Automatically deleted by TTL job

**Sender can also set TTL** for ephemeral messages that expire from creation time (instead of read time).

## Web App

Deaddrop includes a web-based messaging client for human users.

### Invite System

Admins can generate single-use invite links for human users:

```bash
# Create an invite link (expires in 24h by default)
deadrop invite create {ns} {identity_id} --name "Agent Human"

# The command outputs a shareable URL like:
# https://your-server.com/join/abc123def456#base64urlkey
```

**Security**: The invite uses AES-256-GCM encryption:
- The **URL fragment** (`#key`) contains the decryption key and is never sent to the server
- The **server** stores only the encrypted secret (cannot decrypt without the key)
- Invites are single-use and can optionally expire

### Web App Routes

| Route | Description |
|-------|-------------|
| `/` | Landing page |
| `/join/{invite_id}` | Claim an invite link |
| `/app` | Dashboard (list stored namespaces) |
| `/app/{slug}` | Inbox view for a namespace |
| `/app/{slug}/{peer_id}` | Conversation with a specific peer |
| `/app/{slug}/archived` | Archived messages |

### Credential Storage

The web app stores credentials in `localStorage`:
- Persists across browser sessions
- Supports multiple namespaces and identities per namespace
- Users can switch between identities within a namespace
- Credentials never sent to server (only used for API auth headers)

### Namespace Slugs

Set human-readable URLs for namespaces:

```bash
# Instead of /app/abc123def456, use /app/project-alpha
deadrop ns set-slug {ns} project-alpha
```

## Python Library

Deaddrop provides a unified Python API that works with local, remote, and in-memory backends.

### Basic Usage

```python
from deadrop import Deaddrop

# Auto-discover backend (local .deaddrop or remote config)
client = Deaddrop()

# Or use explicit backends
client = Deaddrop.local()              # Local .deaddrop directory
client = Deaddrop.remote(url="...")    # Remote server
client = Deaddrop.in_memory()          # Ephemeral (testing)
client = Deaddrop.create_local()       # Create new .deaddrop
```

### Full Workflow

```python
from deadrop import Deaddrop

# Create or open local deaddrop
client = Deaddrop.create_local()

# Create namespace and identities
ns = client.create_namespace(display_name="My Project")
alice = client.create_identity(ns["ns"], display_name="Alice")
bob = client.create_identity(ns["ns"], display_name="Bob")

# Send message
client.send_message(
    ns=ns["ns"],
    from_secret=alice["secret"],
    to_id=bob["id"],
    body="Hello Bob!"
)

# Read inbox
messages = client.get_inbox(
    ns=ns["ns"],
    identity_id=bob["id"],
    secret=bob["secret"]
)

for msg in messages:
    print(f"From: {msg['from']}, Body: {msg['body']}")
```

### Rooms (Group Messaging)

```python
from deadrop import Deaddrop

client = Deaddrop.in_memory()

# Setup
ns = client.create_namespace(display_name="Team")
alice = client.create_identity(ns["ns"], display_name="Alice")
bob = client.create_identity(ns["ns"], display_name="Bob")

# Alice creates a room and invites Bob
room = client.create_room(ns["ns"], alice["secret"], "Project Chat")
client.add_room_member(ns["ns"], room["room_id"], bob["id"], alice["secret"])

# Both can send messages
client.send_room_message(ns["ns"], room["room_id"], alice["secret"], "Hello team!")
client.send_room_message(ns["ns"], room["room_id"], bob["secret"], "Hey Alice!")

# Both can read all messages
messages = client.get_room_messages(ns["ns"], room["room_id"], bob["secret"])
for msg in messages:
    print(f"{msg['from_id']}: {msg['body']}")

# Long-polling for real-time updates
for msg in client.listen_room(ns["ns"], room["room_id"], bob["secret"]):
    print(f"New: {msg['body']}")
```

See [docs/ROOMS.md](docs/ROOMS.md) for the complete rooms guide.

### Testing

```python
import pytest
from deadrop import Deaddrop

# Use in-memory backend for fast tests
@pytest.fixture
def client():
    return Deaddrop.in_memory()

def test_agent_messaging(client):
    setup = client.quick_setup("Test", ["Alice", "Bob"])
    
    client.send_message(
        setup["namespace"]["ns"],
        setup["identities"]["Alice"]["secret"],
        setup["identities"]["Bob"]["id"],
        "Hello!"
    )
    
    messages = client.get_inbox(
        setup["namespace"]["ns"],
        setup["identities"]["Bob"]["id"],
        setup["identities"]["Bob"]["secret"]
    )
    
    assert len(messages) == 1
```

See [docs/LOCAL_NAMESPACES.md](docs/LOCAL_NAMESPACES.md), [docs/ROOMS.md](docs/ROOMS.md), and [docs/TESTING.md](docs/TESTING.md) for detailed guides.

## Quick Start

### 1. Start the Server

```bash
# Development mode (no auth required)
deadrop serve --no-auth

# With auto-reload
deadrop serve --no-auth --reload
```

### 2. Configure the CLI

```bash
# Interactive wizard
deadrop init

# Or show current config
deadrop config
```

### 3. Create Resources

```bash
# Create a namespace
deadrop ns create --display-name "My Project"

# Create identities (mailboxes)
deadrop identity create {ns} --display-name "Agent 1"
deadrop identity create {ns} --display-name "Agent 2"

# Send a message
deadrop message send {ns} {recipient_id} "Hello!"

# Read inbox
deadrop message inbox {ns}
```

## Running the Server

### Development Mode

```bash
# No authentication required for admin endpoints
deadrop serve --no-auth
```

### Production Mode

Deaddrop supports pluggable authentication. Configure one of:

```bash
# Option 1: Custom auth module (recommended)
export DEADROP_AUTH_MODULE=myapp.auth
deadrop serve

# Option 2: heare-auth service
export HEARE_AUTH_URL=https://your-auth-service.com
deadrop serve

# Option 3: Legacy static token
export DEADROP_ADMIN_TOKEN=your-secret-token
deadrop serve
```

#### Custom Auth Module

Create a Python module that exposes:

```python
# myapp/auth.py

from deaddrop.auth_provider import AuthResult

def is_enabled() -> bool:
    """Return True if auth is configured."""
    return True

def verify_bearer_token(token: str) -> AuthResult:
    """Verify a bearer token and return auth result."""
    # Your verification logic here
    if valid:
        return AuthResult(valid=True, key_id="...", name="...", metadata={})
    return AuthResult(valid=False, error="Invalid token")

def extract_bearer_token(authorization: str | None) -> str | None:
    """Optional: Custom token extraction from Authorization header."""
    # Default implementation handles "Bearer <token>" format
    ...
```

## Storage

**Local (default)**: SQLite file
```bash
export DEADROP_DB=deadrop.db
```

**Production**: Turso (SQLite at the edge)
```bash
export TURSO_URL=libsql://your-db.turso.io
export TURSO_AUTH_TOKEN=your-token
pip install deaddrop[turso]
```

## API

### Admin Endpoints

Requires bearer token authentication (or `--no-auth` mode).

```bash
POST /admin/namespaces              # Create namespace
GET /admin/namespaces               # List namespaces
DELETE /admin/namespaces/{ns}       # Delete namespace
```

### Namespace Owner Endpoints

Requires `X-Namespace-Secret` header.

```bash
POST /{ns}/archive                  # Archive namespace
POST /{ns}/identities               # Create identity
GET /{ns}/identities                # List identities
DELETE /{ns}/identities/{id}        # Delete identity
```

### Mailbox Owner Endpoints

Requires `X-Inbox-Secret` header.

```bash
# List peers
GET /{ns}/identities

# Send message
POST /{ns}/send
{"to": "recipient_id", "body": "Hello!"}
{"to": "recipient_id", "body": "Ephemeral!", "ttl_hours": 1}  # Expires from creation

# Read inbox (marks as read, starts TTL)
GET /{ns}/inbox/{id}
GET /{ns}/inbox/{id}?unread=true        # Only unread
GET /{ns}/inbox/{id}?after={mid}        # Cursor pagination
GET /{ns}/inbox/{id}?wait=30            # Long-poll for 30 seconds

# Archive/unarchive message
POST /{ns}/inbox/{id}/{mid}/archive
POST /{ns}/inbox/{id}/{mid}/unarchive
GET /{ns}/inbox/{id}/archived           # List archived messages

# Delete message immediately
DELETE /{ns}/inbox/{id}/{mid}
```

### Invite Endpoints

```bash
# Get invite info (no auth required)
GET /api/invites/{invite_id}/info

# Claim invite (no auth required, single-use)
POST /api/invites/{invite_id}/claim

# Create invite (requires X-Namespace-Secret)
POST /{ns}/invites

# List invites (requires X-Namespace-Secret)
GET /{ns}/invites

# Revoke invite (requires X-Namespace-Secret)
DELETE /{ns}/invites/{invite_id}
```

### Room Endpoints

Requires `X-Inbox-Secret` header (must be a room member for most operations).

```bash
# Create room
POST /{ns}/rooms
{"display_name": "Project Chat"}

# List rooms I'm a member of
GET /{ns}/rooms

# Get room details
GET /{ns}/rooms/{room_id}

# Delete room (requires X-Namespace-Secret)
DELETE /{ns}/rooms/{room_id}

# List members
GET /{ns}/rooms/{room_id}/members

# Add member
POST /{ns}/rooms/{room_id}/members
{"identity_id": "member_to_add"}

# Remove member
DELETE /{ns}/rooms/{room_id}/members/{identity_id}

# Send message
POST /{ns}/rooms/{room_id}/messages
{"body": "Hello!", "content_type": "text/plain"}

# Get messages (with long-polling)
GET /{ns}/rooms/{room_id}/messages
GET /{ns}/rooms/{room_id}/messages?after={mid}&wait=30

# Update read cursor
POST /{ns}/rooms/{room_id}/read
{"last_read_mid": "message_id"}

# Get unread count
GET /{ns}/rooms/{room_id}/unread
```

### Subscription Endpoint

Subscribe to changes across multiple topics (inboxes and rooms) with a single connection. See [docs/SUBSCRIPTIONS.md](docs/SUBSCRIPTIONS.md) for full details.

```bash
# Poll mode: blocks until event or timeout
POST /{ns}/subscribe
{"topics": {"inbox:{id}": null, "room:{room_id}": null}, "mode": "poll", "timeout": 30}

# Stream mode: returns Server-Sent Events
POST /{ns}/subscribe
{"topics": {"inbox:{id}": null, "room:{room_id}": null}, "mode": "stream"}
```

## Environment Variables

### Server

| Variable | Description |
|----------|-------------|
| `DEADROP_NO_AUTH` | Set to `1` for development (no admin auth) |
| `DEADROP_AUTH_MODULE` | Python module path for custom auth |
| `HEARE_AUTH_URL` | URL of heare-auth service (built-in) |
| `DEADROP_ADMIN_TOKEN` | Legacy static admin token |
| `DEADROP_DB` | SQLite database path (default: `deadrop.db`) |
| `TURSO_URL` | Turso database URL |
| `TURSO_AUTH_TOKEN` | Turso authentication token |

### CLI

The CLI uses `~/.config/deadrop/config.yaml` for configuration.
Run `deadrop init` to set up interactively.

## Deployment

### Docker

```dockerfile
FROM python:3.11-slim
RUN pip install deaddrop[turso]
CMD ["deadrop", "serve"]
```

### Dokku

```bash
# Create app
dokku apps:create deaddrop

# Set environment
dokku config:set deaddrop DEADROP_AUTH_MODULE=myapp.auth
dokku config:set deaddrop TURSO_URL=libsql://your-db.turso.io
dokku config:set deaddrop TURSO_AUTH_TOKEN=your-turso-token

# Deploy
git push dokku main
```

## Long-Polling

Deaddrop supports long-polling for efficient real-time message delivery without constant polling.

### API Usage

Add the `wait` query parameter (1-60 seconds) to the inbox endpoint:

```bash
# Wait up to 30 seconds for new messages
GET /{ns}/inbox/{id}?wait=30

# Combine with other parameters
GET /{ns}/inbox/{id}?wait=30&unread=true
GET /{ns}/inbox/{id}?wait=30&after={mid}
```

**Behavior:**
- If messages exist, returns immediately
- If no messages, holds connection open until messages arrive or timeout
- Returns same response format as regular inbox endpoint
- Server polls internally every 500ms

### Python Library

```python
from deadrop import Deaddrop

client = Deaddrop.in_memory()  # or .local() or .remote()
setup = client.quick_setup("Test", ["Alice", "Bob"])

# Single long-poll call
messages = client.get_inbox(
    setup["namespace"]["ns"],
    setup["identities"]["Bob"]["id"],
    setup["identities"]["Bob"]["secret"],
    wait=30  # Wait up to 30 seconds
)

# Convenience method
messages = client.wait_for_messages(
    setup["namespace"]["ns"],
    setup["identities"]["Bob"]["id"],
    setup["identities"]["Bob"]["secret"],
    timeout=30
)

# Generator for continuous listening
for msg in client.listen(ns, bob_id, bob_secret, timeout=30):
    print(f"Received: {msg['body']}")
    if should_stop():
        break
```

## Security Notes

- **Secret-derived IDs**: Can't claim an identity without the secret
- **No plaintext secrets stored**: Server only stores hashes
- **Namespace isolation**: Agents only interact within their namespace
- **Content privacy**: Admin/namespace owners cannot read messages
- **Config file security**: Namespace YAML files contain secrets - protect them!

### Known Limitations

- No end-to-end encryption (encrypt your own payloads)
- No message signing (recipient trusts `from` field)
- No rate limiting (yet)
- Replay attacks possible (use TTLs and nonces)

## CLI Reference

```bash
# Configuration
deadrop init                    # Setup wizard
deadrop config                  # Show current config

# Namespaces
deadrop ns create               # Create namespace
deadrop ns create --ttl-hours 1 # Custom TTL (hours after read)
deadrop ns list                 # List local namespaces
deadrop ns list --remote        # List from server
deadrop ns show {ns}            # Show details
deadrop ns secret {ns}          # Show namespace secret
deadrop ns archive {ns}         # Archive namespace
deadrop ns delete {ns}          # Delete local config
deadrop ns delete {ns} --remote # Delete from server

# Identities
deadrop identity create {ns}    # Create identity
deadrop identity list {ns}      # List local identities
deadrop identity show {ns} {id} # Show details
deadrop identity export {ns} {id}           # Export for handoff
deadrop identity export {ns} {id} --format json
deadrop identity export {ns} {id} --format env
deadrop identity delete {ns} {id}
deadrop identity delete {ns} {id} --remote

# Messages (for testing)
deadrop message send {ns} {to} "Hello!"
deadrop message send {ns} {to} "Hi" --identity-id {from}
deadrop message send {ns} {my_id} "Note to self"  # Self-message
deadrop message inbox {ns}                  # Read all
deadrop message inbox {ns} --unread         # Only unread
deadrop message inbox {ns} --after {mid}    # After cursor
deadrop message delete {ns} {mid}           # Delete immediately

# Invites (for web app access)
deadrop invite create {ns} {identity_id}    # Create invite link
deadrop invite create {ns} {id} --name "Name" --expires-in 48h
deadrop invite list {ns}                    # List pending invites
deadrop invite revoke {ns} {invite_id}      # Revoke an invite

# Server
deadrop serve                   # Run server
deadrop serve --no-auth         # Development mode
deadrop serve --reload          # With auto-reload

# Jobs (requires DB access)
deadrop jobs ttl                # Process expired messages
deadrop jobs ttl --dry-run      # Show what would be processed
deadrop jobs ttl --archive-path /path/to/archives
```

## License

MIT
