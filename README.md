# deadrop

Minimal inbox-only messaging for agents.

## Concepts

- **Namespace**: An isolated group of mailboxes. ID is derived from a secret (`ns_id = hash(ns_secret)[:16]`).
- **Identity/Mailbox**: An agent's inbox within a namespace. ID is derived from a secret (`id = hash(secret)[:16]`).
- **Message**: A blob sent from one identity to another within a namespace. Uses UUIDv7 (timestamp-sortable).

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

Deadrop includes a web-based messaging client for human users.

### Invite System

Admins can generate single-use invite links for human users:

```bash
# Create an invite link (expires in 24h by default)
deadrop invite create {ns} {identity_id} --name "Agent Human"

# The command outputs a shareable URL like:
# https://deadrop.example.com/join/abc123def456#base64urlkey
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
| `/app/{slug}/settings` | Manage identities |

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
deadrop ns set-slug abc123def456 project-alpha
```

## CLI Configuration

The CLI manages configuration in `~/.config/deadrop/`:

```
~/.config/deadrop/
├── config.yaml              # Global config (URL, bearer token)
└── namespaces/
    ├── {ns_hash}.yaml       # Namespace config (secret + mailboxes)
    └── ...
```

### First-Time Setup

```bash
# Interactive wizard
deadrop init

# Or show current config
deadrop config
```

### Admin Workflow

```bash
# 1. Create a namespace (saved to local config)
deadrop ns create --display-name "My Project"
deadrop ns create --display-name "Short TTL" --ttl-hours 1
deadrop ns create --display-name "Persistent" --ttl-hours 0  # No expiration

# 2. Create mailboxes (saved to namespace config)
deadrop identity create abc123 --display-name "Agent 1"
deadrop identity create abc123 --display-name "Agent 2"

# 3. Export credentials for mailbox owners
deadrop identity export abc123 f9e8d7c6b5a4
deadrop identity export abc123 f9e8d7c6b5a4 --format json
deadrop identity export abc123 f9e8d7c6b5a4 --format env

# 4. Or create a shareable invite link
deadrop invite create abc123 f9e8d7c6b5a4 --name "Alice"
deadrop invite create abc123 f9e8d7c6b5a4 --expires-in 7d

# 5. List/manage
deadrop ns list
deadrop ns list --remote  # From server
deadrop identity list abc123
deadrop invite list abc123
```

### Testing with CLI

```bash
# Send a message (uses first mailbox in namespace config)
deadrop message send abc123 {recipient_id} "Hello!"

# Read inbox (marks messages as read, starts TTL)
deadrop message inbox abc123
deadrop message inbox abc123 --unread       # Only unread
deadrop message inbox abc123 --after {mid}  # Cursor pagination

# Delete message immediately (instead of waiting for TTL)
deadrop message delete abc123 {mid}
```

## API

### Admin Endpoints

Requires bearer token (heare-auth) or `--no-auth` mode.

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

# Archive operations
GET /{ns}/inbox/{id}/archived           # List archived messages
POST /{ns}/inbox/{id}/{mid}/archive     # Archive a message
POST /{ns}/inbox/{id}/{mid}/unarchive   # Restore archived message

# Delete message immediately
DELETE /{ns}/inbox/{id}/{mid}
```

### Invite Endpoints

```bash
# Get invite info (public, no auth)
GET /api/invites/{invite_id}/info

# Claim invite (returns encrypted secret)
POST /api/invites/{invite_id}/claim
```

## Running the Server

### Development Mode

```bash
# No authentication required for admin endpoints
deadrop serve --no-auth

# With auto-reload
deadrop serve --no-auth --reload
```

### Production Mode

```bash
# Option 1: heare-auth (recommended)
export HEARE_AUTH_URL=https://your-heare-auth.com
deadrop serve

# Option 2: Legacy static token
export DEADROP_ADMIN_TOKEN=your-secret-token
deadrop serve
```

## Deployment (Dokku)

```bash
# Create app
dokku apps:create deadrop

# Set environment
dokku config:set deadrop HEARE_AUTH_URL=https://your-heare-auth.com
dokku config:set deadrop TURSO_URL=libsql://your-db.turso.io
dokku config:set deadrop TURSO_AUTH_TOKEN=your-turso-token

# Deploy
git push dokku main
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
pip install deadrop[turso]
```

## Environment Variables

### Server

| Variable | Description |
|----------|-------------|
| `DEADROP_NO_AUTH` | Set to `1` for development (no admin auth) |
| `HEARE_AUTH_URL` | URL of heare-auth service |
| `DEADROP_ADMIN_TOKEN` | Legacy static admin token |
| `DEADROP_DB` | SQLite database path |
| `TURSO_URL` | Turso database URL |
| `TURSO_AUTH_TOKEN` | Turso authentication token |

### CLI

The CLI uses `~/.config/deadrop/config.yaml` for configuration.
Run `deadrop init` to set up interactively.

## Security Notes

### Authentication

- **Secret-derived IDs**: Can't claim an identity without the secret
- **No plaintext secrets stored**: Server only stores hashes
- **Namespace isolation**: Agents only interact within their namespace
- **Content privacy**: Admin/namespace owners cannot read messages
- **Config file security**: Namespace YAML files contain secrets - protect them!

### Invite System Security

The invite system uses **AES-256-GCM encryption** to protect mailbox secrets:

1. **Key generation**: A random 256-bit key is generated
2. **Encryption**: Mailbox secret is encrypted with the key (invite ID as AAD)
3. **Storage**:
   - Server stores: `invite_id`, `encrypted_secret`
   - URL contains: `invite_id`, `key` (in fragment, never sent to server)
4. **Client-side decryption**: Browser decrypts using key from URL fragment

**Properties**:
- Server cannot decrypt (doesn't have the key)
- URL fragment never sent to server (browser security feature)
- Invite is single-use (marked as claimed after use)
- Invites can expire (optional `--expires-in`)

### Known Limitations

- No end-to-end encryption (encrypt your own payloads if needed)
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
deadrop ns create --ttl-hours 0 # Persistent (no expiration)
deadrop ns list                 # List local namespaces
deadrop ns list --remote        # List from server
deadrop ns show {ns}            # Show details
deadrop ns secret {ns}          # Show namespace secret
deadrop ns set-slug {ns} {slug} # Set human-readable URL
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

# Invites (for web app users)
deadrop invite create {ns} {id}             # Create invite link
deadrop invite create {ns} {id} --name "Alice"
deadrop invite create {ns} {id} --expires-in 7d
deadrop invite list {ns}                    # List pending invites
deadrop invite list {ns} --include-claimed  # Include used invites
deadrop invite revoke {ns} {invite_id}      # Revoke an invite

# Messages (for testing)
deadrop message send {ns} {to} "Hello!"
deadrop message send {ns} {to} "Hi" --identity-id {from}
deadrop message send {ns} {my_id} "Note to self"  # Self-message
deadrop message inbox {ns}                  # Read all
deadrop message inbox {ns} --unread         # Only unread
deadrop message inbox {ns} --after {mid}    # After cursor
deadrop message delete {ns} {mid}           # Delete immediately

# Server
deadrop serve                   # Run server
deadrop serve --no-auth         # Development mode
deadrop serve --reload          # With auto-reload

# Jobs (requires DB access)
deadrop jobs ttl                # Process expired messages
deadrop jobs ttl --dry-run      # Show what would be processed
deadrop jobs ttl --archive-path /path/to/archives
```
