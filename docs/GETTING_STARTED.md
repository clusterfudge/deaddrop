# Getting Started with Deadrop

This guide walks you through setting up a deadrop server, creating a namespace, and connecting users via the web UI.

## Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

## Installation

```bash
# Clone the repository
git clone https://github.com/clusterfudge/deaddrop.git
cd deaddrop

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

## Quick Start (Development Mode)

### 1. Start the Server

```bash
# Development mode - no authentication required for admin endpoints
uv run deadrop serve --no-auth

# Server runs at http://localhost:8000
```

### 2. Create a Namespace

A namespace is an isolated group of mailboxes. You can create one via the API:

```bash
# Create a namespace with a display name and URL slug
curl -X POST http://localhost:8000/admin/namespaces \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {"display_name": "My Project"},
    "slug": "my-project",
    "ttl_hours": 24
  }'
```

Response:
```json
{
  "ns": "abc123def456",
  "secret": "your-namespace-secret-here",
  "slug": "my-project",
  "metadata": {"display_name": "My Project"},
  "ttl_hours": 24
}
```

**Save the `ns` and `secret`** - you'll need them to create identities.

### 3. Create Identities (Mailboxes)

Create mailboxes for users within your namespace:

```bash
# Create an identity for Alice
curl -X POST http://localhost:8000/{ns}/identities \
  -H "Content-Type: application/json" \
  -H "X-Namespace-Secret: {namespace_secret}" \
  -d '{"metadata": {"display_name": "Alice"}}'
```

Response:
```json
{
  "id": "alice123",
  "secret": "alices-mailbox-secret",
  "metadata": {"display_name": "Alice"}
}
```

### 4. Create an Invite Link for the Web UI

To let a user access their mailbox via the web UI, create an invite:

```bash
# Using Python (since the CLI needs local config)
uv run python -c "
from deadrop import db
from deadrop.crypto import create_invite_secrets
from datetime import datetime, timedelta, timezone

db.init_db()

# Replace with the actual mailbox secret from step 3
mailbox_secret = 'alices-mailbox-secret'
secrets = create_invite_secrets(mailbox_secret)

expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
db.create_invite(
    invite_id=secrets.invite_id,
    ns='{ns}',  # Replace with namespace ID
    identity_id='alice123',  # Replace with identity ID
    encrypted_secret=secrets.encrypted_secret_hex,
    display_name='Alice',
    expires_at=expires_at,
)

print(f'Invite URL: http://localhost:8000/join/{secrets.invite_id}#{secrets.key_base64}')
"
```

### 5. Share the Invite Link

Send the invite URL to Alice. When she opens it:

1. She'll see an invitation page with the namespace and identity info
2. Clicking "Accept Invitation" decrypts her credentials client-side
3. She's redirected to `/app/my-project` where she can send/receive messages

---

## Production Setup

### Authentication Options

Deadrop supports two authentication modes for admin endpoints:

#### Option 1: heare-auth (Recommended)

[heare-auth](https://github.com/heare-io/heare-auth) provides OAuth-based authentication with API keys.

```bash
export HEARE_AUTH_URL=https://your-heare-auth-instance.com
uv run deadrop serve
```

Admin requests require a bearer token:
```bash
curl -X POST http://localhost:8000/admin/namespaces \
  -H "Authorization: Bearer your-heare-auth-token" \
  -H "Content-Type: application/json" \
  -d '{"metadata": {"display_name": "Production Project"}}'
```

#### Option 2: Static Admin Token

For simpler deployments, use a static token:

```bash
export DEADROP_ADMIN_TOKEN=your-secret-admin-token
uv run deadrop serve
```

Admin requests use the `X-Admin-Token` header:
```bash
curl -X POST http://localhost:8000/admin/namespaces \
  -H "X-Admin-Token: your-secret-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"metadata": {"display_name": "Production Project"}}'
```

### Database Configuration

#### Local SQLite (Default)

```bash
export DEADROP_DB=deadrop.db
```

#### Turso (Production)

For edge deployment with [Turso](https://turso.tech/):

```bash
export TURSO_URL=libsql://your-db.turso.io
export TURSO_AUTH_TOKEN=your-turso-token
uv sync --extra turso  # Install Turso driver
```

---

## Using the CLI

The CLI provides a more convenient workflow for managing namespaces and identities.

### Initial Setup

```bash
# Run the interactive setup wizard
uv run deadrop init

# Default server URL is https://deaddrop.dokku.heare.io
# Enter your admin token (if using static token auth)
```

### Create Namespace via CLI

```bash
uv run deadrop ns create --display-name "My Project"
```

This creates the namespace and saves the credentials locally to `~/.config/deadrop/namespaces/`.

### Create Identity via CLI

```bash
# List your namespaces to get the ID
uv run deadrop ns list

# Create an identity in that namespace
uv run deadrop identity create {ns_id} --display-name "Alice"
```

### Create Invite via CLI

```bash
# List identities to get the ID
uv run deadrop identity list {ns_id}

# Create an invite link
uv run deadrop invite create {ns_id} {identity_id} --name "Alice" --expires-in 7d
```

Output:
```
Invite created!
  For: Alice
  Expires: 7d

Share this link (single-use):
http://localhost:8000/join/abc123...#base64key...
```

### Claim Invite via CLI

Users can also claim invites via the CLI instead of the web UI:

```bash
# Claim an invite link
uv run deadrop invite claim "https://deaddrop.example.com/join/abc123#base64key"

# Output:
# Claiming invite from https://deaddrop.example.com...
#   Namespace: My Project
#   Identity: Alice
#
# ✓ Invite claimed successfully!
#   Credentials saved to: ~/.config/deadrop/namespaces/abc123.yaml
#
# You can now use the CLI to interact with this mailbox:
#   deadrop message inbox abc123
#   deadrop message send abc123 <recipient_id> "Hello!"
```

---

## Web UI Flow

### For Admins

1. Create namespace and identities via API or CLI
2. Generate invite links for each user
3. Share invite links securely (they're single-use)

### For Users

1. Open the invite link in a browser
2. Review the invitation details (namespace, identity, TTL)
3. Click "Accept Invitation"
4. Start messaging!

### Web App Features

- **Inbox View**: See all conversations grouped by peer
- **Conversation View**: Chat-style message thread with a peer
- **Compose**: Send messages to any peer in the namespace
- **Archive**: Preserve important messages (bypasses TTL)
- **Multi-Identity**: Switch between identities in the same namespace

---

## Example: Full Workflow

```bash
# 1. Start server
uv run deadrop serve --no-auth &

# 2. Create namespace
NS_RESP=$(curl -s -X POST http://localhost:8000/admin/namespaces \
  -H "Content-Type: application/json" \
  -d '{"metadata": {"display_name": "Team Chat"}, "slug": "team"}')

NS=$(echo $NS_RESP | jq -r '.ns')
NS_SECRET=$(echo $NS_RESP | jq -r '.secret')

echo "Namespace: $NS"

# 3. Create two identities
ALICE=$(curl -s -X POST "http://localhost:8000/$NS/identities" \
  -H "Content-Type: application/json" \
  -H "X-Namespace-Secret: $NS_SECRET" \
  -d '{"metadata": {"display_name": "Alice"}}')

BOB=$(curl -s -X POST "http://localhost:8000/$NS/identities" \
  -H "Content-Type: application/json" \
  -H "X-Namespace-Secret: $NS_SECRET" \
  -d '{"metadata": {"display_name": "Bob"}}')

ALICE_ID=$(echo $ALICE | jq -r '.id')
ALICE_SECRET=$(echo $ALICE | jq -r '.secret')
BOB_ID=$(echo $BOB | jq -r '.id')
BOB_SECRET=$(echo $BOB | jq -r '.secret')

echo "Alice: $ALICE_ID"
echo "Bob: $BOB_ID"

# 4. Bob sends a message to Alice
curl -s -X POST "http://localhost:8000/$NS/send" \
  -H "Content-Type: application/json" \
  -H "X-Inbox-Secret: $BOB_SECRET" \
  -d "{\"to\": \"$ALICE_ID\", \"body\": \"Hey Alice!\"}"

# 5. Create invite for Alice to access web UI
uv run python -c "
from deadrop import db
from deadrop.crypto import create_invite_secrets
from datetime import datetime, timedelta, timezone

db.init_db()
secrets = create_invite_secrets('$ALICE_SECRET')
expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
db.create_invite(
    invite_id=secrets.invite_id,
    ns='$NS',
    identity_id='$ALICE_ID',
    encrypted_secret=secrets.encrypted_secret_hex,
    display_name='Alice',
    expires_at=expires,
)
print(f'Alice invite: http://localhost:8000/join/{secrets.invite_id}#{secrets.key_base64}')
"

# 6. Alice opens the link, accepts, and sees Bob's message!
```

---

---

## End-to-End Encryption

Deaddrop supports optional end-to-end encryption for sensitive communications.

### Setup Encryption Keys

```bash
# Generate a keypair for an identity
uv run deadrop identity generate-keys {ns} {identity_id}

# Verify keys are registered
uv run deadrop identity show-pubkey {ns} {identity_id}
```

### Sending Encrypted Messages

When both sender and recipient have registered public keys, messages are **automatically encrypted**:

```bash
# Both parties need keys
uv run deadrop identity generate-keys $NS $ALICE_ID
uv run deadrop identity generate-keys $NS $BOB_ID

# Bob sends to Alice - auto-encrypted!
uv run deadrop message send $NS $ALICE_ID "Secret message" --identity-id $BOB_ID
# Output:
# 🔒 Encrypting message...
# ✍ Signing message...
# Message sent: abc123...
```

### Reading Encrypted Messages

The CLI automatically decrypts messages when you have the private key:

```bash
uv run deadrop message inbox $NS $ALICE_ID
# Output:
# --- abc123... [unread] 🔓 ✓verified ---
# From: Bob (def456...)
# At: 2026-01-18T12:00:00Z
#
# Secret message
```

### Key Rotation

If you need to rotate keys (e.g., suspected compromise):

```bash
uv run deadrop identity rotate-key {ns} {identity_id}
```

This:
1. Generates a new keypair
2. Registers the new public key on the server
3. Revokes the old key
4. Keeps the old private key locally for decrypting historical messages

### Comprehensive Documentation

For full encryption documentation:

```bash
uv run deadrop docs
```

---

## Security Considerations

- **Invite links are single-use**: Once claimed, they cannot be reused
- **URL fragments are never sent to server**: The decryption key stays client-side
- **Secrets are never stored in plaintext**: Server only stores hashes
- **TTL protects message lifecycle**: Messages auto-expire after being read
- **E2E encryption is optional**: Enable it for sensitive communications
- **Private keys are local-only**: Never transmitted to the server

See the main [README.md](../README.md) for more security details.
