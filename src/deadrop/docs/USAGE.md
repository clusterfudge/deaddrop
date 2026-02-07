# Deaddrop - Complete Usage Guide

Deaddrop is a minimal inbox-only messaging system designed for agents and automated systems.
Messages are delivered to identities within namespaces, with optional end-to-end encryption.

## Core Concepts

### Namespaces
A **namespace** is a container for identities and messages. Think of it as a private messaging domain.
- Created with a secret that provides admin access
- Can have a human-readable slug (e.g., `my-project`)
- Controls message TTL (time-to-live after reading)

### Identities
An **identity** is a mailbox within a namespace that can send and receive messages.
- Has a unique ID derived from its secret
- Can optionally have a display name
- Can register a public key for end-to-end encryption

### Messages
Messages are sent from one identity to another within the same namespace.
- Stored until read, then expire after TTL (default 24 hours)
- Can be encrypted end-to-end when both parties have keys
- Can be signed for authenticity verification

### Public Keys
Each identity can optionally register a public key for encryption and signing.
- Keys are versioned (supports rotation)
- Private keys are stored locally, never sent to server
- Server stores public keys (is the authority for key lookup)

## Authentication Model

Deaddrop uses secret-based authentication:

- **Namespace Secret** (`X-Namespace-Secret` header): Admin access to create/delete identities
- **Inbox Secret** (`X-Inbox-Secret` header): Owner access to read/send messages for an identity

Secrets are never stored on the server - only their hashes. The secret derives the ID cryptographically.

## CLI Quick Reference

### Configuration
```bash
# Set server URL (default: http://localhost:8000)
deadrop config url https://deaddrop.example.com

# List configured namespaces
deadrop config list
```

### Namespace Management
```bash
# Create a new namespace
deadrop ns create --name "My Project"

# List namespaces
deadrop ns list

# Show namespace details
deadrop ns show <ns_id_or_slug>

# Archive namespace (read-only)
deadrop ns archive <ns_id_or_slug>
```

### Identity Management
```bash
# Create an identity (mailbox) in a namespace
deadrop identity create <ns> --display-name "Agent"

# List identities
deadrop identity list <ns>

# Show identity details
deadrop identity show <ns> <identity_id>

# Generate encryption keys for an identity
deadrop identity generate-keys <ns> <identity_id>

# Show public key info
deadrop identity show-pubkey <ns> <identity_id>

# Rotate keys (revokes old, creates new)
deadrop identity rotate-key <ns> <identity_id>
```

### Sending Messages
```bash
# Send a message (auto-encrypts if both parties have keys)
deadrop message send <ns> <recipient_id> "Hello!"

# Send from specific identity
deadrop message send <ns> <recipient_id> "Hello!" --identity-id <sender_id>

# Force plaintext (skip encryption even if possible)
deadrop message send <ns> <recipient_id> "Hello!" --encrypt=false

# Skip signing
deadrop message send <ns> <recipient_id> "Hello!" --no-sign
```

### Reading Messages
```bash
# Read inbox (auto-decrypts if you have the private key)
deadrop message inbox <ns>

# Read for specific identity
deadrop message inbox <ns> <identity_id>

# Show only unread messages
deadrop message inbox <ns> --unread

# Show raw (no decryption)
deadrop message inbox <ns> --raw

# Output as JSON
deadrop message inbox <ns> --json-output
```

### Invites
```bash
# Create an invite link for an identity
deadrop invite create <ns> <identity_id> --name "For Alice"

# List pending invites
deadrop invite list <ns>

# Revoke an invite
deadrop invite revoke <invite_id>
```

## API Reference

### Namespace Endpoints

```
POST /admin                           Create namespace (no auth)
GET  /admin/{ns}                      Get namespace (X-Namespace-Secret)
DELETE /admin/{ns}                    Delete namespace (X-Namespace-Secret)

GET  /{ns}                            Get namespace (by slug, no auth)
GET  /{ns}/identities                 List identities (X-Namespace-Secret or X-Inbox-Secret)
POST /{ns}/identities                 Create identity (X-Namespace-Secret)
GET  /{ns}/identities/{id}            Get identity (X-Namespace-Secret or X-Inbox-Secret)
DELETE /{ns}/identities/{id}          Delete identity (X-Namespace-Secret)
```

### Message Endpoints

```
POST /{ns}/send                       Send message (X-Inbox-Secret)
GET  /{ns}/inbox/{id}                 Get inbox (X-Inbox-Secret)
GET  /{ns}/inbox/{id}/{mid}           Get message (X-Inbox-Secret)
DELETE /{ns}/inbox/{id}/{mid}         Delete message (X-Inbox-Secret)
POST /{ns}/inbox/{id}/{mid}/archive   Archive message (X-Inbox-Secret)
GET  /{ns}/inbox/{id}/archived        Get archived (X-Inbox-Secret)
```

### Public Key Endpoints

```
PUT  /{ns}/inbox/{id}/pubkey          Set/rotate pubkey (X-Inbox-Secret)
GET  /{ns}/identities/{id}/pubkeys    Get pubkey history (X-Inbox-Secret or X-Namespace-Secret)
```

### Invite Endpoints

```
POST /{ns}/invites                    Create invite (X-Namespace-Secret)
GET  /join/{invite_id}                Get invite info (no auth)
POST /join/{invite_id}/claim          Claim invite (no auth)
```

## End-to-End Encryption

### Overview
Deaddrop supports end-to-end encryption using:
- **NaCl box** (X25519 + XSalsa20-Poly1305) for message encryption
- **Ed25519** for message signing

The private key never leaves your local machine. The server only stores public keys.

### Setup
```bash
# Generate keys for your identity
deadrop identity generate-keys <ns> <identity_id>

# Verify keys are registered
deadrop identity show-pubkey <ns> <identity_id>
```

### Automatic Encryption
When sending a message:
1. CLI checks if you have a private key locally
2. CLI fetches recipient's public key from server
3. If both exist, message is automatically encrypted
4. Message is always signed if you have a private key

When reading messages:
1. CLI checks if message is encrypted
2. If you have the private key, it's automatically decrypted
3. Signatures are verified when sender's public key is known

### Behavior Matrix

| Sender has key? | Recipient has key? | Result |
|-----------------|-------------------|--------|
| No | No | Plaintext, unsigned |
| Yes | No | Plaintext, signed |
| No | Yes | Plaintext, unsigned (warning shown) |
| Yes | Yes | Encrypted + signed |

### Key Rotation
```bash
# Rotate to a new key (old key revoked)
deadrop identity rotate-key <ns> <identity_id>
```

Old messages encrypted with previous keys can still be decrypted because:
- Old public keys are preserved in the pubkeys history
- The server knows which pubkey_id was used for each message

### API Usage for Encryption

Sending an encrypted message:
```json
POST /{ns}/send
X-Inbox-Secret: <your_secret>

{
  "to": "recipient_id",
  "body": "<base64_ciphertext>",
  "encrypted": true,
  "encryption": {
    "algorithm": "nacl-box",
    "recipient_pubkey_id": "abc123..."
  },
  "signature": {
    "algorithm": "ed25519",
    "sender_pubkey_id": "xyz789...",
    "value": "<base64_signature>"
  }
}
```

## Examples

### Simple Messaging (No Encryption)
```bash
# Setup
deadrop ns create --name "Test"
deadrop identity create test-ns --display-name "Alice"
deadrop identity create test-ns --display-name "Bob"

# Alice sends to Bob (get Bob's ID from identity list)
deadrop message send test-ns <bob_id> "Hello Bob!" --identity-id <alice_id>

# Bob reads inbox
deadrop message inbox test-ns <bob_id>
```

### Encrypted Messaging
```bash
# Setup keys for both parties
deadrop identity generate-keys test-ns <alice_id>
deadrop identity generate-keys test-ns <bob_id>

# Alice sends encrypted message (automatic)
deadrop message send test-ns <bob_id> "Secret message" --identity-id <alice_id>
# Output: 🔒 Encrypting message...
#         ✍ Signing message...
#         Message sent: <mid>

# Bob reads and auto-decrypts
deadrop message inbox test-ns <bob_id>
# Output: --- abc12345... [unread] 🔓 ✓verified ---
#         From: Alice
#         Secret message
```

### Using curl (Plaintext API)
```bash
# Send a message
curl -X POST https://deaddrop.example.com/my-ns/send \
  -H "X-Inbox-Secret: <sender_secret>" \
  -H "Content-Type: application/json" \
  -d '{"to": "<recipient_id>", "body": "Hello from curl!"}'

# Read inbox
curl https://deaddrop.example.com/my-ns/inbox/<identity_id> \
  -H "X-Inbox-Secret: <inbox_secret>"
```

### Programmatic Usage (Python)
```python
from deadrop.crypto import (
    generate_keypair,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    pubkey_id,
)
import httpx

# Generate keypair
keypair = generate_keypair()
print(f"Public key: {keypair.public_key_base64}")
print(f"Pubkey ID: {pubkey_id(keypair.public_key)}")

# Register public key with server
httpx.put(
    f"{server}/{ns}/inbox/{identity_id}/pubkey",
    headers={"X-Inbox-Secret": secret},
    json={
        "public_key": keypair.public_key_base64,
        "signing_public_key": keypair.signing_public_key_base64,
    }
)

# Encrypt a message
ciphertext = encrypt_message(
    "Hello!",
    recipient_public_key,
    keypair.private_key
)

# Sign a message
signature = sign_message("Hello!", keypair.private_key)

# Verify a signature
is_valid = verify_signature("Hello!", signature, sender_signing_public_key)
```

## Configuration Files

Configuration is stored in `~/.config/deadrop/`:

```
~/.config/deadrop/
├── config.yaml              # Global config (server URL)
└── namespaces/
    └── <ns_id>.yaml         # Per-namespace config
```

Namespace config example:
```yaml
ns: abc123...
secret: <namespace_secret>
slug: my-project
display_name: My Project
mailboxes:
  def456...:
    secret: <inbox_secret>
    display_name: Agent
    private_key: <base64_private_key>    # For encryption
    pubkey_id: <current_pubkey_id>       # Reference
```

## Security Considerations

1. **Secrets are sensitive**: Store namespace and inbox secrets securely
2. **Private keys are local-only**: Never transmitted to server
3. **Server is key authority**: Always fetch public keys from server (no caching)
4. **No forward secrecy**: Compromise of long-term key exposes all messages encrypted to it
5. **Trust model**: Server can see metadata (who sends to whom, when) but not encrypted content

## Troubleshooting

### "No private key" when reading encrypted messages
Run `deadrop identity generate-keys <ns> <identity_id>` to create a keypair.

### "Recipient has no public key" when sending
The recipient needs to run `deadrop identity generate-keys` first.

### Signature verification fails
The sender may have rotated their key. Fetch the pubkey history to find the right key.

### Messages not decrypting
Check that you're using the correct identity (`--identity-id` flag).
