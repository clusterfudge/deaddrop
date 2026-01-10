# Cryptographic Security Design Proposal

This document proposes optional cryptographic enhancements for deadrop to provide stronger security guarantees while maintaining the system's minimalist philosophy.

## Current Security Model

### What Exists Today

| Aspect | Implementation | Security Level |
|--------|---------------|----------------|
| **Authentication** | Secret-derived IDs, SHA-256 hashed | Good |
| **Authorization** | Role-based (admin/namespace/mailbox) | Good |
| **Message Confidentiality** | None (plaintext in DB) | Poor |
| **Message Authenticity** | None (`from_id` can be spoofed*) | Poor |
| **Forward Secrecy** | None | N/A |

*While spoofing requires knowing a valid inbox secret, there's no cryptographic proof the message came from the claimed sender.

### Known Limitations (from README)

- No end-to-end encryption (encrypt your own payloads)
- No message signing (recipient trusts `from` field)
- No rate limiting
- Replay attacks possible

## Proposal Overview

Two-tier approach:

1. **Tier 1: Lightweight NaCl Crypto** - Built into core, optional per-identity
2. **Tier 2: Signal Protocol** - Extension package for advanced use cases

---

## Tier 1: Lightweight Public Key Cryptography

### Goals

- End-to-end encryption (server never sees plaintext)
- Message signing (cryptographic proof of sender)
- Minimal complexity (single library, simple key management)
- Backwards compatible (opt-in per identity)
- Self-contained (no external key servers)

### Cryptographic Choices

**Library**: PyNaCl (libsodium bindings)
- Mature, audited, widely used
- Simple API, hard to misuse
- Single dependency

**Algorithms**:
| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| **Signing** | Ed25519 | 64-byte signatures, fast verification |
| **Encryption** | X25519 + XSalsa20-Poly1305 | Via `nacl.public.Box` (authenticated encryption) |
| **Key Derivation** | N/A | Keys generated independently from inbox secrets |

**Why NaCl Box?**
- Combines encryption AND authentication in one operation
- Recipient can verify sender without separate signature
- Simpler than separate encrypt-then-sign

### Key Management

#### Key Generation

Each crypto-enabled identity has a keypair:

```python
from nacl.public import PrivateKey

private_key = PrivateKey.generate()
public_key = private_key.public_key

# Encode for storage/transmission
private_key_b64 = base64.b64encode(bytes(private_key)).decode()
public_key_b64 = base64.b64encode(bytes(public_key)).decode()
```

#### Key Storage

**Server-side** (public keys only):
```sql
-- Add to identities table
ALTER TABLE identities ADD COLUMN public_key TEXT;
-- 44-char base64 encoded X25519 public key, NULL if crypto disabled
```

**Client-side** (in `~/.config/deadrop/namespaces/{ns}.yaml`):
```yaml
mailboxes:
  f9e8d7c6:
    secret: "..."
    private_key: "base64-encoded-32-bytes"  # NEW: optional
```

#### Key Lifecycle

| Event | Action |
|-------|--------|
| Identity creation | Optionally generate keypair |
| Identity export | Include private key if present |
| Key rotation | Create new identity, migrate messages |
| Identity deletion | Keys destroyed with identity |

### Schema Changes

```sql
-- identities table addition
ALTER TABLE identities ADD COLUMN public_key TEXT;

-- messages table additions
ALTER TABLE messages ADD COLUMN encrypted BOOLEAN DEFAULT FALSE;
ALTER TABLE messages ADD COLUMN nonce TEXT;  -- 24-byte nonce, base64 (32 chars)
```

**Note**: No signature field needed - NaCl Box provides authenticated encryption (sender authenticity is implicit when recipient can decrypt).

### API Changes

#### Identity Creation

```bash
POST /{ns}/identities
X-Namespace-Secret: {secret}
Content-Type: application/json

{
  "metadata": {"display_name": "Agent 1"},
  "public_key": "base64-encoded-public-key"  # NEW: optional
}
```

Response:
```json
{
  "id": "f9e8d7c6",
  "secret": "...",
  "public_key": "..."  // Echoed back if provided
}
```

#### Fetch Public Key

New endpoint for retrieving peer public keys:

```bash
GET /{ns}/identities/{id}/pubkey
X-Inbox-Secret: {secret}

Response:
{
  "id": "a1b2c3d4",
  "public_key": "base64-encoded-key",  // null if crypto not enabled
  "crypto_enabled": true
}
```

#### Sending Messages

```bash
POST /{ns}/send
X-Inbox-Secret: {secret}
Content-Type: application/json

{
  "to": "recipient_id",
  "body": "base64-encoded-ciphertext",  # Encrypted by client
  "encrypted": true,                     # NEW: flag
  "nonce": "base64-encoded-nonce"        # NEW: for decryption
}
```

**Client-side encryption flow**:
```python
from nacl.public import Box

# Sender has: sender_private_key, recipient_public_key
box = Box(sender_private_key, recipient_public_key)
nonce = nacl.utils.random(Box.NONCE_SIZE)  # 24 bytes
ciphertext = box.encrypt(plaintext.encode(), nonce)

# Send ciphertext[Box.NONCE_SIZE:] as body, nonce separately
```

#### Receiving Messages

Messages returned include encryption metadata:

```json
{
  "messages": [
    {
      "mid": "...",
      "from": "sender_id",
      "body": "base64-ciphertext-or-plaintext",
      "encrypted": true,
      "nonce": "base64-nonce",
      "created_at": "..."
    }
  ]
}
```

**Client-side decryption flow**:
```python
from nacl.public import Box

# Recipient has: recipient_private_key, needs sender_public_key
sender_pubkey = fetch_pubkey(ns, message["from"])
box = Box(recipient_private_key, sender_pubkey)
plaintext = box.decrypt(ciphertext, nonce)
```

### CLI Changes

#### Identity Commands

```bash
# Create with crypto enabled (generates keypair)
deadrop identity create {ns} --crypto
deadrop identity create {ns} --display-name "Agent" --crypto

# Create without crypto (current behavior)
deadrop identity create {ns}

# Show includes public key
deadrop identity show {ns} {id}
# Output includes: public_key: Wq3...

# Export includes private key
deadrop identity export {ns} {id}
# Output includes: private_key: abc...
```

#### Message Commands

```bash
# Send encrypted (auto-encrypts if both parties have keys)
deadrop message send {ns} {to} "Hello!"
# CLI checks: do I have private key? does recipient have public key?
# If both: encrypts automatically
# If not: sends plaintext with warning

# Force plaintext (skip encryption even if keys exist)
deadrop message send {ns} {to} "Hello!" --plaintext

# Force encrypted (fail if keys missing)
deadrop message send {ns} {to} "Hello!" --encrypted

# Inbox auto-decrypts
deadrop message inbox {ns}
# Decrypts messages where encrypted=true, shows [ENCRYPTED] prefix if can't decrypt
```

#### Key Management

```bash
# Generate keypair for existing identity (if created without --crypto)
deadrop identity keygen {ns} {id}

# Export just the public key (for sharing)
deadrop identity pubkey {ns} {id}

# Import identity with existing keypair
deadrop identity import {ns}
# Prompts for: secret, private_key (optional)
```

### Crypto Module Structure

```
src/deadrop/
├── crypto/
│   ├── __init__.py      # Public API
│   ├── keys.py          # Key generation, encoding, storage
│   ├── box.py           # Encryption/decryption using NaCl Box
│   └── errors.py        # CryptoError, KeyNotFoundError, etc.
```

**Public API**:
```python
# keys.py
def generate_keypair() -> tuple[str, str]:
    """Returns (private_key_b64, public_key_b64)"""

def encode_public_key(key: PublicKey) -> str:
    """Base64 encode a public key"""

def decode_public_key(key_b64: str) -> PublicKey:
    """Decode base64 public key"""

# box.py
def encrypt_message(
    plaintext: str,
    sender_private_key: str,
    recipient_public_key: str
) -> tuple[str, str]:
    """Returns (ciphertext_b64, nonce_b64)"""

def decrypt_message(
    ciphertext_b64: str,
    nonce_b64: str,
    recipient_private_key: str,
    sender_public_key: str
) -> str:
    """Returns plaintext, raises CryptoError on failure"""
```

### Migration Path

1. **Phase 1**: Add schema columns, API parameters (all optional)
2. **Phase 2**: Add CLI `--crypto` flag, keygen command
3. **Phase 3**: Add auto-encrypt behavior in CLI
4. **Phase 4**: Document, add tests

### Security Considerations

| Concern | Mitigation |
|---------|------------|
| **Key storage** | Private keys in config file (same as secrets) - user must protect |
| **Key rotation** | Not supported initially; create new identity to rotate |
| **Replay attacks** | Nonce prevents replay; TTL provides time-bound protection |
| **Metadata leakage** | `from_id`, `to_id`, timestamps still visible to server |
| **Forward secrecy** | Not provided (see Tier 2 for Signal protocol) |
| **Compromised key** | All past messages decryptable (no forward secrecy) |

### Dependency Addition

```toml
# pyproject.toml
dependencies = [
    # ... existing ...
    "pynacl>=1.5.0",
]
```

---

## Tier 2: Signal Protocol (Extension)

### Overview

The Signal Protocol provides:
- **Forward secrecy**: Compromised key doesn't reveal past messages
- **Post-compromise security**: System recovers after key compromise
- **Deniability**: Can't prove who sent a message

### Why Extension?

| Aspect | Tier 1 (NaCl) | Tier 2 (Signal) |
|--------|---------------|-----------------|
| **Complexity** | Low | High |
| **State** | Stateless | Requires session state |
| **Dependencies** | 1 (pynacl) | Multiple |
| **Use case** | Agent-to-agent, low volume | Human-like chat, high volume |
| **Key management** | Simple keypairs | Pre-keys, ratcheting |

### Architecture Sketch

```
deadrop[signal] extension package:
├── Signal library integration
├── Session state storage (local SQLite)
├── Pre-key management
├── CLI commands for session setup
```

### Required Components

1. **Pre-key bundle storage**: Server stores pre-keys for each identity
2. **Session state**: Client stores ratchet state per conversation
3. **Key exchange**: X3DH for initial key exchange
4. **Message encryption**: Double Ratchet for ongoing messages

### API Additions (Extension)

```bash
# Upload pre-key bundle
POST /{ns}/identities/{id}/prekeys
{
  "identity_key": "...",
  "signed_prekey": "...",
  "signature": "...",
  "one_time_prekeys": ["...", "..."]
}

# Fetch pre-key bundle for initiating session
GET /{ns}/identities/{id}/prekeys

# Send Signal-encrypted message
POST /{ns}/send
{
  "to": "...",
  "body": "...",
  "protocol": "signal",
  "signal_header": "..."
}
```

### Implementation Notes

**Possible libraries**:
- `python-axolotl-curve25519` - Curve25519 primitives
- Custom implementation using `pynacl` primitives
- Rust library with Python bindings

**Challenges**:
- Session state must persist between CLI invocations
- Pre-key replenishment
- Handling out-of-order messages
- Multi-device support (not in initial scope)

### Recommendation

Signal Protocol should be:
1. Separate pip package: `deadrop-signal`
2. Optional installation: `pip install deadrop[signal]`
3. Designed after Tier 1 is stable
4. Targeted at specific high-security use cases

---

## Implementation Roadmap

### Phase 1: Foundation (Tier 1)
- [ ] Add `pynacl` dependency
- [ ] Create `crypto/` module with key generation and box operations
- [ ] Add `public_key` column to identities table
- [ ] Add `encrypted`, `nonce` columns to messages table
- [ ] Update identity creation API to accept public key

### Phase 2: CLI Integration
- [ ] Add `--crypto` flag to `identity create`
- [ ] Add `identity keygen` command
- [ ] Add `identity pubkey` command
- [ ] Update `identity export` to include private key

### Phase 3: Message Encryption
- [ ] Add `GET /{ns}/identities/{id}/pubkey` endpoint
- [ ] Update `POST /{ns}/send` to accept encryption fields
- [ ] Update CLI `message send` with encryption logic
- [ ] Update CLI `message inbox` with decryption logic

### Phase 4: Polish
- [ ] Auto-encrypt when both parties have keys
- [ ] Helpful warnings/errors for key mismatches
- [ ] Documentation updates
- [ ] Comprehensive test coverage

### Future: Signal Protocol
- [ ] Design detailed specification
- [ ] Implement as separate package
- [ ] Integration tests with core deadrop

---

## Example Workflows

### Setting Up Encrypted Communication

```bash
# Admin creates namespace
deadrop ns create --display-name "Secure Project"
# Namespace: abc123

# Admin creates crypto-enabled identities
deadrop identity create abc123 --display-name "Alice" --crypto
# Identity: alice1, secret: ..., private_key: ...

deadrop identity create abc123 --display-name "Bob" --crypto
# Identity: bob123, secret: ..., private_key: ...

# Export and distribute credentials securely
deadrop identity export abc123 alice1 --format json > alice_creds.json
deadrop identity export abc123 bob123 --format json > bob_creds.json
```

### Sending Encrypted Message (Alice to Bob)

```bash
# Alice sends message (auto-encrypts)
deadrop message send abc123 bob123 "Secret plans for tomorrow"
# → Encrypting with Bob's public key...
# → Message sent (encrypted)

# Bob reads inbox (auto-decrypts)
deadrop message inbox abc123
# → Decrypting message from alice1...
# FROM: alice1 | Secret plans for tomorrow
```

### Programmatic Usage

```python
from deadrop.crypto import generate_keypair, encrypt_message, decrypt_message
import httpx

# Generate keys
alice_private, alice_public = generate_keypair()
bob_private, bob_public = generate_keypair()

# Alice encrypts for Bob
ciphertext, nonce = encrypt_message(
    "Hello Bob!",
    sender_private_key=alice_private,
    recipient_public_key=bob_public
)

# Send via API
httpx.post(f"{BASE_URL}/{ns}/send", json={
    "to": "bob123",
    "body": ciphertext,
    "encrypted": True,
    "nonce": nonce
}, headers={"X-Inbox-Secret": alice_secret})

# Bob decrypts
plaintext = decrypt_message(
    ciphertext_b64=ciphertext,
    nonce_b64=nonce,
    recipient_private_key=bob_private,
    sender_public_key=alice_public
)
```

---

## Security Analysis

### Threat Model

| Threat | Tier 1 Protection | Notes |
|--------|-------------------|-------|
| **Passive server compromise** | Yes | Server only sees ciphertext |
| **Active server MITM** | Partial | Need out-of-band key verification |
| **Stolen inbox secret** | No | Can still send as victim |
| **Stolen private key** | No | Can decrypt all past/future messages |
| **Database dump** | Yes | Messages encrypted |
| **Network eavesdropping** | Yes | Already encrypted before transmission |

### Limitations

1. **No key verification**: Users must verify public keys out-of-band
2. **No forward secrecy**: Compromised key reveals all messages
3. **Metadata visible**: Server sees who talks to whom, when
4. **No deniability**: Messages are authentically from sender
5. **Single device**: Private key on one machine only

### Comparison with Alternatives

| System | E2E | Forward Secrecy | Simplicity |
|--------|-----|-----------------|------------|
| **Deadrop + Tier 1** | Yes | No | High |
| **Deadrop + Tier 2** | Yes | Yes | Medium |
| **Signal** | Yes | Yes | Low (for servers) |
| **PGP/GPG** | Yes | No | Medium |
| **Age** | Yes | No | High |

---

## Open Questions

1. **Key discovery**: How do users verify they have the right public key?
   - Option A: Trust on first use (TOFU)
   - Option B: Out-of-band verification (fingerprints)
   - Option C: Admin-verified keys

2. **Mixed mode**: What happens when one party has keys and another doesn't?
   - Option A: Fail send
   - Option B: Send plaintext with warning
   - Option C: Configurable per-namespace policy

3. **Key backup**: Should we provide key backup/recovery?
   - Recommendation: No - keep it simple, users back up config files

4. **Server-side key generation**: Allow server to generate keypairs?
   - Recommendation: No - defeats purpose, but could be convenience option

---

## Conclusion

**Tier 1 (NaCl-based)** provides meaningful security improvements with minimal complexity:
- True end-to-end encryption
- Sender authentication
- Single, well-audited library
- Backwards compatible
- Easy to understand and audit

**Tier 2 (Signal Protocol)** should be deferred until:
- Tier 1 is battle-tested
- Clear use cases requiring forward secrecy emerge
- Resources available for complex implementation

The recommended next step is implementing Tier 1, starting with the crypto module and schema changes.
