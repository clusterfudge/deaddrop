"""FastAPI application for deadrop."""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import db
from .auth import derive_id
from .auth_provider import (
    extract_bearer_token,
    get_auth_method_name,
    is_auth_enabled,
    verify_bearer_token,
)


def is_no_auth_mode() -> bool:
    """Check if server is running in no-auth mode (for development)."""
    return os.environ.get("DEADROP_NO_AUTH", "").lower() in ("1", "true", "yes")


# Get the package directory for static files and templates
PACKAGE_DIR = Path(__file__).parent
STATIC_DIR = PACKAGE_DIR / "static"
TEMPLATES_DIR = PACKAGE_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup database."""
    db.init_db()
    yield
    db.close_db()


app = FastAPI(
    title="deadrop",
    description="Minimal inbox-only messaging for agents",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files if directory exists
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Initialize templates if directory exists
templates = Jinja2Templates(directory=TEMPLATES_DIR) if TEMPLATES_DIR.exists() else None


# --- Request/Response Models ---


class CreateNamespaceRequest(BaseModel):
    metadata: dict[str, Any] | None = None
    ttl_hours: int = 24
    slug: str | None = None


class CreateNamespaceResponse(BaseModel):
    ns: str
    secret: str
    slug: str | None
    metadata: dict[str, Any]
    ttl_hours: int


class NamespaceInfo(BaseModel):
    ns: str
    slug: str | None = None
    metadata: dict[str, Any]
    ttl_hours: int
    created_at: str
    archived_at: str | None = None


class CreateIdentityRequest(BaseModel):
    metadata: dict[str, Any] | None = None


class CreateIdentityResponse(BaseModel):
    id: str
    secret: str
    metadata: dict[str, Any]


class IdentityInfo(BaseModel):
    id: str
    metadata: dict[str, Any]
    created_at: str
    # Public key info (optional - present if identity has registered a key)
    pubkey_id: str | None = None
    public_key: str | None = None
    signing_public_key: str | None = None
    algorithm: str | None = None
    pubkey_version: int | None = None


class SetPubkeyRequest(BaseModel):
    public_key: str  # Base64-encoded X25519 public key
    signing_public_key: str  # Base64-encoded Ed25519 public key
    algorithm: str = "nacl-box"


class PubkeyInfo(BaseModel):
    pubkey_id: str
    ns: str
    identity_id: str
    public_key: str
    signing_public_key: str
    algorithm: str
    version: int
    created_at: str
    revoked_at: str | None = None


class UpdateMetadataRequest(BaseModel):
    metadata: dict[str, Any]


class EncryptionMeta(BaseModel):
    """Metadata for encrypted messages."""

    algorithm: str  # e.g., "nacl-box"
    recipient_pubkey_id: str  # Which key was used to encrypt


class SignatureMeta(BaseModel):
    """Metadata for signed messages."""

    algorithm: str  # e.g., "ed25519"
    sender_pubkey_id: str  # Which key signed
    value: str  # Base64-encoded signature


class SendMessageRequest(BaseModel):
    to: str
    body: str  # Plaintext OR base64-encoded ciphertext (if encrypted=True)
    content_type: str = (
        "text/plain"  # MIME type (e.g., text/plain, text/markdown, text/html, application/json)
    )
    ttl_hours: int | None = None  # Optional TTL override (ephemeral messages)
    encrypted: bool = False  # Whether body is encrypted
    encryption: EncryptionMeta | None = None  # Required if encrypted=True
    signature: SignatureMeta | None = None  # Optional signature


class MessageInfo(BaseModel):
    mid: str
    from_id: str
    to: str
    body: str
    content_type: str = "text/plain"
    created_at: str
    read_at: str | None
    expires_at: str | None
    archived_at: str | None = None
    encrypted: bool = False
    encryption: EncryptionMeta | None = None
    signature: SignatureMeta | None = None


class InviteClaimResponse(BaseModel):
    encrypted_secret: str
    ns: str
    namespace_slug: str | None
    namespace_display_name: str | None
    namespace_ttl_hours: int | None
    identity_id: str
    identity_display_name: str | None
    display_name: str | None


class InviteInfoResponse(BaseModel):
    invite_id: str
    ns: str
    namespace_slug: str | None = None
    namespace_display_name: str | None = None
    namespace_ttl_hours: int | None = None
    identity_id: str
    identity_display_name: str | None = None
    display_name: str | None = None
    created_at: str
    expires_at: str | None = None
    claimed_at: str | None = None


class CreateInviteRequest(BaseModel):
    identity_id: str
    invite_id: str  # Client provides this (used as AAD in encryption)
    encrypted_secret: str
    display_name: str | None = None
    expires_at: str | None = None


class CreateInviteResponse(BaseModel):
    invite_id: str
    ns: str
    identity_id: str
    display_name: str | None
    created_at: str
    expires_at: str | None


# --- Auth Helpers ---


def get_legacy_admin_token() -> str | None:
    """Get legacy admin token from environment (fallback when heare-auth not configured)."""
    return os.environ.get("DEADROP_ADMIN_TOKEN")


def require_admin(authorization: str | None, x_admin_token: str | None) -> dict:
    """
    Verify admin authentication.

    Supports multiple modes:
    1. No-auth: DEADROP_NO_AUTH=1 (for development, no auth required)
    2. Pluggable auth: DEADROP_AUTH_MODULE or HEARE_AUTH_URL (Bearer token)
    3. Legacy: X-Admin-Token header (fallback)

    Returns:
        dict with auth info: {"method": "...", "key_id": ..., "metadata": ...}
    """
    # Development mode - no auth required
    if is_no_auth_mode():
        return {"method": "no-auth", "key_id": None, "metadata": {}}

    # Try pluggable auth (includes heare-auth) if configured
    if is_auth_enabled():
        token = extract_bearer_token(authorization)
        if not token:
            raise HTTPException(401, "Authorization: Bearer <token> header required")

        result = verify_bearer_token(token)
        if not result.valid:
            raise HTTPException(403, result.error or "Invalid token")

        return {
            "method": get_auth_method_name(),
            "key_id": result.key_id,
            "name": result.name,
            "metadata": result.metadata,
        }

    # Fallback to legacy admin token
    legacy_token = get_legacy_admin_token()
    if not legacy_token:
        raise HTTPException(
            500,
            "No auth method configured. Set DEADROP_AUTH_MODULE, HEARE_AUTH_URL, "
            "or DEADROP_ADMIN_TOKEN",
        )

    if not x_admin_token:
        raise HTTPException(401, "X-Admin-Token header required")

    if x_admin_token != legacy_token:
        raise HTTPException(403, "Invalid admin token")

    return {"method": "legacy", "key_id": None, "metadata": {}}


def require_namespace_secret(ns: str, x_namespace_secret: str | None) -> None:
    """Verify namespace secret."""
    if not x_namespace_secret:
        raise HTTPException(401, "X-Namespace-Secret header required")
    if not db.verify_namespace_secret(ns, x_namespace_secret):
        raise HTTPException(403, "Invalid namespace secret")


def require_inbox_secret(ns: str, identity_id: str, x_inbox_secret: str | None) -> str:
    """Verify inbox secret matches identity. Returns the identity ID."""
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    # Derive ID from secret and verify it matches claimed identity
    derived_id = derive_id(x_inbox_secret)
    if derived_id != identity_id:
        raise HTTPException(403, "Secret does not match identity")

    # Verify identity exists in namespace
    if not db.verify_identity_secret(ns, identity_id, x_inbox_secret):
        raise HTTPException(403, "Invalid inbox secret or identity not in namespace")

    return identity_id


def require_inbox_secret_any(ns: str, x_inbox_secret: str | None) -> str:
    """Verify inbox secret belongs to some identity in namespace. Returns identity ID."""
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    identity_id = db.verify_identity_in_namespace(ns, x_inbox_secret)
    if not identity_id:
        raise HTTPException(403, "Invalid inbox secret or not in namespace")

    return identity_id


def require_active_namespace(ns: str) -> None:
    """Check that namespace exists and is not archived."""
    if db.is_namespace_archived(ns):
        raise HTTPException(410, "Namespace is archived")


# --- Admin Endpoints ---
# Admin can: CRUD namespaces, CRUD mailbox metadata (not contents)


@app.post("/admin/namespaces", response_model=CreateNamespaceResponse)
def create_namespace(
    request: CreateNamespaceRequest | None = None,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Create a new namespace."""
    auth_info = require_admin(authorization, x_admin_token)
    metadata = request.metadata if request else None
    ttl_hours = request.ttl_hours if request else 24
    slug = request.slug if request else None

    # Optionally include auth info in namespace metadata
    if auth_info.get("key_id"):
        metadata = metadata or {}
        metadata.setdefault("created_by", auth_info["key_id"])

    result = db.create_namespace(metadata, ttl_hours=ttl_hours, slug=slug)
    # ns and secret are always present strings, slug may be None
    ns = result["ns"]
    secret = result["secret"]
    assert ns is not None and secret is not None
    return CreateNamespaceResponse(
        ns=ns,
        secret=secret,
        slug=result.get("slug"),
        metadata=metadata or {},
        ttl_hours=ttl_hours,
    )


@app.get("/admin/namespaces", response_model=list[NamespaceInfo])
def list_namespaces(
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """List all namespaces."""
    require_admin(authorization, x_admin_token)
    return [NamespaceInfo(**ns) for ns in db.list_namespaces()]


@app.get("/admin/namespaces/{ns}", response_model=NamespaceInfo)
def get_namespace(
    ns: str,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Get namespace details."""
    require_admin(authorization, x_admin_token)
    namespace = db.get_namespace(ns)
    if namespace is None:
        raise HTTPException(404, "Namespace not found")
    return NamespaceInfo(**namespace)


@app.patch("/admin/namespaces/{ns}", response_model=NamespaceInfo)
def update_namespace(
    ns: str,
    request: UpdateMetadataRequest,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Update namespace metadata."""
    require_admin(authorization, x_admin_token)
    if not db.update_namespace_metadata(ns, request.metadata):
        raise HTTPException(404, "Namespace not found")
    namespace = db.get_namespace(ns)
    if namespace is None:
        raise HTTPException(404, "Namespace not found")
    return NamespaceInfo(**namespace)


@app.delete("/admin/namespaces/{ns}")
def delete_namespace(
    ns: str,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Delete a namespace and all its data (hard delete)."""
    require_admin(authorization, x_admin_token)
    if not db.delete_namespace(ns):
        raise HTTPException(404, "Namespace not found")
    return {"ok": True}


# Admin can also CRUD identities (metadata only, not inbox contents)
@app.post("/admin/{ns}/identities", response_model=CreateIdentityResponse)
def admin_create_identity(
    ns: str,
    request: CreateIdentityRequest | None = None,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Create identity as admin."""
    require_admin(authorization, x_admin_token)
    require_active_namespace(ns)

    # Verify namespace exists
    if not db.get_namespace(ns):
        raise HTTPException(404, "Namespace not found")

    metadata = request.metadata if request else None
    result = db.create_identity(ns, metadata)
    return CreateIdentityResponse(
        id=result["id"],
        secret=result["secret"],
        metadata=metadata or {},
    )


@app.get("/admin/{ns}/identities", response_model=list[IdentityInfo])
def admin_list_identities(
    ns: str,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """List identities as admin."""
    require_admin(authorization, x_admin_token)
    return [IdentityInfo(**identity) for identity in db.list_identities(ns)]


@app.delete("/admin/{ns}/identities/{identity_id}")
def admin_delete_identity(
    ns: str,
    identity_id: str,
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Delete identity as admin."""
    require_admin(authorization, x_admin_token)
    if not db.delete_identity(ns, identity_id):
        raise HTTPException(404, "Identity not found")
    return {"ok": True}


# --- Namespace Owner Endpoints ---
# NS owner can: archive own namespace, CRUD mailboxes (metadata only, not contents)


@app.post("/{ns}/archive")
def archive_namespace(
    ns: str,
    x_namespace_secret: Annotated[str | None, Header()] = None,
):
    """Archive namespace (soft-delete, rejects future writes)."""
    require_namespace_secret(ns, x_namespace_secret)

    if not db.archive_namespace(ns):
        raise HTTPException(400, "Namespace already archived or not found")

    return {"ok": True, "archived": True}


@app.post("/{ns}/identities", response_model=CreateIdentityResponse)
def create_identity(
    ns: str,
    request: CreateIdentityRequest | None = None,
    x_namespace_secret: Annotated[str | None, Header()] = None,
):
    """Create a new identity (mailbox) in a namespace."""
    require_namespace_secret(ns, x_namespace_secret)
    require_active_namespace(ns)

    metadata = request.metadata if request else None
    result = db.create_identity(ns, metadata)
    return CreateIdentityResponse(
        id=result["id"],
        secret=result["secret"],
        metadata=metadata or {},
    )


@app.get("/{ns}/identities", response_model=list[IdentityInfo])
def list_identities(
    ns: str,
    x_namespace_secret: Annotated[str | None, Header()] = None,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """
    List identities in namespace.

    - Namespace owner (X-Namespace-Secret): Full access
    - Mailbox owner (X-Inbox-Secret): Can list peers
    """
    # Either namespace secret OR inbox secret works
    if x_namespace_secret:
        if not db.verify_namespace_secret(ns, x_namespace_secret):
            raise HTTPException(403, "Invalid namespace secret")
    elif x_inbox_secret:
        if not db.verify_identity_in_namespace(ns, x_inbox_secret):
            raise HTTPException(403, "Invalid inbox secret or not in namespace")
    else:
        raise HTTPException(401, "X-Namespace-Secret or X-Inbox-Secret header required")

    return [IdentityInfo(**identity) for identity in db.list_identities(ns)]


@app.get("/{ns}/identities/{identity_id}", response_model=IdentityInfo)
def get_identity(
    ns: str,
    identity_id: str,
    x_namespace_secret: Annotated[str | None, Header()] = None,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get identity details.

    Requires authentication as either:
    - Namespace owner (X-Namespace-Secret)
    - Any identity in the namespace (X-Inbox-Secret) - for fetching peer pubkeys
    """
    # Either namespace secret OR any inbox secret in the namespace
    if x_namespace_secret:
        if not db.verify_namespace_secret(ns, x_namespace_secret):
            raise HTTPException(403, "Invalid namespace secret")
    elif x_inbox_secret:
        # Any identity in the namespace can view other identities (for pubkey exchange)
        if not db.verify_identity_in_namespace(ns, x_inbox_secret):
            raise HTTPException(403, "Invalid inbox secret for this namespace")
    else:
        raise HTTPException(401, "X-Namespace-Secret or X-Inbox-Secret header required")

    identity = db.get_identity(ns, identity_id)
    if identity is None:
        raise HTTPException(404, "Identity not found")
    return IdentityInfo(**identity)


@app.put("/{ns}/inbox/{identity_id}/pubkey", response_model=PubkeyInfo)
def set_pubkey(
    ns: str,
    identity_id: str,
    request: SetPubkeyRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Set or rotate public key for own identity.

    This endpoint allows the mailbox owner to register their public key
    for end-to-end encryption. If a key already exists, it will be rotated
    (old key revoked, new key becomes active).

    Requires X-Inbox-Secret header matching the identity.
    """
    # Only mailbox owner can set their pubkey
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    # Verify identity exists
    identity = db.get_identity(ns, identity_id)
    if identity is None:
        raise HTTPException(404, "Identity not found")

    # Create/rotate pubkey
    pubkey = db.create_pubkey(
        ns=ns,
        identity_id=identity_id,
        public_key=request.public_key,
        signing_public_key=request.signing_public_key,
        algorithm=request.algorithm,
    )

    return PubkeyInfo(**pubkey)


@app.get("/{ns}/identities/{identity_id}/pubkeys", response_model=list[PubkeyInfo])
def get_pubkey_history(
    ns: str,
    identity_id: str,
    x_namespace_secret: Annotated[str | None, Header()] = None,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get public key history for an identity.

    Returns all public keys (current and revoked) for key rotation scenarios.
    Useful for decrypting old messages encrypted with previous keys.
    """
    # Either namespace secret OR any inbox secret in the namespace
    if x_namespace_secret:
        if not db.verify_namespace_secret(ns, x_namespace_secret):
            raise HTTPException(403, "Invalid namespace secret")
    elif x_inbox_secret:
        # Any identity in the namespace can view pubkey history
        if not db.verify_identity_in_namespace(ns, x_inbox_secret):
            raise HTTPException(403, "Invalid inbox secret for this namespace")
    else:
        raise HTTPException(401, "X-Namespace-Secret or X-Inbox-Secret header required")

    history = db.get_pubkey_history(ns, identity_id)
    return [PubkeyInfo(**pk) for pk in history]


@app.patch("/{ns}/identities/{identity_id}", response_model=IdentityInfo)
def update_identity(
    ns: str,
    identity_id: str,
    request: UpdateMetadataRequest,
    x_namespace_secret: Annotated[str | None, Header()] = None,
):
    """Update identity metadata. Requires namespace secret."""
    require_namespace_secret(ns, x_namespace_secret)
    require_active_namespace(ns)

    if not db.update_identity_metadata(ns, identity_id, request.metadata):
        raise HTTPException(404, "Identity not found")

    identity = db.get_identity(ns, identity_id)
    if identity is None:
        raise HTTPException(404, "Identity not found")
    return IdentityInfo(**identity)


@app.delete("/{ns}/identities/{identity_id}")
def delete_identity(
    ns: str,
    identity_id: str,
    x_namespace_secret: Annotated[str | None, Header()] = None,
):
    """Delete an identity and all its messages. Requires namespace secret."""
    require_namespace_secret(ns, x_namespace_secret)

    if not db.delete_identity(ns, identity_id):
        raise HTTPException(404, "Identity not found")
    return {"ok": True}


# --- Mailbox Owner Endpoints ---
# Mailbox owner can: send messages, read own inbox, list peers


@app.post("/{ns}/send")
def send_message(
    ns: str,
    request: SendMessageRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Send a message to another identity.

    Messages are delivered instantly. Optionally set ttl_hours for ephemeral
    messages that expire from creation time (instead of read time).

    For encrypted messages, set encrypted=True and include encryption metadata.
    For signed messages, include signature metadata (recommended when sender has a keypair).
    """
    require_active_namespace(ns)

    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    from_id = db.verify_identity_in_namespace(ns, x_inbox_secret)
    if not from_id:
        raise HTTPException(403, "Invalid inbox secret or not in namespace")

    # Validate encryption metadata if encrypted
    if request.encrypted and not request.encryption:
        raise HTTPException(400, "encryption metadata required when encrypted=True")

    try:
        result = db.send_message(
            ns=ns,
            from_id=from_id,
            to_id=request.to,
            body=request.body,
            content_type=request.content_type,
            ttl_hours=request.ttl_hours,
            encrypted=request.encrypted,
            encryption_meta=request.encryption.model_dump() if request.encryption else None,
            signature=request.signature.value if request.signature else None,
            signature_meta=(
                {
                    "algorithm": request.signature.algorithm,
                    "sender_pubkey_id": request.signature.sender_pubkey_id,
                }
                if request.signature
                else None
            ),
        )
    except ValueError as e:
        raise HTTPException(404, str(e))

    return result


@app.get("/{ns}/inbox/{identity_id}")
async def get_inbox(
    ns: str,
    identity_id: str,
    unread: Annotated[bool, Query()] = False,
    after: Annotated[str | None, Query()] = None,
    wait: Annotated[int, Query(ge=0, le=60)] = 0,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get messages for own inbox.

    Reading messages marks them as read and starts the TTL countdown.

    Query parameters:
    - unread: Only return unread messages
    - after: Only return messages after this message ID (cursor for pagination)
    - wait: Long-poll timeout in seconds (0-60). If no messages, wait up to this
            many seconds for new messages before returning empty response.
    """
    import asyncio

    # Only mailbox owner can read their inbox
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    # Long-polling: wait for messages if none exist and wait > 0
    if wait > 0:
        poll_interval = 0.5  # Check every 500ms
        elapsed = 0.0

        while elapsed < wait:
            # Check if messages exist (lightweight query)
            if db.has_new_messages(ns, identity_id, after_mid=after, unread_only=unread):
                break
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

    # Fetch and return messages
    messages = db.get_messages(
        ns=ns,
        identity_id=identity_id,
        unread_only=unread,
        after_mid=after,
    )

    return {
        "messages": [
            {
                "mid": m["mid"],
                "from": m["from"],
                "to": m["to"],
                "body": m["body"],
                "content_type": m.get("content_type", "text/plain"),
                "created_at": m["created_at"],
                "read_at": m["read_at"],
                "expires_at": m["expires_at"],
                "archived_at": m.get("archived_at"),
                "encrypted": m.get("encrypted", False),
                "encryption": m.get("encryption_meta"),
                "signature": m.get("signature_meta"),
            }
            for m in messages
        ]
    }


@app.get("/{ns}/inbox/{identity_id}/archived")
def get_archived_messages_endpoint(
    ns: str,
    identity_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get archived messages for own inbox."""
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    messages = db.get_archived_messages(ns=ns, identity_id=identity_id)

    return {
        "messages": [
            {
                "mid": m["mid"],
                "from": m["from"],
                "to": m["to"],
                "body": m["body"],
                "content_type": m.get("content_type", "text/plain"),
                "created_at": m["created_at"],
                "read_at": m["read_at"],
                "expires_at": m["expires_at"],
                "archived_at": m["archived_at"],
                "encrypted": m.get("encrypted", False),
                "encryption": m.get("encryption_meta"),
                "signature": m.get("signature_meta"),
            }
            for m in messages
        ]
    }


@app.get("/{ns}/inbox/{identity_id}/{mid}")
def get_message_endpoint(
    ns: str,
    identity_id: str,
    mid: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get a single message from own inbox."""
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    message = db.get_message(ns, identity_id, mid)
    if not message:
        raise HTTPException(404, "Message not found")

    return {
        "mid": message["mid"],
        "from": message["from"],
        "to": message["to"],
        "body": message["body"],
        "content_type": message.get("content_type", "text/plain"),
        "encrypted": message.get("encrypted", False),
        "encryption": message.get("encryption_meta"),
        "signature": message.get("signature_meta"),
        "created_at": message["created_at"],
        "read_at": message["read_at"],
        "expires_at": message["expires_at"],
        "archived_at": message.get("archived_at"),
    }


@app.post("/{ns}/inbox/{identity_id}/{mid}/archive")
def archive_message(
    ns: str,
    identity_id: str,
    mid: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Archive a message (hide from inbox but preserve)."""
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    if not db.archive_message(ns, identity_id, mid):
        raise HTTPException(404, "Message not found or already archived")

    return {"ok": True}


@app.post("/{ns}/inbox/{identity_id}/{mid}/unarchive")
def unarchive_message(
    ns: str,
    identity_id: str,
    mid: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Unarchive a message (restore to inbox)."""
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    if not db.unarchive_message(ns, identity_id, mid):
        raise HTTPException(404, "Message not found")

    return {"ok": True}


@app.delete("/{ns}/inbox/{identity_id}/{mid}")
def delete_message_endpoint(
    ns: str,
    identity_id: str,
    mid: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Delete a message from own inbox immediately."""
    require_inbox_secret(ns, identity_id, x_inbox_secret)

    if not db.delete_message(ns, identity_id, mid):
        raise HTTPException(404, "Message not found")

    return {"ok": True}


# --- Invite Endpoints ---


@app.get("/{ns}/invites")
def list_invites(
    ns: str,
    include_claimed: bool = False,
    x_namespace_secret: str | None = Header(None),
):
    """List invites for a namespace.

    Requires namespace secret authentication.
    """
    namespace = db.get_namespace(ns)
    if not namespace:
        raise HTTPException(404, "Namespace not found")

    if not x_namespace_secret:
        raise HTTPException(401, "X-Namespace-Secret header required")

    if not db.verify_namespace_secret(ns, x_namespace_secret):
        raise HTTPException(403, "Invalid namespace secret")

    invites = db.list_invites(ns, include_claimed=include_claimed)
    return invites


@app.delete("/{ns}/invites/{invite_id}")
def revoke_invite(
    ns: str,
    invite_id: str,
    x_namespace_secret: str | None = Header(None),
):
    """Revoke (delete) an invite.

    Requires namespace secret authentication.
    """
    namespace = db.get_namespace(ns)
    if not namespace:
        raise HTTPException(404, "Namespace not found")

    if not x_namespace_secret:
        raise HTTPException(401, "X-Namespace-Secret header required")

    if not db.verify_namespace_secret(ns, x_namespace_secret):
        raise HTTPException(403, "Invalid namespace secret")

    if db.revoke_invite(invite_id):
        return {"status": "ok", "invite_id": invite_id}
    else:
        raise HTTPException(404, "Invite not found")


@app.post("/{ns}/invites", response_model=CreateInviteResponse)
def create_invite(
    ns: str,
    req: CreateInviteRequest,
    x_namespace_secret: str | None = Header(None),
):
    """Create an invite for an identity in a namespace.

    Requires namespace secret authentication.
    The client must generate the invite_id and encrypt the secret before calling this.
    """
    # Verify namespace secret
    namespace = db.get_namespace(ns)
    if not namespace:
        raise HTTPException(404, "Namespace not found")

    if not x_namespace_secret:
        raise HTTPException(401, "X-Namespace-Secret header required")

    if not db.verify_namespace_secret(ns, x_namespace_secret):
        raise HTTPException(403, "Invalid namespace secret")

    # Verify identity exists
    identity = db.get_identity(ns, req.identity_id)
    if not identity:
        raise HTTPException(404, "Identity not found")

    # Use client-provided invite_id (needed because it's used as AAD in encryption)
    # Client generates this randomly, we just need to ensure uniqueness
    invite_id = req.invite_id

    # Create the invite
    result = db.create_invite(
        invite_id=invite_id,
        ns=ns,
        identity_id=req.identity_id,
        encrypted_secret=req.encrypted_secret,
        display_name=req.display_name,
        expires_at=req.expires_at,
    )

    return CreateInviteResponse(**result)


@app.get("/api/invites/{invite_id}/info", response_model=InviteInfoResponse)
def get_invite_info(invite_id: str):
    """Get public info about an invite (no auth required, no secrets returned)."""
    invite = db.get_invite_info(invite_id)
    if not invite:
        raise HTTPException(404, "Invite not found")

    if invite.get("claimed_at"):
        raise HTTPException(410, "Invite already claimed")

    return InviteInfoResponse(**invite)


@app.post("/api/invites/{invite_id}/claim", response_model=InviteClaimResponse)
def claim_invite(invite_id: str, request: Request):
    """Claim an invite and receive the encrypted secret.

    This is a one-time operation. After claiming, the invite cannot be used again.
    The response includes encrypted_secret which the client decrypts using
    the key from the URL fragment.
    """
    # Get client IP for logging
    client_ip = request.client.host if request.client else None

    invite = db.claim_invite(invite_id, claimed_by=client_ip)
    if not invite:
        # Check if it exists but was already claimed
        existing = db.get_invite(invite_id)
        if existing and existing.get("claimed_at"):
            raise HTTPException(410, "Invite already claimed")
        elif existing:
            raise HTTPException(410, "Invite expired")
        else:
            raise HTTPException(404, "Invite not found")

    return InviteClaimResponse(
        encrypted_secret=invite["encrypted_secret"],
        ns=invite["ns"],
        namespace_slug=invite.get("namespace_slug"),
        namespace_display_name=invite.get("namespace_display_name"),
        namespace_ttl_hours=invite.get("namespace_ttl_hours"),
        identity_id=invite["identity_id"],
        identity_display_name=invite.get("identity_display_name"),
        display_name=invite.get("display_name"),
    )


# --- Room API Models ---


class CreateRoomRequest(BaseModel):
    display_name: str | None = None
    encryption_enabled: bool = False


class RoomInfo(BaseModel):
    room_id: str
    ns: str
    display_name: str | None
    created_by: str
    created_at: str
    encryption_enabled: bool = False
    current_epoch_number: int = 0


class RoomWithMemberInfo(BaseModel):
    room_id: str
    ns: str
    display_name: str | None
    created_by: str
    created_at: str
    joined_at: str
    last_read_mid: str | None
    encryption_enabled: bool = False
    current_epoch_number: int = 0


class AddRoomMemberRequest(BaseModel):
    identity_id: str


class RoomMemberInfo(BaseModel):
    room_id: str
    identity_id: str
    ns: str
    joined_at: str
    last_read_mid: str | None
    metadata: dict[str, Any]


class SendRoomMessageRequest(BaseModel):
    body: str
    content_type: str = "text/plain"
    # Encryption fields (optional, for encrypted messages)
    epoch_number: int | None = None
    encrypted: bool = False
    encryption_meta: str | None = None
    signature: str | None = None


class RoomMessageInfo(BaseModel):
    mid: str
    room_id: str
    from_id: str  # The sender's identity ID
    body: str
    content_type: str
    created_at: str
    # Encryption fields (optional, only present for encrypted messages)
    encrypted: bool | None = None
    epoch_number: int | None = None
    encryption_meta: str | None = None
    signature: str | None = None

    @classmethod
    def from_db(cls, data: dict) -> "RoomMessageInfo":
        """Create from db result which uses 'from' key."""
        msg = cls(
            mid=data["mid"],
            room_id=data["room_id"],
            from_id=data["from"],
            body=data["body"],
            content_type=data.get("content_type", "text/plain"),
            created_at=data["created_at"],
        )
        # Include encryption fields if present
        if data.get("encrypted"):
            msg.encrypted = True
            msg.epoch_number = data.get("epoch_number")
            msg.encryption_meta = data.get("encryption_meta")
            msg.signature = data.get("signature")
        return msg


class UpdateReadCursorRequest(BaseModel):
    last_read_mid: str


# --- Room Encryption Models ---


class EpochInfo(BaseModel):
    """Information about a room epoch."""

    epoch_id: str
    room_id: str
    epoch_number: int
    membership_hash: str
    reason: str
    triggered_by: str | None
    created_at: str


class EpochKeyResponse(BaseModel):
    """Response containing epoch info and the caller's encrypted key."""

    epoch: EpochInfo
    encrypted_epoch_key: str | None  # Base64 NaCl box ciphertext, None if caller not in epoch
    distributor_public_key: str | None = None  # Server's public key used to encrypt epoch keys


class RoomMessageEncryptedRequest(BaseModel):
    """Request to send an encrypted room message."""

    body: str  # Encrypted ciphertext
    content_type: str = "text/plain"
    epoch_number: int
    encrypted: bool = True
    encryption_meta: str | None = None  # JSON with algorithm, nonce
    signature: str | None = None  # Base64 Ed25519 signature


class EpochMismatchResponse(BaseModel):
    """Response when epoch mismatch occurs (409 Conflict)."""

    error: str = "epoch_mismatch"
    expected_epoch: int
    provided_epoch: int
    room_id: str


# --- Room Helper Functions ---


def require_room_member(room_id: str, x_inbox_secret: str | None) -> tuple[dict, str]:
    """Verify caller is a member of the room. Returns (room, identity_id)."""
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    room = db.get_room(room_id)
    if not room:
        raise HTTPException(404, "Room not found")

    # Derive identity from secret
    identity_id = derive_id(x_inbox_secret)

    # Verify identity is a member
    if not db.is_room_member(room_id, identity_id):
        raise HTTPException(403, "Not a member of this room")

    # Verify identity exists in namespace
    if not db.verify_identity_secret(room["ns"], identity_id, x_inbox_secret):
        raise HTTPException(403, "Invalid inbox secret")

    return room, identity_id


# --- Room Endpoints ---


@app.post("/{ns}/rooms", response_model=RoomInfo)
def create_room(
    ns: str,
    request: CreateRoomRequest | None = None,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Create a new room in a namespace.

    The caller becomes the first member of the room.
    Requires inbox secret of an identity in the namespace.

    If encryption_enabled=True, the room will use E2E encryption.
    The creator must have a registered pubkey.
    """
    require_active_namespace(ns)

    # Verify caller is in namespace
    created_by = require_inbox_secret_any(ns, x_inbox_secret)

    display_name = request.display_name if request else None
    encryption_enabled = request.encryption_enabled if request else False

    try:
        room = db.create_room(ns, created_by, display_name=display_name)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Initialize encryption if requested
    if encryption_enabled:
        from .crypto import generate_keypair, generate_room_base_secret

        # Verify creator has a pubkey
        identity = db.get_identity(ns, created_by)
        if not identity or not identity.get("pubkey_id"):
            # Delete the room we just created since we can't enable encryption
            db.delete_room(room["room_id"])
            raise HTTPException(
                400, "Creator must have a registered pubkey to create an encrypted room"
            )

        # Generate room base secret and initialize encryption
        base_secret = generate_room_base_secret()
        server_keypair = generate_keypair()

        db.initialize_room_encryption(
            room_id=room["room_id"],
            base_secret=base_secret,
            triggered_by=created_by,
            server_keypair=(server_keypair.private_key, server_keypair.public_key),
        )

        # Get updated room info with encryption status
        room_updated = db.get_room_with_encryption(room["room_id"])
        if room_updated:
            room = room_updated

    return RoomInfo(**room)


@app.get("/{ns}/rooms", response_model=list[RoomWithMemberInfo])
def list_my_rooms(
    ns: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """List rooms that the caller is a member of.

    Returns rooms with membership info (joined_at, last_read_mid).
    """
    identity_id = require_inbox_secret_any(ns, x_inbox_secret)

    rooms = db.list_rooms_for_identity(ns, identity_id)
    return [RoomWithMemberInfo(**r) for r in rooms]


@app.get("/{ns}/rooms/{room_id}", response_model=RoomInfo)
def get_room(
    ns: str,
    room_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get room details. Requires membership."""
    room, _ = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    # Get full room info with encryption status
    room_full = db.get_room_with_encryption(room_id)
    if not room_full:
        raise HTTPException(404, "Room not found")
    return RoomInfo(**room_full)


@app.delete("/{ns}/rooms/{room_id}")
def delete_room_endpoint(
    ns: str,
    room_id: str,
    x_namespace_secret: Annotated[str | None, Header()] = None,
):
    """Delete a room and all its messages/members.

    Requires namespace secret (only namespace owner can delete rooms).
    """
    require_namespace_secret(ns, x_namespace_secret)

    room = db.get_room(room_id)
    if not room or room["ns"] != ns:
        raise HTTPException(404, "Room not found")

    db.delete_room(room_id)
    return {"ok": True}


@app.get("/{ns}/rooms/{room_id}/members", response_model=list[RoomMemberInfo])
def list_room_members(
    ns: str,
    room_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """List members of a room. Requires membership."""
    room, _ = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    members = db.list_room_members(room_id)
    return [RoomMemberInfo(**m) for m in members]


@app.post("/{ns}/rooms/{room_id}/members")
def add_room_member(
    ns: str,
    room_id: str,
    request: AddRoomMemberRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Add a member to a room.

    Any room member can invite other identities from the same namespace.
    For encrypted rooms, the invitee must have a registered pubkey.
    Adding a member to an encrypted room triggers epoch rotation.
    """
    room, _ = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    try:
        db.add_room_member(room_id, request.identity_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Get full member info with metadata
    member_info = db.get_room_member_info(room_id, request.identity_id)
    if not member_info:
        raise HTTPException(500, "Failed to get member info")

    # For encrypted rooms, include epoch info in response
    room_info = db.get_room_with_encryption(room_id)
    if room_info and room_info.get("encryption_enabled"):
        return {
            "member": RoomMemberInfo(**member_info).model_dump(),
            "current_epoch_number": room_info["current_epoch_number"],
        }

    return RoomMemberInfo(**member_info)


class RemoveMemberResponse(BaseModel):
    """Response for member removal."""

    ok: bool = True
    immediate: bool = False
    pending: bool = False
    pending_removal_id: str | None = None
    pending_removal_at: str | None = None
    current_epoch_number: int | None = None
    message: str | None = None


@app.delete("/{ns}/rooms/{room_id}/members/{identity_id}")
def remove_room_member(
    ns: str,
    room_id: str,
    identity_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Remove a member from a room.

    Members can remove themselves. Namespace owner can remove anyone.

    For E2E encrypted rooms, removal uses a two-phase protocol:
    1. This endpoint marks the member as "pending removal" (returns 202)
    2. A remaining member must rotate the secret with fresh randomness
    3. The rotation finalizes the removal

    For server-mediated encrypted rooms, removal is immediate with HKDF rotation.

    Returns:
        200 with ok=True for immediate removal
        202 with pending=True for two-phase (E2E) removal
    """
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    room = db.get_room(room_id)
    if not room or room["ns"] != ns:
        raise HTTPException(404, "Room not found")

    caller_id = derive_id(x_inbox_secret)

    # Verify caller is either the member being removed or a room member
    if caller_id != identity_id:
        # Must be a member to remove others
        if not db.is_room_member(room_id, caller_id):
            raise HTTPException(403, "Not authorized to remove members")

    # Perform removal (may be immediate or pending depending on room type)
    result = db.remove_room_member(room_id, identity_id)

    if result.get("error"):
        if result["error"] == "not_member":
            raise HTTPException(404, "Member not found")
        elif result["error"] == "room_not_found":
            raise HTTPException(404, "Room not found")
        else:
            raise HTTPException(400, result["error"])

    # Two-phase pending removal (E2E rooms)
    if result.get("pending"):
        return Response(
            content=RemoveMemberResponse(
                ok=True,
                pending=True,
                pending_removal_id=result["pending_removal_id"],
                pending_removal_at=result["pending_removal_at"],
                message=result.get("message"),
            ).model_dump_json(),
            status_code=202,
            media_type="application/json",
        )

    # Immediate removal
    room_info = db.get_room_with_encryption(room_id)
    return RemoveMemberResponse(
        ok=True,
        immediate=True,
        current_epoch_number=room_info["current_epoch_number"] if room_info else None,
    )


@app.post("/{ns}/rooms/{room_id}/cancel-exit")
def cancel_pending_exit(
    ns: str,
    room_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Cancel a pending exit request.

    Only the member who requested to leave can cancel their exit.
    """
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    room = db.get_room(room_id)
    if not room or room["ns"] != ns:
        raise HTTPException(404, "Room not found")

    caller_id = derive_id(x_inbox_secret)

    # Check pending removal
    pending = db.get_pending_removal(room_id)
    if not pending:
        raise HTTPException(404, "No pending exit to cancel")

    # Only the pending member can cancel
    if pending["pending_removal_id"] != caller_id:
        raise HTTPException(403, "Only the exiting member can cancel their exit")

    db.clear_pending_removal(room_id)
    return {"ok": True, "cancelled": True}


@app.get("/{ns}/rooms/{room_id}/messages")
async def get_room_messages(
    ns: str,
    room_id: str,
    after: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    wait: Annotated[int, Query(ge=0, le=60)] = 0,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get messages from a room.

    Query parameters:
    - after: Only return messages after this message ID (for pagination/polling)
    - limit: Maximum number of messages to return (default: 100, max: 1000)
    - wait: Long-poll timeout in seconds (0-60). If no messages, wait up to this
            many seconds for new messages before returning empty response.
    """
    import asyncio

    room, identity_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    # Long-polling: wait for messages if none exist and wait > 0
    if wait > 0:
        poll_interval = 0.5
        elapsed = 0.0

        while elapsed < wait:
            if db.has_new_room_messages(room_id, after_mid=after):
                break
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

    messages = db.get_room_messages(room_id, after_mid=after, limit=limit)

    return {
        "messages": [RoomMessageInfo.from_db(m).model_dump() for m in messages],
        "room_id": room_id,
    }


@app.post("/{ns}/rooms/{room_id}/messages", response_model=RoomMessageInfo)
def send_room_message(
    ns: str,
    room_id: str,
    request: SendRoomMessageRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Send a message to a room. Requires membership.

    For encrypted rooms, include:
    - epoch_number: The epoch used to encrypt
    - encrypted: True
    - encryption_meta: JSON with algorithm info
    - signature: Ed25519 signature

    Returns 409 Conflict if epoch_number doesn't match current epoch.
    """
    room, from_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    try:
        message = db.send_room_message(
            room_id=room_id,
            from_id=from_id,
            body=request.body,
            content_type=request.content_type,
            epoch_number=request.epoch_number,
            encrypted=request.encrypted,
            encryption_meta=request.encryption_meta,
            signature=request.signature,
        )
    except db.EpochMismatchError as e:
        # Return 409 Conflict with epoch info for client retry
        raise HTTPException(
            409,
            detail={
                "error": "epoch_mismatch",
                "expected_epoch": e.expected_epoch,
                "provided_epoch": e.provided_epoch,
                "room_id": e.room_id,
            },
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return RoomMessageInfo.from_db(message)


@app.post("/{ns}/rooms/{room_id}/read")
def update_read_cursor(
    ns: str,
    room_id: str,
    request: UpdateReadCursorRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Update the read cursor for the calling user.

    The cursor tracks the last message the user has read.
    """
    room, identity_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    result = db.update_room_read_cursor(room_id, identity_id, request.last_read_mid)
    if not result:
        raise HTTPException(400, "Failed to update read cursor")

    return {"ok": True, "last_read_mid": request.last_read_mid}


@app.get("/{ns}/rooms/{room_id}/unread")
def get_unread_count(
    ns: str,
    room_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get the count of unread messages for the calling user."""
    room, identity_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    count = db.get_room_unread_count(room_id, identity_id)
    return {"unread_count": count, "room_id": room_id}


# --- Room Encryption Endpoints ---


@app.get("/{ns}/rooms/{room_id}/epoch", response_model=EpochKeyResponse)
def get_current_epoch(
    ns: str,
    room_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get the current epoch info and caller's encrypted key.

    For encrypted rooms, this returns the current epoch information
    along with the caller's encrypted epoch key (if they have one).
    """
    room, identity_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    # Check if room has encryption
    room_info = db.get_room_with_encryption(room_id)
    if not room_info or not room_info.get("encryption_enabled"):
        raise HTTPException(400, "Room does not have encryption enabled")

    # Get current epoch
    epoch = db.get_current_epoch(room_id)
    if not epoch:
        raise HTTPException(404, "No epochs found for this room")

    # Get caller's encrypted key for this epoch
    key_record = db.get_epoch_key_for_identity(room_id, epoch["epoch_number"], identity_id)
    encrypted_key = key_record["encrypted_epoch_key"] if key_record else None

    # Get server's public key for decryption
    distributor_public_key = room_info.get("server_public_key") if room_info else None

    return EpochKeyResponse(
        epoch=EpochInfo(**epoch),
        encrypted_epoch_key=encrypted_key,
        distributor_public_key=distributor_public_key,
    )


@app.get("/{ns}/rooms/{room_id}/epoch/{epoch_number}", response_model=EpochKeyResponse)
def get_epoch_by_number(
    ns: str,
    room_id: str,
    epoch_number: int,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get a specific epoch info and caller's encrypted key.

    Use this to fetch epoch keys for decrypting older messages.
    """
    room, identity_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    # Check if room has encryption
    room_info = db.get_room_with_encryption(room_id)
    if not room_info or not room_info.get("encryption_enabled"):
        raise HTTPException(400, "Room does not have encryption enabled")

    # Get specific epoch
    epoch = db.get_epoch_by_number(room_id, epoch_number)
    if not epoch:
        raise HTTPException(404, f"Epoch {epoch_number} not found")

    # Get caller's encrypted key for this epoch
    key_record = db.get_epoch_key_for_identity(room_id, epoch_number, identity_id)
    encrypted_key = key_record["encrypted_epoch_key"] if key_record else None

    # Get server's public key for decryption
    distributor_public_key = room_info.get("server_public_key") if room_info else None

    return EpochKeyResponse(
        epoch=EpochInfo(**epoch),
        encrypted_epoch_key=encrypted_key,
        distributor_public_key=distributor_public_key,
    )


class MemberSecretInput(BaseModel):
    """Encrypted secret for one member."""

    identity_id: str
    encrypted_base_secret: str  # Base64-encoded encrypted secret
    inviter_public_key: str  # Base64-encoded public key of inviter


class RotateSecretE2ERequest(BaseModel):
    """Request to rotate room secret in E2E mode."""

    new_secret_version: int
    member_secrets: list[MemberSecretInput]
    finalize_removal: str | None = None  # If set, completes a two-phase exit


class RotateSecretE2EResponse(BaseModel):
    """Response from E2E secret rotation."""

    room_id: str
    secret_version: int
    member_count: int
    removed_member: str | None = None


@app.post("/{ns}/rooms/{room_id}/rotate-secret", response_model=RotateSecretE2EResponse)
def rotate_room_secret_e2e(
    ns: str,
    room_id: str,
    request: RotateSecretE2ERequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Rotate room secret in E2E mode with client-provided encrypted secrets.

    This is used in true E2E mode where the server never sees plaintext secrets.
    The caller provides pre-encrypted secrets for each remaining member.

    If finalize_removal is set, this completes a two-phase exit:
    1. The pending member is excluded from member_secrets
    2. After successful rotation, the removal is finalized

    Only room members can trigger rotation.
    """
    room, caller_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    # Check if room has encryption
    room_info = db.get_room_with_encryption(room_id)
    if not room_info or not room_info.get("encryption_enabled"):
        raise HTTPException(400, "Room does not have encryption enabled")

    # Check if this is an E2E room (no base_secret stored)
    if room_info.get("base_secret"):
        raise HTTPException(
            400,
            "This room uses server-mediated encryption. Use POST /rotate instead.",
        )

    try:
        result = db.rotate_room_secret_e2e(
            room_id=room_id,
            new_secret_version=request.new_secret_version,
            member_secrets=[s.model_dump() for s in request.member_secrets],
            triggered_by=caller_id,
            finalize_removal=request.finalize_removal,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return RotateSecretE2EResponse(
        room_id=result["room_id"],
        secret_version=result["secret_version"],
        member_count=result["member_count"],
        removed_member=result.get("removed_member"),
    )


@app.post("/{ns}/rooms/{room_id}/rotate", response_model=EpochKeyResponse)
def rotate_room_epoch(
    ns: str,
    room_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Manually rotate the room's epoch key.

    Only the room creator can trigger manual rotation.
    This is useful after a potential key compromise.
    """
    room, identity_id = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    # Only room creator can rotate
    if room.get("created_by") != identity_id:
        raise HTTPException(403, "Only room creator can trigger manual rotation")

    # Check if room has encryption
    room_info = db.get_room_with_encryption(room_id)
    if not room_info or not room_info.get("encryption_enabled"):
        raise HTTPException(400, "Room does not have encryption enabled")

    try:
        result = db.rotate_room_epoch(
            room_id=room_id,
            reason="manual",
            triggered_by=identity_id,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Get caller's encrypted key for the new epoch
    key_record = db.get_epoch_key_for_identity(
        room_id, result["epoch"]["epoch_number"], identity_id
    )
    encrypted_key = key_record["encrypted_epoch_key"] if key_record else None

    return EpochKeyResponse(
        epoch=EpochInfo(**result["epoch"]),
        encrypted_epoch_key=encrypted_key,
        distributor_public_key=result.get("server_public_key"),
    )


# --- Web App Routes ---


@app.get("/", response_class=HTMLResponse)
def landing_page(request: Request):
    """Landing page."""
    if templates:
        return templates.TemplateResponse("landing.html", {"request": request})
    return HTMLResponse("<h1>Deadrop</h1><p>Minimal inbox-only messaging for agents.</p>")


@app.get("/join/{invite_id}", response_class=HTMLResponse)
def join_page(request: Request, invite_id: str):
    """Invite redemption page."""
    if templates:
        # Get invite info for display (but not secrets)
        invite = db.get_invite_info(invite_id)
        return templates.TemplateResponse(
            "join.html",
            {
                "request": request,
                "invite_id": invite_id,
                "invite": invite,
            },
        )
    return HTMLResponse(f"<h1>Join Invite</h1><p>Invite ID: {invite_id}</p>")


@app.get("/app", response_class=HTMLResponse)
def app_page(request: Request):
    """Main web app - namespace list."""
    if templates:
        return templates.TemplateResponse("app.html", {"request": request})
    return HTMLResponse("<h1>Deadrop App</h1><p>Web interface coming soon.</p>")


@app.get("/app/{slug}", response_class=HTMLResponse)
def app_namespace_page(request: Request, slug: str):
    """Web app - inbox view for a namespace."""
    if templates:
        return templates.TemplateResponse(
            "app.html",
            {
                "request": request,
                "slug": slug,
            },
        )
    return HTMLResponse(f"<h1>Deadrop App</h1><p>Namespace: {slug}</p>")


@app.get("/app/{slug}/{peer_id}", response_class=HTMLResponse)
def app_conversation_page(request: Request, slug: str, peer_id: str):
    """Web app - conversation view with a peer."""
    if templates:
        return templates.TemplateResponse(
            "app.html",
            {
                "request": request,
                "slug": slug,
                "peer_id": peer_id,
            },
        )
    return HTMLResponse(f"<h1>Conversation</h1><p>With: {peer_id}</p>")


@app.get("/app/{slug}/archived", response_class=HTMLResponse)
def app_archived_page(request: Request, slug: str):
    """Web app - archived messages view."""
    if templates:
        return templates.TemplateResponse(
            "app.html",
            {
                "request": request,
                "slug": slug,
                "view": "archived",
            },
        )
    return HTMLResponse(f"<h1>Archived Messages</h1><p>Namespace: {slug}</p>")


@app.get("/app/{slug}/settings", response_class=HTMLResponse)
def app_settings_page(request: Request, slug: str):
    """Web app - namespace settings."""
    if templates:
        return templates.TemplateResponse(
            "app.html",
            {
                "request": request,
                "slug": slug,
                "view": "settings",
            },
        )
    return HTMLResponse(f"<h1>Settings</h1><p>Namespace: {slug}</p>")


# --- Health Check ---


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}
