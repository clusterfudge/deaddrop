"""FastAPI application for deadrop."""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import db
from .auth import derive_id
from .heare_auth import (
    extract_bearer_token,
    is_heare_auth_enabled,
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


class UpdateMetadataRequest(BaseModel):
    metadata: dict[str, Any]


class SendMessageRequest(BaseModel):
    to: str
    body: str
    ttl_hours: int | None = None  # Optional TTL override (ephemeral messages)


class MessageInfo(BaseModel):
    mid: str
    from_id: str
    to: str
    body: str
    created_at: str
    read_at: str | None
    expires_at: str | None
    archived_at: str | None = None


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


# --- Auth Helpers ---


def get_legacy_admin_token() -> str | None:
    """Get legacy admin token from environment (fallback when heare-auth not configured)."""
    return os.environ.get("DEADROP_ADMIN_TOKEN")


def require_admin(authorization: str | None, x_admin_token: str | None) -> dict:
    """
    Verify admin authentication.

    Supports three modes:
    1. No-auth: DEADROP_NO_AUTH=1 (for development, no auth required)
    2. heare-auth: Authorization: Bearer <token> (if HEARE_AUTH_URL is set)
    3. Legacy: X-Admin-Token header (fallback)

    Returns:
        dict with auth info: {"method": "no-auth"|"heare-auth"|"legacy", "key_id": ..., "metadata": ...}
    """
    # Development mode - no auth required
    if is_no_auth_mode():
        return {"method": "no-auth", "key_id": None, "metadata": {}}

    # Try heare-auth first if configured
    if is_heare_auth_enabled():
        token = extract_bearer_token(authorization)
        if not token:
            raise HTTPException(401, "Authorization: Bearer <token> header required")

        result = verify_bearer_token(token)
        if not result.valid:
            raise HTTPException(403, result.error or "Invalid token")

        return {
            "method": "heare-auth",
            "key_id": result.key_id,
            "name": result.name,
            "metadata": result.metadata,
        }

    # Fallback to legacy admin token
    legacy_token = get_legacy_admin_token()
    if not legacy_token:
        raise HTTPException(
            500, "No auth method configured (set HEARE_AUTH_URL or DEADROP_ADMIN_TOKEN)"
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
    """Get identity details."""
    # Either namespace secret OR matching inbox secret
    if x_namespace_secret:
        if not db.verify_namespace_secret(ns, x_namespace_secret):
            raise HTTPException(403, "Invalid namespace secret")
    elif x_inbox_secret:
        # Must be this identity's secret
        derived_id = derive_id(x_inbox_secret)
        if derived_id != identity_id:
            raise HTTPException(403, "Can only view own identity")
        if not db.verify_identity_secret(ns, identity_id, x_inbox_secret):
            raise HTTPException(403, "Invalid inbox secret")
    else:
        raise HTTPException(401, "X-Namespace-Secret or X-Inbox-Secret header required")

    identity = db.get_identity(ns, identity_id)
    if identity is None:
        raise HTTPException(404, "Identity not found")
    return IdentityInfo(**identity)


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
    """
    require_active_namespace(ns)

    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    from_id = db.verify_identity_in_namespace(ns, x_inbox_secret)
    if not from_id:
        raise HTTPException(403, "Invalid inbox secret or not in namespace")

    try:
        result = db.send_message(
            ns=ns,
            from_id=from_id,
            to_id=request.to,
            body=request.body,
            ttl_hours=request.ttl_hours,
        )
    except ValueError as e:
        raise HTTPException(404, str(e))

    return result


@app.get("/{ns}/inbox/{identity_id}")
def get_inbox(
    ns: str,
    identity_id: str,
    unread: Annotated[bool, Query()] = False,
    after: Annotated[str | None, Query()] = None,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get messages for own inbox.

    Reading messages marks them as read and starts the TTL countdown.

    Query parameters:
    - unread: Only return unread messages
    - after: Only return messages after this message ID (cursor for pagination)
    """
    # Only mailbox owner can read their inbox
    require_inbox_secret(ns, identity_id, x_inbox_secret)

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
                "created_at": m["created_at"],
                "read_at": m["read_at"],
                "expires_at": m["expires_at"],
                "archived_at": m.get("archived_at"),
            }
            for m in messages
        ]
    }


@app.get("/{ns}/inbox/{identity_id}/archived")
def get_archived_messages(
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
                "created_at": m["created_at"],
                "read_at": m["read_at"],
                "expires_at": m["expires_at"],
                "archived_at": m["archived_at"],
            }
            for m in messages
        ]
    }


@app.get("/{ns}/inbox/{identity_id}/{mid}")
def get_message(
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
