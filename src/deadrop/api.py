"""FastAPI application for deadrop."""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

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
    """Initialize and cleanup database, and warm caches."""
    db.init_db()

    # Schedule cache warming as background task (non-blocking)
    from .cache import schedule_cache_warming, stop_cache_warming

    schedule_cache_warming()

    yield

    # Stop background cache refresh
    stop_cache_warming()
    db.close_db()


app = FastAPI(
    title="deadrop",
    description="Minimal inbox-only messaging for agents",
    version="0.1.0",
    lifespan=lifespan,
)


# --- Request Timing Middleware ---


@app.middleware("http")
async def add_timing_middleware(request: Request, call_next):
    """Middleware to track request timing for metrics."""
    import time

    from .metrics import metrics

    start_time = time.perf_counter()

    response = await call_next(request)

    duration_ms = (time.perf_counter() - start_time) * 1000

    # Extract endpoint pattern (simplified - uses path)
    # For rooms endpoints, normalize the IDs
    path = request.url.path
    if "/rooms/" in path:
        # Normalize room endpoints for aggregation
        parts = path.split("/")
        if len(parts) >= 4 and parts[2] == "rooms":
            # /{ns}/rooms/{room_id}/... -> /rooms/{action}
            action = parts[4] if len(parts) > 4 else "info"
            endpoint = f"rooms/{action}"
        else:
            endpoint = "rooms"
    elif "/inbox/" in path:
        endpoint = "inbox"
    elif path.startswith("/admin"):
        endpoint = "admin"
    elif path in ("/health", "/metrics"):
        endpoint = path[1:]  # Remove leading slash
    else:
        endpoint = "other"

    metrics.record_request(endpoint, duration_ms)

    # Add timing header for debugging
    response.headers["X-Response-Time-Ms"] = f"{duration_ms:.1f}"

    return response


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
    content_type: str = (
        "text/plain"  # MIME type (e.g., text/plain, text/markdown, text/html, application/json)
    )
    ttl_hours: int | None = None  # Optional TTL override (ephemeral messages)


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


# --- Async helpers (for use in async def handlers) ---
# These wrap synchronous db/auth calls in run_in_executor so they don't
# block the event loop.  Sync handlers already run in a threadpool, so
# they keep using the sync versions above directly.


def _get_db_executor():
    """Get the appropriate executor for DB operations.

    Returns a single-threaded executor when using libsql/Turso (which uses
    a single shared connection that isn't thread-safe), or None to use the
    default threadpool for local SQLite (which uses thread-local connections).
    """
    global _db_executor
    if _db_executor is not None:
        return _db_executor

    if db.is_using_libsql():
        from concurrent.futures import ThreadPoolExecutor

        _db_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="db")
        logger.info("Using serialized DB executor for libsql/Turso")
    else:
        _db_executor = None  # Use default threadpool for local SQLite
        logger.info("Using default threadpool for local SQLite")

    return _db_executor


_db_executor = None  # Initialized lazily


async def _run_sync(fn, *args):
    """Run a synchronous function off the event loop.

    Uses a single-threaded executor for libsql/Turso (shared connection)
    or the default threadpool for local SQLite (thread-local connections).
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_get_db_executor(), fn, *args)


async def _require_active_namespace(ns: str) -> None:
    """Async variant of require_active_namespace."""
    archived = await _run_sync(db.is_namespace_archived, ns)
    if archived:
        raise HTTPException(410, "Namespace is archived")


async def _require_inbox_secret(ns: str, identity_id: str, x_inbox_secret: str | None) -> str:
    """Async variant of require_inbox_secret."""
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    derived_id = derive_id(x_inbox_secret)
    if derived_id != identity_id:
        raise HTTPException(403, "Secret does not match identity")

    verified = await _run_sync(db.verify_identity_secret, ns, identity_id, x_inbox_secret)
    if not verified:
        raise HTTPException(403, "Invalid inbox secret or identity not in namespace")

    return identity_id


async def _require_inbox_secret_any(ns: str, x_inbox_secret: str | None) -> str:
    """Async variant of require_inbox_secret_any."""
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    identity_id = await _run_sync(db.verify_identity_in_namespace, ns, x_inbox_secret)
    if not identity_id:
        raise HTTPException(403, "Invalid inbox secret or not in namespace")

    return identity_id


async def _require_room_member(room_id: str, x_inbox_secret: str | None) -> tuple[dict, str]:
    """Async variant of require_room_member."""
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    identity_id = derive_id(x_inbox_secret)

    import functools

    room, error = await _run_sync(
        functools.partial(db.verify_room_access, room_id, identity_id, x_inbox_secret)
    )

    if error or room is None:
        error_msg = error or "Unknown error"
        if "not found" in error_msg.lower():
            raise HTTPException(404, error_msg)
        elif "not a member" in error_msg.lower():
            raise HTTPException(403, error_msg)
        elif "invalid" in error_msg.lower() or "does not match" in error_msg.lower():
            raise HTTPException(403, error_msg)
        else:
            raise HTTPException(400, error_msg)

    return room, identity_id


async def _validate_subscription_topics(
    ns: str,
    topics: dict[str, str | None],
    caller_id: str,
) -> None:
    """Async variant of _validate_subscription_topics_sync."""
    for topic_key in topics:
        if ":" not in topic_key:
            raise HTTPException(
                400,
                f"Invalid topic format: {topic_key!r}. "
                "Expected 'inbox:{id}' or 'room:{room_id}'",
            )

        topic_type, topic_id = topic_key.split(":", 1)

        if topic_type == "inbox":
            if topic_id != caller_id:
                raise HTTPException(
                    403,
                    f"Cannot subscribe to another identity's inbox: {topic_key}",
                )
        elif topic_type == "room":
            is_member = await _run_sync(db.is_room_member, topic_id, caller_id)
            if not is_member:
                raise HTTPException(
                    403,
                    f"Not a member of room: {topic_id}",
                )
            room = await _run_sync(db.get_room, topic_id)
            if room is None or room.get("ns") != ns:
                raise HTTPException(404, f"Room not found in this namespace: {topic_id}")
        else:
            raise HTTPException(
                400,
                f"Unknown topic type: {topic_type!r}. Supported: 'inbox', 'room'",
            )


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
async def send_message(
    ns: str,
    request: SendMessageRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Send a message to another identity.

    Messages are delivered instantly. Optionally set ttl_hours for ephemeral
    messages that expire from creation time (instead of read time).
    """
    import functools

    from .events import get_event_bus

    await _require_active_namespace(ns)
    from_id = await _require_inbox_secret_any(ns, x_inbox_secret)

    try:
        result = await _run_sync(
            functools.partial(
                db.send_message,
                ns=ns,
                from_id=from_id,
                to_id=request.to,
                body=request.body,
                content_type=request.content_type,
                ttl_hours=request.ttl_hours,
            )
        )
    except ValueError as e:
        raise HTTPException(404, str(e))

    # Notify subscribers that the recipient's inbox has a new message
    try:
        await get_event_bus().publish(ns, f"inbox:{request.to}", result["mid"])
    except Exception:
        logger.warning("Failed to publish inbox event", exc_info=True)

    return result


@app.get("/{ns}/inbox/{identity_id}")
async def get_inbox(
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

    For real-time updates, use the POST /{ns}/subscribe endpoint instead.
    """
    import functools

    # Only mailbox owner can read their inbox
    await _require_inbox_secret(ns, identity_id, x_inbox_secret)

    # Fetch and return messages
    messages = await _run_sync(
        functools.partial(
            db.get_messages,
            ns=ns,
            identity_id=identity_id,
            unread_only=unread,
            after_mid=after,
        )
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
                "content_type": m.get("content_type", "text/plain"),
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
        "content_type": message.get("content_type", "text/plain"),
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


class RoomInfo(BaseModel):
    room_id: str
    ns: str
    display_name: str | None
    created_by: str
    created_at: str


class RoomWithMemberInfo(BaseModel):
    room_id: str
    ns: str
    display_name: str | None
    created_by: str
    created_at: str
    joined_at: str
    last_read_mid: str | None


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


class RoomMessageInfo(BaseModel):
    mid: str
    room_id: str
    from_id: str  # The sender's identity ID
    body: str
    content_type: str
    created_at: str

    @classmethod
    def from_db(cls, data: dict) -> "RoomMessageInfo":
        """Create from db result which uses 'from' key."""
        return cls(
            mid=data["mid"],
            room_id=data["room_id"],
            from_id=data["from"],
            body=data["body"],
            content_type=data.get("content_type", "text/plain"),
            created_at=data["created_at"],
        )


class UpdateReadCursorRequest(BaseModel):
    last_read_mid: str


# --- Room Helper Functions ---


def require_room_member(room_id: str, x_inbox_secret: str | None) -> tuple[dict, str]:
    """Verify caller is a member of the room. Returns (room, identity_id).

    Uses optimized combined query with caching to minimize database round-trips.
    Previously this made 3 sequential DB calls (~250ms with Turso).
    Now it makes 1 combined query with caching (~80ms or cache hit).
    """
    if not x_inbox_secret:
        raise HTTPException(401, "X-Inbox-Secret header required")

    # Derive identity from secret (no DB call needed)
    identity_id = derive_id(x_inbox_secret)

    # Use optimized combined query with caching
    room, error = db.verify_room_access(room_id, identity_id, x_inbox_secret)

    if error or room is None:
        # Map error messages to appropriate HTTP status codes
        error_msg = error or "Unknown error"
        if "not found" in error_msg.lower():
            raise HTTPException(404, error_msg)
        elif "not a member" in error_msg.lower():
            raise HTTPException(403, error_msg)
        elif "invalid" in error_msg.lower() or "does not match" in error_msg.lower():
            raise HTTPException(403, error_msg)
        else:
            raise HTTPException(400, error_msg)

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
    """
    require_active_namespace(ns)

    # Verify caller is in namespace
    created_by = require_inbox_secret_any(ns, x_inbox_secret)

    display_name = request.display_name if request else None

    try:
        room = db.create_room(ns, created_by, display_name=display_name)
    except ValueError as e:
        raise HTTPException(400, str(e))

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

    return RoomInfo(**room)


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

    # Invalidate room cache
    from .cache import invalidate_room

    invalidate_room(room_id)

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


@app.post("/{ns}/rooms/{room_id}/members", response_model=RoomMemberInfo)
def add_room_member(
    ns: str,
    room_id: str,
    request: AddRoomMemberRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Add a member to a room.

    Any room member can invite other identities from the same namespace.
    """
    room, _ = require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    try:
        db.add_room_member(room_id, request.identity_id)
        # Invalidate membership cache for the new member
        from .cache import invalidate_membership

        invalidate_membership(room_id, request.identity_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Get full member info with metadata
    member_info = db.get_room_member_info(room_id, request.identity_id)
    if not member_info:
        raise HTTPException(500, "Failed to get member info")

    return RoomMemberInfo(**member_info)


@app.delete("/{ns}/rooms/{room_id}/members/{identity_id}")
def remove_room_member(
    ns: str,
    room_id: str,
    identity_id: str,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Remove a member from a room.

    Members can remove themselves. Namespace owner can remove anyone.
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

    if not db.remove_room_member(room_id, identity_id):
        raise HTTPException(404, "Member not found")

    # Invalidate membership cache
    from .cache import invalidate_membership

    invalidate_membership(room_id, identity_id)

    return {"ok": True}


@app.get("/{ns}/rooms/{room_id}/messages")
async def get_room_messages(
    ns: str,
    room_id: str,
    after: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Get messages from a room.

    Query parameters:
    - after: Only return messages after this message ID (for pagination/polling)
    - limit: Maximum number of messages to return (default: 100, max: 1000)

    For real-time updates, use the POST /{ns}/subscribe endpoint instead.
    """
    import functools

    room, identity_id = await _require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    messages = await _run_sync(
        functools.partial(db.get_room_messages, room_id, after_mid=after, limit=limit)
    )

    return {
        "messages": [RoomMessageInfo.from_db(m).model_dump() for m in messages],
        "room_id": room_id,
    }


@app.post("/{ns}/rooms/{room_id}/messages", response_model=RoomMessageInfo)
async def send_room_message(
    ns: str,
    room_id: str,
    request: SendRoomMessageRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Send a message to a room. Requires membership."""
    import functools

    from .events import get_event_bus

    room, from_id = await _require_room_member(room_id, x_inbox_secret)

    if room["ns"] != ns:
        raise HTTPException(404, "Room not found in this namespace")

    try:
        message = await _run_sync(
            functools.partial(
                db.send_room_message,
                room_id=room_id,
                from_id=from_id,
                body=request.body,
                content_type=request.content_type,
            )
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Notify subscribers that this room has a new message
    try:
        await get_event_bus().publish(ns, f"room:{room_id}", message["mid"])
    except Exception:
        logger.warning("Failed to publish room event", exc_info=True)

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


# --- Subscription Endpoint ---

logger = logging.getLogger(__name__)


class SubscribeRequest(BaseModel):
    """Request body for topic subscription."""

    topics: dict[str, str | None]
    """Map of topic_key -> last_seen_mid. Use None for 'never seen'."""

    mode: Literal["poll", "stream"] = "poll"
    """Subscription mode: 'poll' blocks and returns, 'stream' uses SSE."""

    timeout: int = Field(default=30, ge=1, le=60)
    """Timeout in seconds for poll mode (ignored for stream mode)."""


def _validate_subscription_topics_sync(
    ns: str,
    topics: dict[str, str | None],
    caller_id: str,
) -> None:
    """Validate that the caller has access to all requested topics (sync version).

    Used only by tests. The subscribe endpoint uses the async variant above.
    """
    for topic_key in topics:
        if ":" not in topic_key:
            raise HTTPException(
                400,
                f"Invalid topic format: {topic_key!r}. "
                "Expected 'inbox:{id}' or 'room:{room_id}'",
            )

        topic_type, topic_id = topic_key.split(":", 1)

        if topic_type == "inbox":
            # Can only subscribe to your own inbox
            if topic_id != caller_id:
                raise HTTPException(
                    403,
                    f"Cannot subscribe to another identity's inbox: {topic_key}",
                )
        elif topic_type == "room":
            # Must be a member of the room
            if not db.is_room_member(topic_id, caller_id):
                raise HTTPException(
                    403,
                    f"Not a member of room: {topic_id}",
                )
            # Also verify room belongs to this namespace
            room = db.get_room(topic_id)
            if room is None or room.get("ns") != ns:
                raise HTTPException(404, f"Room not found in this namespace: {topic_id}")
        else:
            raise HTTPException(
                400,
                f"Unknown topic type: {topic_type!r}. Supported: 'inbox', 'room'",
            )


@app.post("/{ns}/subscribe")
async def subscribe(
    ns: str,
    request: SubscribeRequest,
    x_inbox_secret: Annotated[str | None, Header()] = None,
):
    """Subscribe to changes on topics within a namespace.

    Clients provide a vector clock (map of topic -> last_seen_mid) and
    receive notifications when any subscribed topic has new messages.

    **Events, not payloads**: The response tells you *which* topics changed,
    not the message contents. Use the existing inbox/room endpoints to
    fetch content, passing the cursor from the event.

    **Modes**:
    - `poll`: Blocks until an event occurs or timeout. Returns changed topics.
    - `stream`: Returns Server-Sent Events (SSE) for continuous streaming.

    **Topic format**:
    - `inbox:{identity_id}` — subscribe to your own inbox
    - `room:{room_id}` — subscribe to a room you're a member of

    **Auth**: X-Inbox-Secret header required. Must be a valid identity
    in the namespace.
    """
    from .events import get_event_bus

    await _require_active_namespace(ns)
    caller_id = await _require_inbox_secret_any(ns, x_inbox_secret)

    if not request.topics:
        raise HTTPException(400, "At least one topic is required")

    await _validate_subscription_topics(ns, request.topics, caller_id)

    event_bus = get_event_bus()

    if request.mode == "stream":
        # SSE streaming mode
        async def event_generator():
            # Send initial connected event
            yield "event: connected\ndata: {}\n\n"

            try:
                async for event in event_bus.stream(ns, request.topics):
                    yield f"event: change\ndata: {json.dumps(event)}\n\n"
            except asyncio.CancelledError:
                return

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # Poll mode — block until event or timeout
    changes = await event_bus.subscribe(ns, request.topics, timeout=request.timeout)

    return {
        "events": changes,
        "timeout": len(changes) == 0,
    }


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


@app.get("/app/{slug}/room/{room_id}", response_class=HTMLResponse)
def app_room_page(request: Request, slug: str, room_id: str):
    """Web app - room chat view."""
    if templates:
        return templates.TemplateResponse(
            "app.html",
            {
                "request": request,
                "slug": slug,
                "room_id": room_id,
            },
        )
    return HTMLResponse(f"<h1>Room</h1><p>Room: {room_id}</p>")


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


@app.get("/metrics")
def get_metrics(
    authorization: Annotated[str | None, Header()] = None,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Get application metrics. Requires admin authentication."""
    require_admin(authorization, x_admin_token)

    from .cache import (
        CACHE_REFRESH_INTERVAL,
        CACHE_WARMING_ENABLED,
        identity_hash_cache,
        membership_cache,
        room_cache,
    )
    from .metrics import metrics

    return {
        **metrics.to_dict(),
        "caches": {
            "warming_enabled": CACHE_WARMING_ENABLED,
            "refresh_interval_seconds": CACHE_REFRESH_INTERVAL,
            "room": room_cache.stats(),
            "membership": membership_cache.stats(),
            "identity_hash": identity_hash_cache.stats(),
        },
    }
