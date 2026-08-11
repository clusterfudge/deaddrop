"""MCP server exposing deaddrop rooms as tools over Streamable HTTP.

Mounted at ``POST /mcp`` by :mod:`deadrop.api`, with ``POST /mcp/{ns}/{secret}``
as a second entrance for clients that cannot set an ``Authorization`` header.
The transport is the reference ``StreamableHTTPSessionManager`` in stateless
JSON mode: one request in, one JSON-RPC response out, no server-side session
state.

Both entrances authenticate a **deaddrop identity**, and there is no
server-wide credential and no configured identity to fall back on:

``POST /mcp``
    ``Authorization: Bearer <token>``, where the token was issued by this app's
    own OAuth authorization server (:mod:`deadrop.mcp_oauth`). The identity is
    the one chosen at consent time.
``POST /mcp/{ns}/{secret}``
    An ordinary inbox secret in the URL, verified against the ``identities``
    table exactly as an ``X-Inbox-Secret`` header would be.

Either way the acting identity is per-request and travels in a ``ContextVar``,
so adding a connection is an identity, not a config change.

The tool handlers call the room route functions in :mod:`deadrop.api`
directly, so membership checks, message dedup, and SSE fanout behave exactly
as they do for an HTTP caller.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import mcp.types as types
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.routing import Route

from . import instrument, mcp_oauth

logger = logging.getLogger(__name__)

SERVER_NAME = "deaddrop"
MCP_PATH = "/mcp"
MCP_IDENTITY_PATH = f"{MCP_PATH}/{{ns}}/{{secret}}"
REDACTED_SEGMENT = "<redacted>"

# Ceiling on read_room's limit. The underlying route allows 1000; a connector
# reply is fed to a model, so cap it well below that.
MAX_READ_LIMIT = 200
DEFAULT_READ_LIMIT = 20


@dataclass(frozen=True)
class Actor:
    """The identity a request's tool calls act as."""

    ns: str
    secret: str


# Set by whichever auth wrapper accepted the request, for the duration of that
# request. anyio copies the calling context when the session manager starts its
# per-request task, so the tool handlers see the value set here.
_actor: ContextVar[Actor | None] = ContextVar("mcp_actor", default=None)


# --- Tool definitions ---------------------------------------------------


def _tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_rooms",
            title="List deaddrop rooms",
            description=(
                "List the deaddrop rooms this connector is a member of. Returns each "
                "room's id, display name, member count, and last activity timestamp. "
                "Call this first to resolve a room name to the room_id the other tools need."
            ),
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False),
        ),
        types.Tool(
            name="read_room",
            title="Read deaddrop room messages",
            description=(
                "Read recent messages from a deaddrop room, oldest first. Pass `after` "
                "with the `mid` of the last message you have seen to fetch only newer "
                "messages. Reactions are excluded."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "room_id": {
                        "type": "string",
                        "description": "Room id, as returned by list_rooms.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_READ_LIMIT,
                        "default": DEFAULT_READ_LIMIT,
                        "description": "Maximum number of messages to return.",
                    },
                    "after": {
                        "type": "string",
                        "description": "Return only messages after this message id (cursor).",
                    },
                },
                "required": ["room_id"],
                "additionalProperties": False,
            },
            annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False),
        ),
        types.Tool(
            name="send_message",
            title="Send a deaddrop room message",
            description=(
                "Post a message to a deaddrop room. The message is attributed to this "
                "connector's identity and is immediately visible to every room member."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "room_id": {
                        "type": "string",
                        "description": "Room id, as returned by list_rooms.",
                    },
                    "body": {"type": "string", "description": "Message text."},
                    "content_type": {
                        "type": "string",
                        "default": "text/markdown",
                        "description": "MIME type of the body.",
                    },
                },
                "required": ["room_id", "body"],
                "additionalProperties": False,
            },
            annotations=types.ToolAnnotations(read_only_hint=False, destructive_hint=False),
        ),
    ]


# --- Tool implementations ----------------------------------------------


async def _list_rooms(actor: Actor) -> dict[str, Any]:
    from . import api

    rooms = await api.list_my_rooms(actor.ns, x_inbox_secret=actor.secret)
    return {
        "rooms": [
            {
                "room_id": r.room_id,
                "display_name": r.display_name,
                "member_count": r.member_count,
                "last_activity_at": r.last_activity_at,
            }
            for r in rooms
        ]
    }


async def _read_room(actor: Actor, args: dict[str, Any]) -> dict[str, Any]:
    from . import api

    limit = int(args.get("limit") or DEFAULT_READ_LIMIT)
    limit = max(1, min(limit, MAX_READ_LIMIT))

    after = args.get("after") or None
    # Reject a non-v7 cursor here instead of letting the route coerce it.
    # _coerce_read_cursor maps an invalid cursor to None, and None on a read
    # path means "return the latest messages" — a caller asking for messages
    # *after* a cursor would silently receive already-seen messages instead.
    # A tool error is recoverable in-band: the caller drops the cursor and
    # retries, so there is no reader to wedge.
    if after is not None and not api._is_valid_uuid7(after):
        raise ValueError(
            f"after must be a UUID v7 message id (got {after!r}); "
            "omit it to read the most recent messages"
        )

    result = await api.get_room_messages(
        actor.ns,
        _require_str(args, "room_id"),
        after=after,
        before=None,
        limit=limit,
        exclude_reactions=True,
        x_inbox_secret=actor.secret,
    )
    return {
        "room_id": result["room_id"],
        "messages": [
            {
                "mid": m["mid"],
                "from_id": m["from_id"],
                "body": m["body"],
                "content_type": m["content_type"],
                "created_at": m["created_at"],
            }
            for m in result["messages"]
        ],
    }


async def _send_message(actor: Actor, args: dict[str, Any]) -> dict[str, Any]:
    from . import api

    response = await api.send_room_message(
        actor.ns,
        _require_str(args, "room_id"),
        api.SendRoomMessageRequest(
            body=_require_str(args, "body"),
            content_type=args.get("content_type") or "text/markdown",
        ),
        x_inbox_secret=actor.secret,
    )
    # send_room_message returns a JSONResponse so it can set Dedup-Status.
    sent = json.loads(bytes(response.body))
    return {
        "mid": sent.get("mid"),
        "room_id": sent.get("room_id"),
        "created_at": sent.get("created_at"),
        "deduplicated": response.headers.get("Dedup-Status") == "deduplicated",
    }


def _require_str(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} is required and must be a non-empty string")
    return value


# --- Protocol handlers -------------------------------------------------


def build_server() -> Server:
    """Build the low-level MCP server.

    One instance serves every connection. It holds no identity of its own: the
    auth wrapper that accepted the request has already put the acting identity
    in ``_actor``, and the tool handlers read it there.
    """

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=_tools())

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        from fastapi import HTTPException

        args = params.arguments or {}
        actor = _actor.get()
        if actor is None:  # pragma: no cover — the auth wrappers always set it
            return _error("no authenticated identity for this request")
        started = time.perf_counter()
        outcome = "ok"
        try:
            if params.name == "list_rooms":
                payload = await _list_rooms(actor)
            elif params.name == "read_room":
                payload = await _read_room(actor, args)
            elif params.name == "send_message":
                payload = await _send_message(actor, args)
            else:
                outcome = "unknown_tool"
                return _error(f"Unknown tool: {params.name}")
        except HTTPException as exc:
            outcome = f"http_{exc.status_code}"
            return _error(f"deaddrop returned {exc.status_code}: {exc.detail}")
        except ValueError as exc:
            outcome = "bad_argument"
            return _error(str(exc))
        except Exception:
            outcome = "exception"
            logger.exception("MCP tool %s failed", params.name)
            return _error(f"Tool {params.name} failed — see server logs")
        finally:
            tags = {"tool": params.name, "outcome": outcome}
            instrument.sink.timing(
                "mcp.tool.duration_ms", (time.perf_counter() - started) * 1000, tags=tags
            )
            instrument.sink.counter("mcp.tool.calls", tags=tags)

        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(payload, indent=2))],
            structured_content=payload,
        )

    return Server(
        SERVER_NAME,
        title="deaddrop",
        instructions=(
            "Read and post messages in deaddrop rooms. Resolve a room name to a "
            "room_id with list_rooms before calling read_room or send_message."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)], is_error=True
    )


# --- ASGI plumbing -----------------------------------------------------


async def _send_unauthorized(send, www_authenticate: bytes | None = None) -> None:
    """Send a fixed 401 body that reflects nothing the caller presented."""
    instrument.sink.counter("mcp.auth.rejected")
    body = json.dumps({"error": "unauthorized"}).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    if www_authenticate is not None:
        headers.append((b"www-authenticate", www_authenticate))
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class OAuthAuthASGI:
    """Gate an ASGI app on an access token from this app's authorization server.

    The token names its own identity: the grant it belongs to recorded the
    ``(ns, identity_id)`` chosen at consent time, so a verified token yields the
    :class:`Actor` for that identity rather than unlocking a configured one.

    A rejection is the same opaque ``401`` the URL route sends, plus a
    ``WWW-Authenticate: Bearer`` challenge carrying the RFC 9728
    ``resource_metadata`` pointer and the scopes to ask for — the handshake a
    remote MCP client uses to discover where to authorize. The challenge names
    an authorization server only when one is configured; advertising discovery
    for a server that is not running turns a clean rejection into a failed
    handshake.
    """

    def __init__(self, app, oauth: mcp_oauth.OAuthConfig | None) -> None:
        self._app = app
        self._oauth = oauth

    def _challenge(self) -> bytes:
        params = ['realm="deaddrop-mcp"']
        if self._oauth is not None:
            params.append(f'resource_metadata="{self._oauth.resource_metadata_url}"')
            params.append(f'scope="{" ".join(mcp_oauth.SCOPES_SUPPORTED)}"')
        return b"Bearer " + ", ".join(params).encode("latin-1")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        presented = ""
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                presented = value.decode("latin-1")
                break

        granted = None
        if self._oauth is not None and presented.startswith("Bearer "):
            granted = mcp_oauth.verify_access_token(presented[len("Bearer ") :], self._oauth)
        if granted is None:
            await _send_unauthorized(send, self._challenge())
            return

        token = _actor.set(Actor(ns=granted.ns, secret=granted.inbox_secret))
        try:
            await self._app(scope, receive, send)
        finally:
            _actor.reset(token)


class IdentityAuthASGI:
    """Gate an ASGI app on an inbox secret carried in the URL path.

    ``{ns}`` and ``{secret}`` are the pair the identity table can verify — the
    same pair an ``X-Inbox-Secret`` request carries, one in the path and one in
    a header — so verification goes through :func:`api._require_inbox_secret_any`
    and inherits its hashed comparison and its identity-hash cache. Requests
    that get through act as the verified identity.

    Every rejection is the same opaque ``401``: an unknown namespace, a secret
    that belongs to another namespace, and a malformed secret are
    indistinguishable to the caller, and none of them are echoed back. No
    ``WWW-Authenticate``, because there is no header credential to challenge
    for.
    """

    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        from fastapi import HTTPException

        from . import api

        params = scope.get("path_params", {})
        ns = params.get("ns", "")
        secret = params.get("secret", "")
        if not isinstance(ns, str) or not isinstance(secret, str):
            await _send_unauthorized(send)
            return

        try:
            await api._require_inbox_secret_any(ns, secret)
        except HTTPException:
            await _send_unauthorized(send)
            return

        token = _actor.set(Actor(ns=ns, secret=secret))
        try:
            await self._app(scope, receive, send)
        finally:
            _actor.reset(token)


def redact_path(path: str) -> str:
    """Replace the secret segment of a ``/mcp/{ns}/{secret}`` path.

    The namespace survives — it is public and appears in every other logged
    path — and everything after it becomes a placeholder. A ``/mcp/`` path with
    no namespace segment is redacted whole, since a client that mangles the URL
    can put the secret anywhere in it. Any other path is returned unchanged.
    Call this before a path reaches a log line or a metric label.
    """
    if not path.startswith(f"{MCP_PATH}/"):
        return path
    segments = path.split("/")
    if len(segments) < 4:
        return f"{MCP_PATH}/{REDACTED_SEGMENT}"
    return "/".join([*segments[:3], REDACTED_SEGMENT])


class _StreamableHTTPASGI:
    """Adapt ``StreamableHTTPSessionManager`` to a bare ASGI callable.

    The manager is looked up on ``app.state`` per request rather than captured
    at construction. A manager's ``run()`` may be entered only once, so the
    instance belongs to one pass through the app's lifespan — and an app whose
    lifespan is entered twice (a test suite opening two clients against the
    same app object) needs a second instance, not the first one again.
    """

    async def __call__(self, scope, receive, send) -> None:
        manager = getattr(scope["app"].state, STATE_ATTR, None)
        if manager is None:
            body = json.dumps({"error": "mcp transport not started"}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await manager.handle_request(scope, receive, send)


STATE_ATTR = "mcp_session_manager"


def register(app) -> bool:
    """Mount the MCP endpoint on ``app``. Returns whether it was mounted.

    Unconditional: every credential either route accepts is a deaddrop
    identity or a token issued against one, so there is nothing to configure
    before the endpoint can safely exist. ``POST /mcp`` answers ``401`` until
    :mod:`deadrop.mcp_oauth` is configured, which is the correct answer for a
    route whose only credential is an OAuth token.

    Only the routes are registered here. The transport instance is created by
    :func:`session_lifespan`, because it is bound to one entry of the app's
    lifespan.
    """
    # A Route, not a Mount: Starlette's Mount regex only matches paths *below*
    # the mount point, so a request to the bare /mcp gets a 307 to /mcp/. The
    # connector URL an operator types has no trailing slash, and a redirect on
    # POST is not something to rely on a client honouring.
    transport = _StreamableHTTPASGI()
    app.router.routes.append(
        Route(MCP_PATH, endpoint=OAuthAuthASGI(transport, mcp_oauth.get_config(app)), name="mcp")
    )
    app.router.routes.append(
        Route(MCP_IDENTITY_PATH, endpoint=IdentityAuthASGI(transport), name="mcp_identity")
    )
    return True


@asynccontextmanager
async def session_lifespan(app):
    """Own the session manager for one pass through ``app``'s lifespan.

    The manager is created here rather than in :func:`register` because its
    ``run()`` may be entered only once and it owns an anyio task group, which
    has to be entered on the running loop.
    """
    manager = StreamableHTTPSessionManager(
        app=build_server(),
        json_response=True,
        stateless=True,
    )
    setattr(app.state, STATE_ATTR, manager)
    # Logged here rather than in register(): registration happens at import,
    # before configure_logging() runs in the lifespan.
    logger.info("MCP endpoint active at %s and %s", MCP_PATH, MCP_IDENTITY_PATH)
    if mcp_oauth.get_config(app) is not None:
        from . import db

        logger.info(
            "MCP OAuth authorization server active; purged %s", db.purge_expired_oauth_records()
        )
    try:
        async with manager.run():
            yield
    finally:
        setattr(app.state, STATE_ATTR, None)
