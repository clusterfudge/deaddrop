"""MCP server exposing deaddrop rooms as tools over Streamable HTTP.

Mounted unconditionally at ``POST /mcp/{ns}/{secret}`` by :mod:`deadrop.api`.
The transport is the reference ``StreamableHTTPSessionManager`` in stateless
JSON mode: one request in, one JSON-RPC response out, no server-side session
state.

The credential is an ordinary inbox secret, verified against the ``identities``
table exactly as an ``X-Inbox-Secret`` header would be, and the tools act as
that identity: its namespace, its rooms, its attribution. There is no
server-side configuration and no fallback identity, so adding a connection is
an identity, not a config change.

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

from . import instrument

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


# Set by IdentityAuthASGI for the duration of one request. anyio copies the
# calling context when the session manager starts its per-request task, so the
# tool handlers see the value set here. Declared with no default: a tool call
# that reached the server without passing the gate raises LookupError instead
# of acting as some fallback identity.
_actor: ContextVar[Actor] = ContextVar("mcp_actor")


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

    The server holds no identity of its own: each request's tools act as the
    identity :class:`IdentityAuthASGI` verified from the URL.
    """

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=_tools())

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        from fastapi import HTTPException

        args = params.arguments or {}
        started = time.perf_counter()
        outcome = "ok"
        try:
            actor = _actor.get()
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


async def _send_unauthorized(send) -> None:
    """Send a fixed 401 body that reflects nothing the caller presented."""
    instrument.sink.counter("mcp.auth.rejected")
    body = json.dumps({"error": "unauthorized"}).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    await send({"type": "http.response.start", "status": 401, "headers": headers})
    await send({"type": "http.response.body", "body": body})


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


STATE_ATTR = "mcp_session_manager"


class _StreamableHTTPASGI:
    """Adapt the app's ``StreamableHTTPSessionManager`` to an ASGI callable.

    The manager is looked up per request instead of captured at registration:
    ``run()`` may only be entered once per manager, so each lifespan entry owns
    a fresh one on ``app.state``.
    """

    async def __call__(self, scope, receive, send) -> None:
        manager: StreamableHTTPSessionManager = getattr(scope["app"].state, STATE_ATTR)
        await manager.handle_request(scope, receive, send)


def register(app) -> None:
    """Mount the MCP endpoint on ``app``."""
    app.router.routes.append(
        Route(
            MCP_IDENTITY_PATH,
            endpoint=IdentityAuthASGI(_StreamableHTTPASGI()),
            name="mcp_identity",
        )
    )


@asynccontextmanager
async def session_lifespan(app):
    """Own a session manager and its task group for the life of ``app``."""
    manager = StreamableHTTPSessionManager(
        app=build_server(),
        json_response=True,
        stateless=True,
    )
    setattr(app.state, STATE_ATTR, manager)
    # Logged here rather than in register(): registration happens at import,
    # before configure_logging() runs in the lifespan.
    logger.info("MCP endpoint active at %s", MCP_IDENTITY_PATH)
    async with manager.run():
        yield
