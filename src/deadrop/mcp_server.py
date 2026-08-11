"""MCP server exposing deaddrop rooms as tools over Streamable HTTP.

Mounted at ``POST /mcp`` by :mod:`deadrop.api` when configured. The transport
is the reference ``StreamableHTTPSessionManager`` in stateless JSON mode: one
request in, one JSON-RPC response out, no server-side session state.

Configuration is entirely environment-driven and the server stays unmounted
unless all three variables are present:

``DEADROP_MCP_TOKEN``
    The bearer token a client must present in ``Authorization``.
``DEADROP_MCP_NS``
    Namespace the tools operate in.
``DEADROP_MCP_SECRET``
    Inbox secret of the identity the tools act as. Every room read and every
    message sent is attributed to this identity.

The tool handlers call the room route functions in :mod:`deadrop.api`
directly, so membership checks, message dedup, and SSE fanout behave exactly
as they do for an HTTP caller.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import time
from contextlib import asynccontextmanager
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

# Ceiling on read_room's limit. The underlying route allows 1000; a connector
# reply is fed to a model, so cap it well below that.
MAX_READ_LIMIT = 200
DEFAULT_READ_LIMIT = 20


@dataclass(frozen=True)
class McpConfig:
    """Resolved environment configuration for the MCP server."""

    token: str
    ns: str
    secret: str


def load_config() -> McpConfig | None:
    """Read config from the environment, or None when not fully configured."""
    token = os.environ.get("DEADROP_MCP_TOKEN", "").strip()
    ns = os.environ.get("DEADROP_MCP_NS", "").strip()
    secret = os.environ.get("DEADROP_MCP_SECRET", "").strip()
    if not (token and ns and secret):
        return None
    return McpConfig(token=token, ns=ns, secret=secret)


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


async def _list_rooms(cfg: McpConfig) -> dict[str, Any]:
    from . import api

    rooms = await api.list_my_rooms(cfg.ns, x_inbox_secret=cfg.secret)
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


async def _read_room(cfg: McpConfig, args: dict[str, Any]) -> dict[str, Any]:
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
        cfg.ns,
        _require_str(args, "room_id"),
        after=after,
        before=None,
        limit=limit,
        exclude_reactions=True,
        x_inbox_secret=cfg.secret,
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


async def _send_message(cfg: McpConfig, args: dict[str, Any]) -> dict[str, Any]:
    from . import api

    response = await api.send_room_message(
        cfg.ns,
        _require_str(args, "room_id"),
        api.SendRoomMessageRequest(
            body=_require_str(args, "body"),
            content_type=args.get("content_type") or "text/markdown",
        ),
        x_inbox_secret=cfg.secret,
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


def build_server(cfg: McpConfig) -> Server:
    """Build the low-level MCP server for a resolved config."""

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        return types.ListToolsResult(tools=_tools())

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        from fastapi import HTTPException

        args = params.arguments or {}
        started = time.perf_counter()
        outcome = "ok"
        try:
            if params.name == "list_rooms":
                payload = await _list_rooms(cfg)
            elif params.name == "read_room":
                payload = await _read_room(cfg, args)
            elif params.name == "send_message":
                payload = await _send_message(cfg, args)
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


class BearerAuthASGI:
    """Gate an ASGI app on a fixed bearer token.

    ``static_headers`` is the auth type this implements: the client sends a
    single pre-shared credential in ``Authorization`` on every request. The
    ``401`` carries ``WWW-Authenticate: Bearer`` with no ``resource_metadata``
    parameter, because there is no OAuth authorization server to discover.
    """

    def __init__(self, app, token: str) -> None:
        self._app = app
        self._token = f"Bearer {token}"

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        presented = ""
        for name, value in scope.get("headers", []):
            if name.lower() == b"authorization":
                presented = value.decode("latin-1")
                break

        if not hmac.compare_digest(presented, self._token):
            instrument.sink.counter("mcp.auth.rejected")
            body = json.dumps({"error": "unauthorized"}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b'Bearer realm="deaddrop-mcp"'),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        await self._app(scope, receive, send)


class _StreamableHTTPASGI:
    """Adapt ``StreamableHTTPSessionManager`` to a bare ASGI callable."""

    def __init__(self, manager: StreamableHTTPSessionManager) -> None:
        self._manager = manager

    async def __call__(self, scope, receive, send) -> None:
        await self._manager.handle_request(scope, receive, send)


STATE_ATTR = "mcp_session_manager"


def register(app) -> bool:
    """Mount the MCP endpoint on ``app``. Returns whether it was mounted.

    The session manager is stored on ``app.state`` rather than in a module
    global: a manager's ``run()`` may only be entered once, so it has to be
    owned by the app whose lifespan enters it.
    """
    cfg = load_config()
    if cfg is None:
        logger.info("MCP server not mounted (DEADROP_MCP_TOKEN/NS/SECRET not all set)")
        return False

    manager = StreamableHTTPSessionManager(
        app=build_server(cfg),
        json_response=True,
        stateless=True,
    )
    setattr(app.state, STATE_ATTR, manager)

    # A Route, not a Mount: Starlette's Mount regex only matches paths *below*
    # the mount point, so a request to the bare /mcp gets a 307 to /mcp/. The
    # connector URL an operator types has no trailing slash, and a redirect on
    # POST is not something to rely on a client honouring.
    endpoint = BearerAuthASGI(_StreamableHTTPASGI(manager), cfg.token)
    app.router.routes.append(Route(MCP_PATH, endpoint=endpoint, name="mcp"))
    return True


@asynccontextmanager
async def session_lifespan(app):
    """Run the session manager's task group for the life of ``app``.

    A no-op when the endpoint was never mounted on this app.
    """
    manager = getattr(app.state, STATE_ATTR, None)
    if manager is None:
        yield
        return
    # Logged here rather than in register(): registration happens at import,
    # before configure_logging() runs in the lifespan.
    logger.info("MCP endpoint active at %s", MCP_PATH)
    async with manager.run():
        yield
