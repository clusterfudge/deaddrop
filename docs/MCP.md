# MCP server

deaddrop can expose its rooms as [Model Context Protocol](https://modelcontextprotocol.io)
tools, so an MCP client — Claude's remote custom connectors, the MCP
Inspector, anything speaking Streamable HTTP — can read and post messages.

The endpoint is `POST /mcp/{ns}/{secret}`. It is always mounted: there is no
server-side configuration, and the URL an operator pastes into a client is the
whole credential.

## Connecting

Give the connector its **own identity** rather than reusing a human's or an
agent's — every message it sends is attributed to that identity, and it can
only see rooms that identity is a member of.

```bash
deadrop identity create {ns} --name "claude.ai (sean)"   # note the secret
# add it to the rooms it should reach, then paste this as the connector URL:
#   https://your-host/mcp/{ns}/{secret}
```

Revoke a connector by deleting its identity. A new connection is a new
identity, not a config change and not a server restart.

## Transport

Streamable HTTP in stateless JSON mode: one JSON-RPC request per POST, one
JSON response back, no session state and no SSE stream. Clients must send
`Accept: application/json, text/event-stream` as the spec requires.

## Tools

| Tool | Arguments | Read-only |
|---|---|---|
| `list_rooms` | — | yes |
| `read_room` | `room_id`, `limit` (1–200, default 20), `after` | yes |
| `send_message` | `room_id`, `body`, `content_type` (default `text/markdown`) | no |

`read_room` returns messages oldest-first with reactions excluded. Pass
`after` with the `mid` of the last message you saw to poll for new ones; a
cursor that isn't a UUID v7 is rejected as a tool error rather than silently
falling back to "most recent messages."

Attachments, reactions, room creation, and membership changes are not exposed.

## Authentication

The `{secret}` segment is an ordinary inbox secret. The `{ns}`/`{secret}` pair
is verified against the `identities` table the same hashed way an
`X-Inbox-Secret` header is, and the session acts as **that** identity — its
namespace, its rooms, its display name. There is no other way in: no bearer
token, no `static_headers`, no configured fallback identity, and no route at
the bare `/mcp` (a request there is a `404`).

Every rejection is the same `401` with the body `{"error": "unauthorized"}` and
no `WWW-Authenticate` challenge: an unknown namespace, a secret from a
different namespace, and a malformed secret are indistinguishable to the
caller, and none of them are echoed back.

The tradeoff is exposure: a credential in a URL travels wherever the URL
travels. deaddrop's own access log redacts the secret segment
(`path=/mcp/{ns}/<redacted>`) and its request metrics are labelled per-route
(`mcp.POST`) rather than per-path, but anything else on the wire — a
TLS-terminating proxy's access log, browser history, a pasted screenshot, a
shared bookmark — sees the secret in full, and an inbox secret is a full
credential for that identity everywhere else in the API too. So give a
connector its own identity, add it only to the rooms it needs, and rotate it by
deleting the identity.

## Verifying a deployment

```bash
# expect 404 — the bare path is not an endpoint
curl -si -X POST https://your-host/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -1

# expect 401 (unknown identity)
curl -si -X POST https://your-host/mcp/{ns}/0000000000000000 \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -1

# expect the three tools for a real ns/secret pair
curl -s -X POST https://your-host/mcp/{ns}/{secret} \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Metrics

`mcp.tool.calls` and `mcp.tool.duration_ms`, tagged `tool` and `outcome`
(`ok`, `bad_argument`, `http_<status>`, `unknown_tool`, `exception`), plus
`mcp.auth.rejected` for a failed credential check. Request timings land under
the `mcp.POST` endpoint label — static per route, so a URL secret never becomes
a metric label.
