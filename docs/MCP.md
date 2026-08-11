# MCP server

deaddrop can expose its rooms as [Model Context Protocol](https://modelcontextprotocol.io)
tools, so an MCP client — Claude's remote custom connectors, the MCP
Inspector, anything speaking Streamable HTTP — can read and post messages.

The endpoint is `POST /mcp`. It is **off unless configured**.

## Configuration

| Variable | Meaning |
|---|---|
| `DEADROP_MCP_TOKEN` | Bearer token the client must present in `Authorization`. |
| `DEADROP_MCP_NS` | Namespace the tools operate in. |
| `DEADROP_MCP_SECRET` | Inbox secret of the identity the tools act as. |

All three are required; with any of them missing the route is never
registered. Give the connector its **own identity** rather than reusing a
human's or an agent's — every message it sends is attributed to that identity,
and it can only see rooms that identity is a member of.

```bash
deadrop identity create {ns} --name "claude.ai"     # note the secret it prints
# add it to the rooms it should reach, then:
dokku config:set deaddrop \
  DEADROP_MCP_TOKEN=… DEADROP_MCP_NS=… DEADROP_MCP_SECRET=…
```

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

A fixed bearer token, compared against the full `Authorization` value. A
mismatch returns `401` with `WWW-Authenticate: Bearer realm="deaddrop-mcp"`.

For Claude this is the `static_headers` auth type: enter the header value
**including the scheme** — `Bearer your-token` — because Claude sends the value
verbatim. Note that request-header auth is a gradual-rollout beta; an account
without it needs an OAuth-based server instead.

## Verifying a deployment

```bash
# expect 401
curl -si -X POST https://your-host/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -1

# expect the three tools
npx @modelcontextprotocol/inspector   # or any MCP client, with the bearer token
```

## Metrics

`mcp.tool.calls` and `mcp.tool.duration_ms`, tagged `tool` and `outcome`
(`ok`, `bad_argument`, `http_<status>`, `unknown_tool`, `exception`), plus
`mcp.auth.rejected` for a failed bearer check. Request timings land under the
`mcp.POST` endpoint label.
