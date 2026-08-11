"""Tests for the MCP server mounted at /mcp."""

import json
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from deadrop import mcp_server
from deadrop.api import app as deaddrop_app

TOKEN = "test-mcp-token"
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Authorization": f"Bearer {TOKEN}",
}


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": "test-admin-token"}


@pytest.fixture
def room(admin_headers):
    """A namespace with one identity and one room it belongs to."""
    with TestClient(deaddrop_app) as client:
        ns = client.post("/admin/namespaces", headers=admin_headers).json()
        alice = client.post(
            f"/{ns['ns']}/identities",
            headers={"X-Namespace-Secret": ns["secret"]},
            json={"metadata": {"display_name": "Alice"}},
        ).json()
        created = client.post(
            f"/{ns['ns']}/rooms",
            headers={"X-Inbox-Secret": alice["secret"]},
            json={"display_name": "MCP Room"},
        ).json()
    return {
        "ns": ns["ns"],
        "secret": alice["secret"],
        "identity_id": alice["id"],
        "room_id": created["room_id"],
    }


@pytest.fixture
def mcp_client(room, monkeypatch):
    """A TestClient for a bare app with only the MCP endpoint mounted."""
    monkeypatch.setenv("DEADROP_MCP_TOKEN", TOKEN)
    monkeypatch.setenv("DEADROP_MCP_NS", room["ns"])
    monkeypatch.setenv("DEADROP_MCP_SECRET", room["secret"])

    @asynccontextmanager
    async def lifespan(host_app):
        async with mcp_server.session_lifespan(host_app):
            yield

    host = FastAPI(lifespan=lifespan)
    assert mcp_server.register(host) is True

    with TestClient(host) as client:
        yield client


def _rpc(client, method, params=None, request_id=1):
    body = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    response = client.post("/mcp", headers=MCP_HEADERS, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _call_tool(client, name, arguments=None):
    result = _rpc(client, "tools/call", {"name": name, "arguments": arguments or {}})["result"]
    payload = None
    if not result.get("isError"):
        payload = json.loads(result["content"][0]["text"])
    return result, payload


class TestConfig:
    def test_unconfigured_returns_none(self, monkeypatch):
        for var in ("DEADROP_MCP_TOKEN", "DEADROP_MCP_NS", "DEADROP_MCP_SECRET"):
            monkeypatch.delenv(var, raising=False)
        assert mcp_server.load_config() is None

    def test_partial_config_returns_none(self, monkeypatch):
        monkeypatch.setenv("DEADROP_MCP_TOKEN", TOKEN)
        monkeypatch.setenv("DEADROP_MCP_NS", "abc123")
        monkeypatch.delenv("DEADROP_MCP_SECRET", raising=False)
        assert mcp_server.load_config() is None

    def test_full_config(self, monkeypatch):
        monkeypatch.setenv("DEADROP_MCP_TOKEN", TOKEN)
        monkeypatch.setenv("DEADROP_MCP_NS", "abc123")
        monkeypatch.setenv("DEADROP_MCP_SECRET", "s3cret")
        cfg = mcp_server.load_config()
        assert cfg is not None
        assert (cfg.token, cfg.ns, cfg.secret) == (TOKEN, "abc123", "s3cret")

    def test_register_is_noop_when_unconfigured(self, monkeypatch):
        for var in ("DEADROP_MCP_TOKEN", "DEADROP_MCP_NS", "DEADROP_MCP_SECRET"):
            monkeypatch.delenv(var, raising=False)
        host = FastAPI()
        assert mcp_server.register(host) is False
        assert not any(getattr(r, "path", None) == "/mcp" for r in host.routes)


class TestRouting:
    def test_bare_mcp_path_does_not_redirect(self, mcp_client):
        """The connector URL has no trailing slash; a 307 on POST is not ok."""
        response = mcp_client.post(
            "/mcp",
            headers=MCP_HEADERS,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            follow_redirects=False,
        )
        assert response.status_code == 200

    def test_unauthenticated_bare_path_is_401_not_a_redirect(self, mcp_client):
        response = mcp_client.post(
            "/mcp",
            headers={k: v for k, v in MCP_HEADERS.items() if k != "Authorization"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            follow_redirects=False,
        )
        assert response.status_code == 401


class TestAuth:
    def test_missing_token_is_401(self, mcp_client):
        response = mcp_client.post(
            "/mcp",
            headers={k: v for k, v in MCP_HEADERS.items() if k != "Authorization"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert response.status_code == 401
        assert "Bearer" in response.headers["www-authenticate"]

    def test_wrong_token_is_401(self, mcp_client):
        headers = dict(MCP_HEADERS, Authorization="Bearer nope")
        response = mcp_client.post(
            "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        assert response.status_code == 401

    def test_bare_token_without_scheme_is_401(self, mcp_client):
        """Claude sends the header value verbatim; 'Bearer ' is part of it."""
        headers = dict(MCP_HEADERS, Authorization=TOKEN)
        response = mcp_client.post(
            "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        assert response.status_code == 401


class TestToolListing:
    def test_lists_three_tools(self, mcp_client):
        tools = _rpc(mcp_client, "tools/list")["result"]["tools"]
        assert {t["name"] for t in tools} == {"list_rooms", "read_room", "send_message"}

    def test_every_tool_declares_both_required_hints(self, mcp_client):
        """claude.ai requires readOnlyHint and destructiveHint on every tool."""
        for tool in _rpc(mcp_client, "tools/list")["result"]["tools"]:
            annotations = tool["annotations"]
            assert "readOnlyHint" in annotations
            assert "destructiveHint" in annotations

    def test_read_tools_are_read_only_and_send_is_not(self, mcp_client):
        by_name = {t["name"]: t for t in _rpc(mcp_client, "tools/list")["result"]["tools"]}
        assert by_name["list_rooms"]["annotations"]["readOnlyHint"] is True
        assert by_name["read_room"]["annotations"]["readOnlyHint"] is True
        assert by_name["send_message"]["annotations"]["readOnlyHint"] is False
        assert by_name["send_message"]["annotations"]["destructiveHint"] is False


class TestTools:
    def test_list_rooms(self, mcp_client, room):
        _, payload = _call_tool(mcp_client, "list_rooms")
        assert [r["room_id"] for r in payload["rooms"]] == [room["room_id"]]
        assert payload["rooms"][0]["display_name"] == "MCP Room"

    def test_send_then_read(self, mcp_client, room):
        _, sent = _call_tool(
            mcp_client, "send_message", {"room_id": room["room_id"], "body": "hello from claude"}
        )
        assert sent["mid"]
        assert sent["deduplicated"] is False

        _, read = _call_tool(mcp_client, "read_room", {"room_id": room["room_id"]})
        assert read["room_id"] == room["room_id"]
        assert [m["body"] for m in read["messages"]] == ["hello from claude"]
        assert read["messages"][0]["from_id"] == room["identity_id"]
        assert read["messages"][0]["content_type"] == "text/markdown"

    def test_read_room_after_cursor(self, mcp_client, room):
        _, first = _call_tool(
            mcp_client, "send_message", {"room_id": room["room_id"], "body": "first"}
        )
        _call_tool(mcp_client, "send_message", {"room_id": room["room_id"], "body": "second"})

        _, read = _call_tool(
            mcp_client, "read_room", {"room_id": room["room_id"], "after": first["mid"]}
        )
        assert [m["body"] for m in read["messages"]] == ["second"]

    def test_read_room_rejects_non_v7_cursor(self, mcp_client, room):
        """A v4 cursor must not silently degrade to 'latest messages'."""
        _call_tool(mcp_client, "send_message", {"room_id": room["room_id"], "body": "only"})
        result, _ = _call_tool(
            mcp_client,
            "read_room",
            {"room_id": room["room_id"], "after": "1e141d46-0000-4000-8000-000000000000"},
        )
        assert result["isError"] is True
        assert "UUID v7" in result["content"][0]["text"]

    def test_read_room_limit_is_capped(self, mcp_client, room):
        _, read = _call_tool(mcp_client, "read_room", {"room_id": room["room_id"], "limit": 99999})
        assert read["messages"] == []

    def test_send_to_foreign_room_is_tool_error(self, mcp_client):
        result, _ = _call_tool(
            mcp_client,
            "send_message",
            {"room_id": "0198e39d-5b8b-76f4-8000-87645fce0630", "body": "nope"},
        )
        assert result["isError"] is True

    def test_missing_required_argument_is_tool_error(self, mcp_client, room):
        result, _ = _call_tool(mcp_client, "send_message", {"room_id": room["room_id"]})
        assert result["isError"] is True
        assert "body" in result["content"][0]["text"]

    def test_unknown_tool_is_error(self, mcp_client):
        result, _ = _call_tool(mcp_client, "delete_everything")
        assert result["isError"] is True


class TestInstrumentation:
    """Tool calls and auth rejections must reach the MetricsSink."""

    @pytest.fixture
    def sink(self, monkeypatch):
        from tests.test_instrument import RecordingSink

        recorder = RecordingSink()
        monkeypatch.setattr(mcp_server.instrument, "sink", recorder)
        return recorder

    def test_successful_call_emits_timing_and_counter(self, mcp_client, sink):
        _call_tool(mcp_client, "list_rooms")
        assert ("mcp.tool.calls", {"tool": "list_rooms", "outcome": "ok"}) in [
            (c[1], c[3]) for c in sink.of_type("counter")
        ]
        timings = [c for c in sink.of_type("timing") if c[1] == "mcp.tool.duration_ms"]
        assert timings and timings[0][3] == {"tool": "list_rooms", "outcome": "ok"}

    def test_failed_call_records_the_outcome(self, mcp_client, room):
        from tests.test_instrument import RecordingSink

        recorder = RecordingSink()
        original = mcp_server.instrument.sink
        mcp_server.instrument.sink = recorder
        try:
            _call_tool(
                mcp_client,
                "read_room",
                {"room_id": room["room_id"], "after": "1e141d46-0000-4000-8000-000000000000"},
            )
            _call_tool(mcp_client, "send_message", {"room_id": "nope", "body": "x"})
        finally:
            mcp_server.instrument.sink = original

        outcomes = {
            c[3]["outcome"] for c in recorder.of_type("counter") if c[1] == "mcp.tool.calls"
        }
        assert "bad_argument" in outcomes
        assert any(o.startswith("http_") for o in outcomes)

    def test_rejected_auth_is_counted(self, mcp_client, sink):
        mcp_client.post(
            "/mcp",
            headers=dict(MCP_HEADERS, Authorization="Bearer wrong"),
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert any(c[1] == "mcp.auth.rejected" for c in sink.of_type("counter"))
