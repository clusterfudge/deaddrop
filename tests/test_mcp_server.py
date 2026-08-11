"""Tests for the MCP server mounted at /mcp/{ns}/{secret}."""

import json
import re
from contextlib import asynccontextmanager

import mcp.types as types
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from deadrop import mcp_server
from deadrop.api import app as deaddrop_app

# The credential rides in the path, so no request carries an auth header.
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def identity_path(identity) -> str:
    return f"/mcp/{identity['ns']}/{identity['secret']}"


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
        "ns_secret": ns["secret"],
        "secret": alice["secret"],
        "identity_id": alice["id"],
        "room_id": created["room_id"],
    }


@pytest.fixture
def mcp_client():
    """A TestClient for a bare app with only the MCP endpoint mounted."""

    @asynccontextmanager
    async def lifespan(host_app):
        async with mcp_server.session_lifespan(host_app):
            yield

    host = FastAPI(lifespan=lifespan)
    mcp_server.register(host)

    with TestClient(host) as client:
        yield client


@pytest.fixture
def mcp_path(room) -> str:
    """The connector URL for the room fixture's identity."""
    return identity_path(room)


@pytest.fixture
def second_identity(room, admin_headers):
    """A second identity in the same namespace, with a room of its own."""
    with TestClient(deaddrop_app) as client:
        bob = client.post(
            f"/{room['ns']}/identities",
            headers={"X-Namespace-Secret": room["ns_secret"]},
            json={"metadata": {"display_name": "Bob"}},
        ).json()
        created = client.post(
            f"/{room['ns']}/rooms",
            headers={"X-Inbox-Secret": bob["secret"]},
            json={"display_name": "Bob Room"},
        ).json()
    return {
        "ns": room["ns"],
        "secret": bob["secret"],
        "identity_id": bob["id"],
        "room_id": created["room_id"],
    }


@pytest.fixture
def shared_room(room, second_identity):
    """Bob joins Alice's room, so Alice has exactly one peer in it.

    Bob keeps his own room, which Alice is not a member of.
    """
    with TestClient(deaddrop_app) as client:
        response = client.post(
            f"/{room['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": room["secret"]},
            json={"identity_id": second_identity["identity_id"]},
        )
        assert response.status_code == 200, response.text
    return room


@pytest.fixture
def group_room(shared_room, second_identity):
    """Alice's room plus a third member, mirroring Sean + Fritz + Claude.

    The returned ``caller`` is the third member: two peers, one room.
    """
    with TestClient(deaddrop_app) as client:
        carol = client.post(
            f"/{shared_room['ns']}/identities",
            headers={"X-Namespace-Secret": shared_room["ns_secret"]},
            json={"metadata": {"display_name": "Carol"}},
        ).json()
        response = client.post(
            f"/{shared_room['ns']}/rooms/{shared_room['room_id']}/members",
            headers={"X-Inbox-Secret": shared_room["secret"]},
            json={"identity_id": carol["id"]},
        )
        assert response.status_code == 200, response.text
    return {
        "room_id": shared_room["room_id"],
        "caller": {
            "ns": shared_room["ns"],
            "secret": carol["secret"],
            "identity_id": carol["id"],
        },
    }


@pytest.fixture
def roomless(room):
    """An identity in the same namespace that belongs to no room."""
    with TestClient(deaddrop_app) as client:
        identity = client.post(
            f"/{room['ns']}/identities",
            headers={"X-Namespace-Secret": room["ns_secret"]},
            json={"metadata": {"display_name": "Roomless"}},
        ).json()
    return {
        "ns": room["ns"],
        "ns_secret": room["ns_secret"],
        "secret": identity["secret"],
        "identity_id": identity["id"],
    }


@pytest.fixture
def foreign_room(admin_headers):
    """A room in a different namespace, which no other namespace may observe."""
    with TestClient(deaddrop_app) as client:
        ns = client.post("/admin/namespaces", headers=admin_headers).json()
        zoe = client.post(
            f"/{ns['ns']}/identities",
            headers={"X-Namespace-Secret": ns["secret"]},
            json={"metadata": {"display_name": "Zoe"}},
        ).json()
        created = client.post(
            f"/{ns['ns']}/rooms",
            headers={"X-Inbox-Secret": zoe["secret"]},
            json={"display_name": "Foreign Room"},
        ).json()
    return {"ns": ns["ns"], "room_id": created["room_id"]}


@pytest.fixture
def other_ns(admin_headers):
    """A second namespace, which the first namespace's secrets must not open."""
    with TestClient(deaddrop_app) as client:
        return client.post("/admin/namespaces", headers=admin_headers).json()["ns"]


def _post_rpc(client, path, method="tools/list", headers=None):
    return client.post(
        path,
        headers=headers or MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 1, "method": method},
        follow_redirects=False,
    )


def _rpc(client, path, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    response = client.post(path, headers=MCP_HEADERS, json=body, follow_redirects=False)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def _instructions(client, path) -> str:
    """Complete a real initialize handshake and return its instructions field."""
    result = _rpc(
        client,
        path,
        "initialize",
        {
            "protocolVersion": types.LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "instructions-test", "version": "1.0"},
        },
    )
    return result["instructions"]


def _call_tool_raw(client, path, name, arguments=None):
    result = _rpc(client, path, "tools/call", {"name": name, "arguments": arguments or {}})
    payload = None
    if not result.get("isError"):
        payload = json.loads(result["content"][0]["text"])
    return result, payload


def _call_tool(client, path, name, arguments=None):
    result, payload = _call_tool_raw(client, path, name, arguments)
    assert not result.get("isError"), result["content"][0]["text"]
    return payload


class TestRouting:
    def test_mounts_without_any_configuration(self):
        """No env vars gate the endpoint: registering mounts it."""
        host = FastAPI()
        mcp_server.register(host)
        paths = [getattr(r, "path", "") for r in host.routes]
        assert mcp_server.MCP_IDENTITY_PATH in paths

    def test_identity_path_does_not_redirect(self, mcp_client, mcp_path):
        """The connector URL has no trailing slash; a 307 on POST is not ok."""
        response = _post_rpc(mcp_client, mcp_path)
        assert response.status_code == 200

    def test_bare_mcp_path_has_no_route(self, mcp_client):
        """/mcp is not an endpoint — the credential is the whole path."""
        assert _post_rpc(mcp_client, "/mcp").status_code == 404

    def test_partial_path_is_not_a_bypass(self, mcp_client, room):
        """/mcp/{ns} matches no route."""
        assert _post_rpc(mcp_client, f"/mcp/{room['ns']}").status_code == 404


class TestAuth:
    """POST /mcp/{ns}/{secret} is the only way in."""

    def test_correct_secret_completes_the_initialize_handshake(self, mcp_client, mcp_path):
        response = mcp_client.post(
            mcp_path,
            headers=MCP_HEADERS,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": types.LATEST_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "url-secret-client", "version": "1.0"},
                },
            },
            follow_redirects=False,
        )
        assert response.status_code == 200, response.text
        assert response.json()["result"]["serverInfo"]["name"] == "deaddrop"

    def test_wrong_secret_is_401_and_reflects_nothing(self, mcp_client, room):
        wrong = "0" * 64
        response = _post_rpc(mcp_client, f"/mcp/{room['ns']}/{wrong}")
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}
        assert wrong not in response.text

    def test_real_secret_in_the_wrong_namespace_is_401(self, mcp_client, room, other_ns):
        response = _post_rpc(mcp_client, f"/mcp/{other_ns}/{room['secret']}")
        assert response.status_code == 401
        assert room["secret"] not in response.text

    def test_unknown_namespace_is_401(self, mcp_client, room):
        response = _post_rpc(mcp_client, f"/mcp/deadbeefdeadbeef/{room['secret']}")
        assert response.status_code == 401
        assert room["secret"] not in response.text

    def test_no_challenge_header_is_offered(self, mcp_client, room):
        """There is no header credential to challenge for."""
        response = _post_rpc(mcp_client, f"/mcp/{room['ns']}/{'0' * 64}")
        assert "www-authenticate" not in response.headers

    def test_an_authorization_header_authenticates_nothing(self, mcp_client, room):
        """No bearer path exists: a header credential opens no route."""
        headers = dict(MCP_HEADERS, Authorization=f"Bearer {room['secret']}")
        assert _post_rpc(mcp_client, "/mcp", headers=headers).status_code == 404
        assert (
            _post_rpc(mcp_client, f"/mcp/{room['ns']}/{'0' * 64}", headers=headers).status_code
            == 401
        )

    def test_there_is_no_fallback_identity(self):
        """The actor is per-request only — nothing supplies a default one."""
        with pytest.raises(LookupError):
            mcp_server._actor.get()

    def test_rejected_secret_is_counted(self, mcp_client, room, monkeypatch):
        from tests.test_instrument import RecordingSink

        recorder = RecordingSink()
        monkeypatch.setattr(mcp_server.instrument, "sink", recorder)
        _post_rpc(mcp_client, f"/mcp/{room['ns']}/{'0' * 64}")
        assert any(c[1] == "mcp.auth.rejected" for c in recorder.of_type("counter"))


class TestIdentityScope:
    """Each connection acts as the identity in its own URL, and only that one."""

    def test_each_url_sees_only_its_own_rooms(self, mcp_client, room, second_identity):
        alice = _call_tool(mcp_client, identity_path(room), "list_rooms")
        assert [r["room_id"] for r in alice["rooms"]] == [room["room_id"]]

        bob = _call_tool(mcp_client, identity_path(second_identity), "list_rooms")
        assert [r["room_id"] for r in bob["rooms"]] == [second_identity["room_id"]]
        assert bob["rooms"][0]["display_name"] == "Bob Room"

    def test_the_actor_does_not_leak_between_requests(self, mcp_client, room, second_identity):
        """One request's identity must not carry into the next one's."""
        _call_tool(mcp_client, identity_path(second_identity), "list_rooms")
        alice = _call_tool(mcp_client, identity_path(room), "list_rooms")
        assert [r["room_id"] for r in alice["rooms"]] == [room["room_id"]]

    def test_messages_are_attributed_to_the_url_identity(self, mcp_client, room, second_identity):
        path = identity_path(second_identity)
        sent = _call_tool(
            mcp_client,
            path,
            "send_message",
            {"room_id": second_identity["room_id"], "body": "bob was here"},
        )
        assert sent["mid"]

        read = _call_tool(mcp_client, path, "read_room", {"room_id": second_identity["room_id"]})
        assert [m["body"] for m in read["messages"]] == ["bob was here"]
        assert read["messages"][0]["from_id"] == second_identity["identity_id"]
        assert read["messages"][0]["from_id"] != room["identity_id"]

    def test_url_identity_cannot_reach_a_room_it_is_not_in(self, mcp_client, room, second_identity):
        result, _ = _call_tool_raw(
            mcp_client,
            identity_path(second_identity),
            "read_room",
            {"room_id": room["room_id"]},
        )
        assert result["isError"] is True


class TestPathRedaction:
    """The secret must not survive into a log line."""

    def test_secret_segment_is_redacted_and_the_ns_survives(self):
        assert mcp_server.redact_path("/mcp/abc123/s3cret") == "/mcp/abc123/<redacted>"

    def test_trailing_segments_are_redacted_too(self):
        assert mcp_server.redact_path("/mcp/abc123/s3cret/extra") == "/mcp/abc123/<redacted>"

    def test_a_path_with_no_ns_segment_is_redacted_whole(self):
        assert mcp_server.redact_path("/mcp/s3cret") == "/mcp/<redacted>"

    def test_bare_mcp_path_is_unchanged(self):
        assert mcp_server.redact_path("/mcp") == "/mcp"

    def test_other_paths_are_unchanged(self):
        assert mcp_server.redact_path("/abc123/rooms") == "/abc123/rooms"

    def test_access_log_never_carries_the_secret(self, room, capsys):
        """The access-log middleware redacts whether or not the route matched."""
        with TestClient(deaddrop_app) as client:
            client.post(identity_path(room), headers=MCP_HEADERS, json={}, follow_redirects=False)
        logged = capsys.readouterr().out
        assert f"/mcp/{room['ns']}/<redacted>" in logged
        assert room["secret"] not in logged


class TestToolListing:
    def test_lists_three_tools(self, mcp_client, mcp_path):
        tools = _rpc(mcp_client, mcp_path, "tools/list")["tools"]
        assert {t["name"] for t in tools} == {"list_rooms", "read_room", "send_message"}

    def test_every_tool_declares_both_required_hints(self, mcp_client, mcp_path):
        """claude.ai requires readOnlyHint and destructiveHint on every tool."""
        for tool in _rpc(mcp_client, mcp_path, "tools/list")["tools"]:
            annotations = tool["annotations"]
            assert "readOnlyHint" in annotations
            assert "destructiveHint" in annotations

    def test_read_tools_are_read_only_and_send_is_not(self, mcp_client, mcp_path):
        by_name = {t["name"]: t for t in _rpc(mcp_client, mcp_path, "tools/list")["tools"]}
        assert by_name["list_rooms"]["annotations"]["readOnlyHint"] is True
        assert by_name["read_room"]["annotations"]["readOnlyHint"] is True
        assert by_name["send_message"]["annotations"]["readOnlyHint"] is False
        assert by_name["send_message"]["annotations"]["destructiveHint"] is False


class TestTools:
    def test_list_rooms(self, mcp_client, mcp_path, room):
        payload = _call_tool(mcp_client, mcp_path, "list_rooms")
        assert [r["room_id"] for r in payload["rooms"]] == [room["room_id"]]
        assert payload["rooms"][0]["display_name"] == "MCP Room"

    def test_send_then_read(self, mcp_client, mcp_path, room):
        sent = _call_tool(
            mcp_client, mcp_path, "send_message", {"room_id": room["room_id"], "body": "hello"}
        )
        assert sent["mid"]
        assert sent["deduplicated"] is False

        read = _call_tool(mcp_client, mcp_path, "read_room", {"room_id": room["room_id"]})
        assert read["room_id"] == room["room_id"]
        assert [m["body"] for m in read["messages"]] == ["hello"]
        assert read["messages"][0]["from_id"] == room["identity_id"]
        assert read["messages"][0]["content_type"] == "text/markdown"

    def test_read_room_after_cursor(self, mcp_client, mcp_path, room):
        first = _call_tool(
            mcp_client, mcp_path, "send_message", {"room_id": room["room_id"], "body": "first"}
        )
        _call_tool(
            mcp_client, mcp_path, "send_message", {"room_id": room["room_id"], "body": "second"}
        )

        read = _call_tool(
            mcp_client, mcp_path, "read_room", {"room_id": room["room_id"], "after": first["mid"]}
        )
        assert [m["body"] for m in read["messages"]] == ["second"]

    def test_read_room_rejects_non_v7_cursor(self, mcp_client, mcp_path, room):
        """A v4 cursor must not silently degrade to 'latest messages'."""
        _call_tool(
            mcp_client, mcp_path, "send_message", {"room_id": room["room_id"], "body": "only"}
        )
        result, _ = _call_tool_raw(
            mcp_client,
            mcp_path,
            "read_room",
            {"room_id": room["room_id"], "after": "1e141d46-0000-4000-8000-000000000000"},
        )
        assert result["isError"] is True
        assert "UUID v7" in result["content"][0]["text"]

    def test_read_room_limit_is_capped(self, mcp_client, mcp_path, room):
        read = _call_tool(
            mcp_client, mcp_path, "read_room", {"room_id": room["room_id"], "limit": 99999}
        )
        assert read["messages"] == []

    def test_send_to_foreign_room_is_tool_error(self, mcp_client, mcp_path):
        result, _ = _call_tool_raw(
            mcp_client,
            mcp_path,
            "send_message",
            {"room_id": "0198e39d-5b8b-76f4-8000-87645fce0630", "body": "nope"},
        )
        assert result["isError"] is True

    def test_missing_required_argument_is_tool_error(self, mcp_client, mcp_path, room):
        result, _ = _call_tool_raw(
            mcp_client, mcp_path, "send_message", {"room_id": room["room_id"]}
        )
        assert result["isError"] is True
        assert "body" in result["content"][0]["text"]

    def test_unknown_tool_is_error(self, mcp_client, mcp_path):
        result, _ = _call_tool_raw(mcp_client, mcp_path, "delete_everything")
        assert result["isError"] is True


class TestInstrumentation:
    """Tool calls and auth rejections must reach the MetricsSink."""

    @pytest.fixture
    def sink(self, monkeypatch):
        from tests.test_instrument import RecordingSink

        recorder = RecordingSink()
        monkeypatch.setattr(mcp_server.instrument, "sink", recorder)
        return recorder

    def test_successful_call_emits_timing_and_counter(self, mcp_client, mcp_path, sink):
        _call_tool(mcp_client, mcp_path, "list_rooms")
        assert ("mcp.tool.calls", {"tool": "list_rooms", "outcome": "ok"}) in [
            (c[1], c[3]) for c in sink.of_type("counter")
        ]
        timings = [c for c in sink.of_type("timing") if c[1] == "mcp.tool.duration_ms"]
        assert timings and timings[0][3] == {"tool": "list_rooms", "outcome": "ok"}

    def test_failed_call_records_the_outcome(self, mcp_client, mcp_path, room):
        from tests.test_instrument import RecordingSink

        recorder = RecordingSink()
        original = mcp_server.instrument.sink
        mcp_server.instrument.sink = recorder
        try:
            _call_tool_raw(
                mcp_client,
                mcp_path,
                "read_room",
                {"room_id": room["room_id"], "after": "1e141d46-0000-4000-8000-000000000000"},
            )
            _call_tool_raw(mcp_client, mcp_path, "send_message", {"room_id": "nope", "body": "x"})
        finally:
            mcp_server.instrument.sink = original

        outcomes = {
            c[3]["outcome"] for c in recorder.of_type("counter") if c[1] == "mcp.tool.calls"
        }
        assert "bad_argument" in outcomes
        assert any(o.startswith("http_") for o in outcomes)


class TestHandshakeInstructions:
    """The initialize result describes the caller's own corner of the namespace."""

    def test_instructions_name_the_identity_and_its_room(self, mcp_client, shared_room):
        text = _instructions(mcp_client, identity_path(shared_room))
        assert f"namespace `{shared_room['ns']}`" in text
        assert "`Alice`" in text
        assert "MCP Room" in text
        assert shared_room["room_id"] in text
        assert "Bob" in text

    def test_instructions_carry_the_message_a_peer_hint(self, mcp_client, shared_room):
        """The point of the feature: 'message Bob' resolves to a room_id."""
        text = _instructions(mcp_client, identity_path(shared_room))
        assert f"to message Bob: send_message with room_id=`{shared_room['room_id']}`" in text

    def test_a_group_room_yields_a_hint_for_every_peer(self, mcp_client, group_room):
        """The target shape: one room, two peers, a hint for each.

        A per-peer hint only for two-member rooms would miss the Sean + Fritz +
        Claude room entirely, which is the room this feature exists for.
        """
        text = _instructions(mcp_client, identity_path(group_room["caller"]))
        room_id = group_room["room_id"]
        assert f"to message Alice: send_message with room_id=`{room_id}`" in text
        assert f"to message Bob: send_message with room_id=`{room_id}`" in text
        assert "group room" in text

    def test_instructions_keep_the_static_guidance(self, mcp_client, shared_room):
        text = _instructions(mcp_client, identity_path(shared_room))
        assert mcp_server.BASE_INSTRUCTIONS in text

    def test_an_identity_with_no_rooms_gets_a_sane_minimal_string(self, mcp_client, roomless):
        text = _instructions(mcp_client, identity_path(roomless))
        assert mcp_server.BASE_INSTRUCTIONS in text
        assert f"namespace `{roomless['ns']}`" in text
        assert "`Roomless`" in text
        assert "not a member of any deaddrop room" in text
        # No roster block, and no id-shaped token: the only "room_id" mention is
        # the static guidance's reference to the tool argument.
        assert "You are a member of these rooms" not in text
        assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-", text)

    def test_instructions_never_carry_the_secret(self, mcp_client, shared_room):
        text = _instructions(mcp_client, identity_path(shared_room))
        assert shared_room["secret"] not in text
        assert shared_room["ns_secret"] not in text

    def test_instructions_omit_a_same_namespace_room_the_identity_is_not_in(
        self, mcp_client, shared_room, second_identity
    ):
        """Membership scoping inside one namespace, not just across namespaces.

        Bob owns a room Alice is not in. Neither its id, its name, nor its
        member list may reach Alice's handshake.
        """
        text = _instructions(mcp_client, identity_path(shared_room))
        assert second_identity["room_id"] not in text
        assert "Bob Room" not in text

    def test_instructions_omit_another_namespaces_rooms(
        self, mcp_client, shared_room, foreign_room
    ):
        text = _instructions(mcp_client, identity_path(shared_room))
        assert foreign_room["room_id"] not in text
        assert "Foreign Room" not in text
        assert "Zoe" not in text

    def test_each_identity_gets_its_own_instructions(self, mcp_client, shared_room, roomless):
        """Composed per handshake, so one connection's roster is not reused."""
        assert "MCP Room" in _instructions(mcp_client, identity_path(shared_room))
        assert "MCP Room" not in _instructions(mcp_client, identity_path(roomless))

    def test_tool_descriptions_carry_no_room_or_member_data(self, mcp_client, shared_room):
        """Only instructions are identity-scoped; the tool schema stays static."""
        tools = _rpc(mcp_client, identity_path(shared_room), "tools/list")["tools"]
        blob = json.dumps(tools)
        assert shared_room["room_id"] not in blob
        assert "MCP Room" not in blob
        assert "Alice" not in blob
        assert "Bob" not in blob

    def test_a_composition_failure_falls_back_to_the_static_instructions(
        self, mcp_client, shared_room, monkeypatch
    ):
        """A DB hiccup must degrade the description, not the connection."""

        async def boom(actor):
            raise RuntimeError("db is on fire")

        monkeypatch.setattr(mcp_server, "compose_instructions", boom)
        assert _instructions(mcp_client, identity_path(shared_room)) == (
            mcp_server.BASE_INSTRUCTIONS
        )


class TestInstructionComposition:
    """compose_instructions reads memberships only."""

    def test_it_never_enumerates_the_namespace(self):
        """No namespace-wide listing call appears in the composer."""
        import inspect

        source = inspect.getsource(mcp_server.compose_instructions)
        assert "list_my_rooms" in source
        assert "list_room_members" in source
        assert "list_identities" not in source
        assert "list_rooms(" not in source
