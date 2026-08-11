"""Tests for the OAuth 2.1 authorization server backing the MCP endpoint."""

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from deadrop import crypto, db, mcp_oauth, mcp_server
from deadrop.api import app as deaddrop_app
from deadrop.auth import hash_secret

PUBLIC_URL = "http://testserver"
RESOURCE = f"{PUBLIC_URL}/mcp"
OAUTH_KEY = crypto.bytes_to_base64url(b"k" * 32)
REDIRECT = "https://claude.ai/api/mcp/auth_callback"

MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def _verifier_and_challenge(verifier: str = "a" * 64) -> tuple[str, str]:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, crypto.bytes_to_base64url(digest)


@pytest.fixture
def world():
    """A namespace, two identities, and a room both belong to."""
    admin = {"X-Admin-Token": "test-admin-token"}
    with TestClient(deaddrop_app) as client:
        ns = client.post("/admin/namespaces", headers=admin).json()
        ns_headers = {"X-Namespace-Secret": ns["secret"]}
        alice = client.post(
            f"/{ns['ns']}/identities", headers=ns_headers, json={"metadata": {"display_name": "A"}}
        ).json()
        bob = client.post(
            f"/{ns['ns']}/identities", headers=ns_headers, json={"metadata": {"display_name": "B"}}
        ).json()
        room = client.post(
            f"/{ns['ns']}/rooms",
            headers={"X-Inbox-Secret": alice["secret"]},
            json={"display_name": "OAuth Room"},
        ).json()
        client.post(
            f"/{ns['ns']}/rooms/{room['room_id']}/members",
            headers={"X-Inbox-Secret": alice["secret"]},
            json={"identity_id": bob["id"]},
        )
    return {"ns": ns["ns"], "alice": alice, "bob": bob, "room_id": room["room_id"]}


def _build_app(world, monkeypatch, *, oauth=True):
    if oauth:
        monkeypatch.setenv("DEADROP_MCP_PUBLIC_URL", PUBLIC_URL)
        monkeypatch.setenv("DEADROP_MCP_OAUTH_KEY", OAUTH_KEY)
    else:
        monkeypatch.delenv("DEADROP_MCP_PUBLIC_URL", raising=False)
        monkeypatch.delenv("DEADROP_MCP_OAUTH_KEY", raising=False)

    @asynccontextmanager
    async def lifespan(host_app):
        async with mcp_server.session_lifespan(host_app):
            yield

    app = FastAPI(lifespan=lifespan)
    mcp_oauth.register(app)
    mcp_server.register(app)
    return app


@pytest.fixture
def client(world, monkeypatch):
    with TestClient(_build_app(world, monkeypatch), follow_redirects=False) as c:
        yield c


@pytest.fixture
def no_oauth_client(world, monkeypatch):
    with TestClient(_build_app(world, monkeypatch, oauth=False), follow_redirects=False) as c:
        yield c


# --- Configuration -----------------------------------------------------


def test_load_config_requires_public_url_and_key(monkeypatch):
    monkeypatch.delenv("DEADROP_MCP_PUBLIC_URL", raising=False)
    monkeypatch.setenv("DEADROP_MCP_OAUTH_KEY", OAUTH_KEY)
    assert mcp_oauth.load_config() is None


def test_load_config_rejects_wrong_key_length(monkeypatch):
    monkeypatch.setenv("DEADROP_MCP_PUBLIC_URL", PUBLIC_URL)
    monkeypatch.setenv("DEADROP_MCP_OAUTH_KEY", crypto.bytes_to_base64url(b"short"))
    assert mcp_oauth.load_config() is None


def test_routes_absent_without_oauth_config(no_oauth_client):
    assert no_oauth_client.get("/.well-known/oauth-authorization-server").status_code == 404
    assert no_oauth_client.post("/oauth/register", json={}).status_code == 404


# --- Discovery ---------------------------------------------------------


def test_protected_resource_metadata(client):
    doc = client.get("/.well-known/oauth-protected-resource").json()
    assert doc["resource"] == RESOURCE
    assert doc["authorization_servers"] == [PUBLIC_URL]
    assert doc["scopes_supported"] == ["mcp", "offline_access"]
    assert doc["bearer_methods_supported"] == ["header"]


def test_protected_resource_metadata_path_inserted_form(client):
    """The form a client probes first when a 401 carried no pointer."""
    resp = client.get("/.well-known/oauth-protected-resource/mcp")
    assert resp.status_code == 200
    assert resp.json()["resource"] == RESOURCE


def test_authorization_server_metadata(client):
    doc = client.get("/.well-known/oauth-authorization-server").json()
    assert doc["issuer"] == PUBLIC_URL
    assert doc["authorization_endpoint"] == f"{PUBLIC_URL}/oauth/authorize"
    assert doc["token_endpoint"] == f"{PUBLIC_URL}/oauth/token"
    assert doc["registration_endpoint"] == f"{PUBLIC_URL}/oauth/register"
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert doc["grant_types_supported"] == ["authorization_code", "refresh_token"]
    # Advertising CIMD would make claude.ai prefer a mechanism we do not serve.
    assert "client_id_metadata_document_supported" not in doc


def test_unauthenticated_mcp_advertises_resource_metadata(client):
    resp = client.post("/mcp", headers=MCP_HEADERS, json={})
    assert resp.status_code == 401
    challenge = resp.headers["www-authenticate"]
    assert f'resource_metadata="{PUBLIC_URL}/.well-known/oauth-protected-resource"' in challenge
    assert 'scope="mcp offline_access"' in challenge


def test_unauthenticated_mcp_omits_pointer_without_oauth(no_oauth_client):
    resp = no_oauth_client.post("/mcp", headers=MCP_HEADERS, json={})
    assert resp.status_code == 401
    assert "resource_metadata" not in resp.headers["www-authenticate"]


# --- Dynamic client registration ---------------------------------------


def _register(client, **overrides) -> dict:
    body = {
        "client_name": "Claude",
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    body.update(overrides)
    resp = client.post("/oauth/register", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_register_issues_a_public_client(client):
    doc = _register(client)
    assert doc["client_id"].startswith("dcr_")
    assert doc["redirect_uris"] == [REDIRECT]
    assert doc["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in doc
    assert db.get_oauth_client(doc["client_id"])["client_name"] == "Claude"


def test_register_allows_loopback_http_for_claude_code(client):
    doc = _register(
        client, redirect_uris=["http://localhost/callback", "http://127.0.0.1/callback"]
    )
    assert len(doc["redirect_uris"]) == 2


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"redirect_uris": []}, "invalid_redirect_uri"),
        ({"redirect_uris": ["http://evil.example/cb"]}, "invalid_redirect_uri"),
        ({"redirect_uris": ["https://ok.example/cb#frag"]}, "invalid_redirect_uri"),
        ({"token_endpoint_auth_method": "client_secret_basic"}, "invalid_client_metadata"),
        ({"grant_types": ["client_credentials"]}, "invalid_client_metadata"),
        ({"response_types": ["token"]}, "invalid_client_metadata"),
    ],
)
def test_register_rejects_bad_metadata(client, overrides, error):
    body = {"redirect_uris": [REDIRECT]}
    body.update(overrides)
    resp = client.post("/oauth/register", json=body)
    assert resp.status_code == 400
    assert resp.json()["error"] == error


def test_register_rejects_non_json_body(client):
    resp = client.post("/oauth/register", content=b"not json")
    assert resp.status_code == 400


# --- Authorize ---------------------------------------------------------


def _authorize_params(client_id, **overrides) -> dict:
    _, challenge = _verifier_and_challenge()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "mcp offline_access",
        "resource": RESOURCE,
        "state": "st4te",
    }
    params.update(overrides)
    return params


def test_authorize_renders_consent(client):
    doc = _register(client)
    resp = client.get("/oauth/authorize", params=_authorize_params(doc["client_id"]))
    assert resp.status_code == 200
    assert "inbox_secret" in resp.text
    assert "claude.ai" in resp.text  # the redirect host is shown to the human
    assert "Approve" in resp.text


def test_authorize_warns_on_loopback_redirect(client):
    doc = _register(client, redirect_uris=["http://localhost/callback"])
    resp = client.get(
        "/oauth/authorize",
        params=_authorize_params(doc["client_id"], redirect_uri="http://localhost:3118/callback"),
    )
    assert resp.status_code == 200
    assert "loopback address" in resp.text


def test_authorize_rejects_unknown_client(client):
    resp = client.get("/oauth/authorize", params=_authorize_params("dcr_nope"))
    assert resp.status_code == 400
    assert "Unknown client" in resp.text


def test_authorize_rejects_unregistered_redirect_uri(client):
    """An unvalidated redirect_uri is answered in-page, never redirected to."""
    doc = _register(client)
    resp = client.get(
        "/oauth/authorize",
        params=_authorize_params(doc["client_id"], redirect_uri="https://evil.example/cb"),
    )
    assert resp.status_code == 400
    assert "location" not in resp.headers


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge": ""}, "invalid_request"),
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"resource": "https://elsewhere.example/mcp"}, "invalid_target"),
        ({"scope": "admin"}, "invalid_scope"),
    ],
)
def test_authorize_redirects_errors_to_the_client(client, overrides, error):
    doc = _register(client)
    resp = client.get("/oauth/authorize", params=_authorize_params(doc["client_id"], **overrides))
    assert resp.status_code == 302
    assert f"error={error}" in resp.headers["location"]


def _consent(client, client_id, secret, ns, **overrides) -> dict:
    _, challenge = _verifier_and_challenge()
    form = {
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "state": "st4te",
        "code_challenge": challenge,
        "scope": "mcp offline_access",
        "ns": ns,
        "inbox_secret": secret,
        "action": "approve",
    }
    form.update(overrides)
    return client.post("/oauth/authorize", data=form)


def test_consent_issues_a_code(client, world):
    doc = _register(client)
    resp = _consent(client, doc["client_id"], world["bob"]["secret"], world["ns"])
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(f"{REDIRECT}?")
    assert "state=st4te" in location
    assert "code=" in location


def test_consent_denied_redirects_with_access_denied(client, world):
    doc = _register(client)
    resp = _consent(client, doc["client_id"], world["bob"]["secret"], world["ns"], action="deny")
    assert resp.status_code == 302
    assert "error=access_denied" in resp.headers["location"]


def test_consent_rejects_a_wrong_secret(client, world):
    doc = _register(client)
    resp = _consent(client, doc["client_id"], "not-a-real-secret", world["ns"])
    assert resp.status_code == 403


def test_consent_rejects_a_secret_from_another_namespace(client, world):
    doc = _register(client)
    resp = _consent(client, doc["client_id"], world["bob"]["secret"], "0000000000000000")
    assert resp.status_code == 403


# --- Token endpoint ----------------------------------------------------


def _code_for(client, world, identity="bob") -> tuple[str, str]:
    doc = _register(client)
    resp = _consent(client, doc["client_id"], world[identity]["secret"], world["ns"])
    code = resp.headers["location"].split("code=")[1].split("&")[0]
    return doc["client_id"], code


def _exchange(client, cid, code, **overrides):
    verifier, _ = _verifier_and_challenge()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": cid,
        "code_verifier": verifier,
        "resource": RESOURCE,
    }
    form.update(overrides)
    return client.post("/oauth/token", data=form)


def test_token_exchange_returns_access_and_refresh(client, world):
    client_id, code = _code_for(client, world)
    resp = _exchange(client, client_id, code)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "mcp offline_access"
    assert body["refresh_token"]
    assert resp.headers["cache-control"] == "no-store"
    # Stored hashed, never in the clear.
    assert db.get_oauth_token(hash_secret(body["access_token"]), "access") is not None


def test_token_exchange_without_offline_access_has_no_refresh_token(client, world):
    doc = _register(client)
    resp = _consent(client, doc["client_id"], world["bob"]["secret"], world["ns"], scope="mcp")
    code = resp.headers["location"].split("code=")[1].split("&")[0]
    body = _exchange(client, doc["client_id"], code).json()
    assert body["scope"] == "mcp"
    assert "refresh_token" not in body


@pytest.mark.parametrize(
    "overrides",
    [
        {"code_verifier": "b" * 64},
        {"code_verifier": ""},
        {"redirect_uri": "https://claude.ai/other"},
        {"client_id": "dcr_someone_else"},
    ],
)
def test_token_exchange_rejects_a_mismatched_request(client, world, overrides):
    client_id, code = _code_for(client, world)
    resp = _exchange(client, client_id, code, **overrides)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_token_exchange_rejects_a_foreign_resource(client, world):
    client_id, code = _code_for(client, world)
    resp = _exchange(client, client_id, code, resource="https://elsewhere.example/mcp")
    assert resp.json()["error"] == "invalid_target"


def test_authorization_code_is_single_use(client, world):
    client_id, code = _code_for(client, world)
    assert _exchange(client, client_id, code).status_code == 200
    replay = _exchange(client, client_id, code)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


def test_expired_authorization_code_is_refused(client, world):
    client_id, code = _code_for(client, world)
    stale = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    conn = db.get_connection()
    conn.execute(
        "UPDATE oauth_auth_codes SET expires_at = ? WHERE code_hash = ?",
        (stale, hash_secret(code)),
        name="test.expire_code",
    )
    conn.commit()
    resp = _exchange(client, client_id, code)
    assert resp.json()["error"] == "invalid_grant"


def test_unsupported_grant_type(client):
    resp = client.post("/oauth/token", data={"grant_type": "client_credentials"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


def test_refresh_rotates_and_invalidates_the_old_token(client, world):
    client_id, code = _code_for(client, world)
    first = _exchange(client, client_id, code).json()
    rotated = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": first["refresh_token"],
            "client_id": client_id,
            "resource": RESOURCE,
        },
    )
    assert rotated.status_code == 200
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]


def test_reusing_a_rotated_refresh_token_revokes_the_grant(client, world):
    client_id, code = _code_for(client, world)
    first = _exchange(client, client_id, code).json()
    client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
    )
    replay = client.post(
        "/oauth/token",
        data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    # The whole lineage dies, including the access token from the first exchange.
    resp = client.post(
        "/mcp",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {first['access_token']}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code == 401


def test_refresh_rejects_an_unknown_token(client):
    resp = client.post(
        "/oauth/token", data={"grant_type": "refresh_token", "refresh_token": "nope"}
    )
    assert resp.json()["error"] == "invalid_grant"


# --- Resource server: identity scoping ---------------------------------


def _mcp(client, token, method, params=None, request_id=1):
    body = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        body["params"] = params
    return client.post(
        "/mcp",
        headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
        json=body,
    )


def _access_token(client, world, identity="bob") -> str:
    client_id, code = _code_for(client, world, identity=identity)
    return _exchange(client, client_id, code).json()["access_token"]


def test_oauth_token_authenticates_the_mcp_endpoint(client, world):
    token = _access_token(client, world)
    resp = _mcp(client, token, "tools/list")
    assert resp.status_code == 200
    names = {t["name"] for t in resp.json()["result"]["tools"]}
    assert names == {"list_rooms", "read_room", "send_message"}


def test_the_url_identity_route_coexists(client, world):
    """OAuth on the bare path does not disturb POST /mcp/{ns}/{secret}."""
    resp = client.post(
        f"/mcp/{world['ns']}/{world['bob']['secret']}",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code == 200
    assert len(resp.json()["result"]["tools"]) == 3


def test_mcp_route_does_not_redirect(client, world):
    """A bare /mcp must answer directly; a Mount here would 307 to /mcp/."""
    resp = _mcp(client, _access_token(client, world), "tools/list")
    assert resp.status_code == 200
    assert "location" not in resp.headers


def test_a_tool_call_acts_as_the_consented_identity(client, world):
    """The message lands attributed to bob, who consented — not to the static identity."""
    token = _access_token(client, world, identity="bob")
    resp = _mcp(
        client,
        token,
        "tools/call",
        {"name": "send_message", "arguments": {"room_id": world["room_id"], "body": "from bob"}},
    )
    assert resp.status_code == 200
    payload = json.loads(resp.json()["result"]["content"][0]["text"])
    assert payload["mid"]

    with TestClient(deaddrop_app) as plain:
        messages = plain.get(
            f"/{world['ns']}/rooms/{world['room_id']}/messages",
            headers={"X-Inbox-Secret": world["alice"]["secret"]},
        ).json()["messages"]
    sent = [m for m in messages if m["body"] == "from bob"]
    assert len(sent) == 1
    assert sent[0]["from_id"] == world["bob"]["id"]


def test_two_grants_act_as_their_own_identities(client, world):
    """One server, two tokens, two identities — the point of identity scoping."""
    bob_token = _access_token(client, world, identity="bob")
    alice_token = _access_token(client, world, identity="alice")
    for token, expected in ((bob_token, world["bob"]["id"]), (alice_token, world["alice"]["id"])):
        resp = _mcp(
            client,
            token,
            "tools/call",
            {
                "name": "send_message",
                "arguments": {"room_id": world["room_id"], "body": f"hello from {expected}"},
            },
        )
        assert resp.status_code == 200

    with TestClient(deaddrop_app) as plain:
        messages = plain.get(
            f"/{world['ns']}/rooms/{world['room_id']}/messages",
            headers={"X-Inbox-Secret": world["alice"]["secret"]},
        ).json()["messages"]
    by_body = {m["body"]: m["from_id"] for m in messages}
    assert by_body[f"hello from {world['bob']['id']}"] == world["bob"]["id"]
    assert by_body[f"hello from {world['alice']['id']}"] == world["alice"]["id"]


def test_expired_access_token_is_rejected(client, world):
    token = _access_token(client, world)
    conn = db.get_connection()
    conn.execute(
        "UPDATE oauth_tokens SET expires_at = ? WHERE token_hash = ?",
        ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), hash_secret(token)),
        name="test.expire_access_token",
    )
    conn.commit()
    assert _mcp(client, token, "tools/list").status_code == 401


def test_token_audienced_elsewhere_is_rejected(client, world):
    """Audience binding is re-checked at the resource, not trusted from issuance."""
    token = _access_token(client, world)
    conn = db.get_connection()
    conn.execute(
        "UPDATE oauth_grants SET resource = ?",
        ("https://elsewhere.example/mcp",),
        name="test.retarget_grant",
    )
    conn.commit()
    assert _mcp(client, token, "tools/list").status_code == 401


def test_revoking_a_grant_kills_its_tokens(client, world):
    token = _access_token(client, world)
    assert _mcp(client, token, "tools/list").status_code == 200
    grant_id = db.get_oauth_token(hash_secret(token), "access")["grant_id"]
    db.revoke_oauth_grant(grant_id)
    assert _mcp(client, token, "tools/list").status_code == 401


def test_a_random_bearer_is_rejected(client):
    assert _mcp(client, "not-a-token", "tools/list").status_code == 401


def test_sealed_secret_is_not_stored_in_the_clear(client, world):
    _access_token(client, world)
    conn = db.get_connection()
    row = conn.execute(
        "SELECT inbox_secret_enc FROM oauth_grants", name="test.read_grant"
    ).fetchone()
    assert world["bob"]["secret"] not in row[0]


def test_purge_clears_consumed_codes_and_dead_tokens(client, world):
    token = _access_token(client, world)
    db.revoke_oauth_token(hash_secret(token))
    purged = db.purge_expired_oauth_records()
    assert purged["codes"] >= 1
    assert purged["tokens"] >= 1
