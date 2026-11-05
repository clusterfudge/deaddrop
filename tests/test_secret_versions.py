"""Versioned identity secrets: auth lookup table, rotation, burns, recovery."""

import asyncio
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from deadrop import api, cache, db, rekey
from deadrop.auth import RETIRED_DETAIL, derive_id, generate_secret, hash_secret

ADMIN = {"X-Admin-Token": "test-admin-token"}
PIN = "424242"


@pytest.fixture
def client():
    return TestClient(api.app)


@pytest.fixture
def world(client):
    ns = client.post("/admin/namespaces", headers=ADMIN).json()
    nsh = {"X-Namespace-Secret": ns["secret"]}

    def ident(name, **extra):
        body = {"metadata": {"display_name": name}, **extra}
        resp = client.post(f"/{ns['ns']}/identities", headers=nsh, json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    sean = ident("Sean", pin=PIN, recovery_email="sean@example.invalid")
    fritz = ident("Fritz")
    room = client.post(
        f"/{ns['ns']}/rooms",
        headers={"X-Inbox-Secret": sean["secret"]},
        json={"display_name": "general"},
    ).json()
    client.post(
        f"/{ns['ns']}/rooms/{room['room_id']}/members",
        headers={"X-Inbox-Secret": sean["secret"]},
        json={"identity_id": fritz["id"]},
    )
    client.post(
        f"/{ns['ns']}/rooms/{room['room_id']}/messages",
        headers={"X-Inbox-Secret": sean["secret"]},
        json={"body": "before the rekey"},
    )
    return {"ns": ns["ns"], "nsh": nsh, "sean": sean, "fritz": fritz, "room": room["room_id"]}


def _msgs(client, w, secret):
    return client.get(f"/{w['ns']}/rooms/{w['room']}/messages", headers={"X-Inbox-Secret": secret})


def _rekey(client, w, identity_id, **body):
    resp = client.post(f"/{w['ns']}/identities/{identity_id}/rekey", headers=w["nsh"], json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _versions(client, w, identity_id):
    rows = client.get(f"/{w['ns']}/rekeys", headers=w["nsh"]).json()
    row = next(r for r in rows if r["identity_id"] == identity_id)
    return {v["version"]: v for v in row["versions"]}


def _raw_conn():
    """A second connection to the test DB that bypasses write-through.

    Stands in for another server process writing the same database.
    """
    conn = db.get_connection()
    return conn


# --- ids and lookups ---------------------------------------------------------


def test_new_identity_id_is_independent_of_secret(world):
    sean = world["sean"]
    assert sean["id"] != derive_id(sean["secret"])
    entry = cache.secret_map.get(hash_secret(sean["secret"]))
    assert entry is not None and entry.identity_id == sean["id"] and entry.version == 1


def test_auth_is_served_from_memory_after_load(client, world, monkeypatch):
    cache.secret_map.clear()
    assert db.load_secret_map() >= 2
    assert cache.secret_map.loaded

    def boom(*a, **k):
        raise AssertionError("auth touched identity_secrets")

    monkeypatch.setattr(db, "_secret_entries", boom)
    monkeypatch.setattr(db, "get_auth_generation", boom)
    assert _msgs(client, world, world["sean"]["secret"]).status_code == 200
    resp = client.get(
        f"/{world['ns']}/inbox/{world['fritz']['id']}",
        headers={"X-Inbox-Secret": world["fritz"]["secret"]},
    )
    assert resp.status_code == 200


def test_startup_loads_the_table(world):
    cache.secret_map.clear()
    with TestClient(api.app):
        assert cache.secret_map.loaded
        assert cache.secret_map.get(hash_secret(world["sean"]["secret"])) is not None


def test_unknown_hash_flood_costs_at_most_one_generation_read(world, monkeypatch):
    db.load_secret_map()
    calls = []
    real = db.get_auth_generation
    monkeypatch.setattr(db, "get_auth_generation", lambda c=None: calls.append(1) or real(c))
    monkeypatch.setattr(db, "AUTH_MISS_REFRESH_SECONDS", 60.0)
    cache.secret_map.last_refresh = 0.0
    for _ in range(200):
        assert db.authenticate_secret(generate_secret()) == (None, db.AUTH_UNKNOWN)
    assert len(calls) == 1


def test_secret_in_wrong_namespace_is_unknown(client, world):
    other = client.post("/admin/namespaces", headers=ADMIN).json()
    resp = client.get(
        f"/{other['ns']}/identities", headers={"X-Inbox-Secret": world["sean"]["secret"]}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] != RETIRED_DETAIL


# --- migration ---------------------------------------------------------------


def test_migration_seeds_existing_identities_with_unchanged_ids():
    conn = db._get_conn(sqlite3.connect(":memory:"))
    conn.executescript(db.SCHEMA_SQL)
    db._ensure_schema_version_table(conn)
    for version, desc, fn in db.MIGRATIONS:
        if version < 10:
            fn(conn)
            db.record_migration(conn, version, desc)
    conn.execute("INSERT INTO namespaces (ns, secret_hash) VALUES ('ns1', 'x')", name="test")
    legacy = generate_secret()
    conn.execute(
        "INSERT INTO identities (id, ns, secret_hash) VALUES (?, 'ns1', ?)",
        (derive_id(legacy), hash_secret(legacy)),
        name="test",
    )
    conn.commit()

    assert db.run_migrations(conn) == [10]
    rows = conn.execute(
        "SELECT identity_id, version, status FROM identity_secrets WHERE secret_hash = ?",
        (hash_secret(legacy),),
        name="test",
    ).fetchall()
    assert rows == [(derive_id(legacy), 1, "active")]
    assert db.authenticate_secret(legacy, "ns1", conn=conn) == (derive_id(legacy), None)


def test_legacy_identity_keeps_working_over_header_auth(client, world):
    legacy = generate_secret()
    legacy_id = derive_id(legacy)
    c = db.get_connection()
    c.execute(
        "INSERT INTO identities (id, ns, secret_hash) VALUES (?, ?, ?)",
        (legacy_id, world["ns"], hash_secret(legacy)),
        name="test",
    )
    db._insert_secret_version(c, world["ns"], legacy_id, hash_secret(legacy), 1, switch_grace=None)
    db._bump_auth_generation(c)
    c.commit()
    db.reload_identity_secrets(world["ns"], legacy_id)

    resp = client.get(f"/{world['ns']}/inbox/{legacy_id}", headers={"X-Inbox-Secret": legacy})
    assert resp.status_code == 200
    # And it can be rotated without its id changing.
    new = _rekey(client, world, legacy_id)
    resp = client.get(
        f"/{world['ns']}/inbox/{legacy_id}", headers={"X-Inbox-Secret": new["secret"]}
    )
    assert resp.status_code == 200
    resp = client.get(f"/{world['ns']}/inbox/{legacy_id}", headers={"X-Inbox-Secret": legacy})
    assert resp.status_code == 403 and resp.json()["detail"] == RETIRED_DETAIL


# --- rotation ------------------------------------------------------------------


def test_rekey_keeps_old_until_new_first_use_then_burns_it(client, world):
    w, old = world, world["sean"]["secret"]
    new = _rekey(client, w, w["sean"]["id"])
    assert new["identity_id"] == w["sean"]["id"] and new["version"] == 2
    assert _msgs(client, w, old).status_code == 200  # old still active
    assert _versions(client, w, w["sean"]["id"])[1]["status"] == "active"

    resp = _msgs(client, w, new["secret"])  # first use of v2: the switch
    assert resp.status_code == 200
    body = resp.json()
    msgs = body["messages"] if isinstance(body, dict) else body
    assert [m["body"] for m in msgs] == ["before the rekey"]  # same id, same history

    resp = _msgs(client, w, old)
    assert resp.status_code == 403 and resp.json()["detail"] == RETIRED_DETAIL
    db.flush_secret_activity()
    v = _versions(client, w, w["sean"]["id"])
    assert v[1]["status"] == "burned" and v[1]["burned_attempts"] == 1
    assert v[2]["status"] == "active" and v[2]["last_seen_at"]


def test_old_or_forged_secret_cannot_trigger_the_switch(client, world):
    w, old = world, world["sean"]["secret"]
    _rekey(client, w, w["sean"]["id"])
    for _ in range(3):
        assert _msgs(client, w, old).status_code == 200
        assert _msgs(client, w, generate_secret()).status_code == 403
    db.flush_secret_activity()
    v = _versions(client, w, w["sean"]["id"])
    assert v[1]["status"] == "active" and v[2]["last_seen_at"] is None


def test_burned_secret_cannot_block_the_switch(client, world):
    w, old = world, world["sean"]["secret"]
    new = _rekey(client, w, w["sean"]["id"], revoke_now=True)
    assert new["burned_versions"] == [1]
    assert _msgs(client, w, old).status_code == 403  # immediately, before v2 is used
    assert _msgs(client, w, new["secret"]).status_code == 200
    assert _versions(client, w, w["sean"]["id"])[2]["status"] == "active"


def test_grace_window(client, world):
    w, old = world, world["sean"]["secret"]
    new = _rekey(client, w, w["sean"]["id"], grace_seconds=1)
    assert _msgs(client, w, new["secret"]).status_code == 200
    assert _msgs(client, w, old).status_code == 200  # in grace
    assert _versions(client, w, w["sean"]["id"])[1]["status"] == "grace"
    time.sleep(1.1)
    assert _msgs(client, w, old).status_code == 403  # every process derives this alike
    db.flush_secret_activity()  # sweeps the row to burned
    assert _versions(client, w, w["sean"]["id"])[1]["status"] == "burned"


def test_manual_burn_and_rollback(client, world):
    w, sid = world, world["sean"]["id"]
    base = f"/{w['ns']}/identities/{sid}/secrets"
    resp = client.post(f"{base}/1/burn", headers=w["nsh"])
    assert resp.status_code == 409 and "last live secret" in resp.json()["detail"]
    assert _msgs(client, w, w["sean"]["secret"]).status_code == 200  # refused: still live
    confirm = {"confirm_last_version": True}
    resp = client.post(f"{base}/1/burn", headers=w["nsh"], json=confirm)
    assert resp.status_code == 200 and resp.json()["live_versions"] == 0
    assert _msgs(client, w, w["sean"]["secret"]).status_code == 403  # write-through, no refresh
    assert client.post(f"{base}/1/burn", headers=w["nsh"]).status_code == 409
    assert client.post(f"{base}/9/burn", headers=w["nsh"]).status_code == 404
    assert client.post(f"{base}/1/burn", headers={"X-Inbox-Secret": "x"}).status_code == 401

    assert client.post(f"{base}/1/rollback", headers=w["nsh"]).status_code == 200
    assert _msgs(client, w, w["sean"]["secret"]).status_code == 200


def test_burning_a_non_last_version_needs_no_confirm(client, world):
    w, sid, old = world, world["sean"]["id"], world["sean"]["secret"]
    new = _rekey(client, w, sid)
    base = f"/{w['ns']}/identities/{sid}/secrets"
    resp = client.post(f"{base}/1/burn", headers=w["nsh"])
    assert resp.status_code == 200 and resp.json()["live_versions"] == 1
    assert _msgs(client, w, old).status_code == 403
    assert client.post(f"{base}/2/burn", headers=w["nsh"]).status_code == 409  # now the last
    assert _msgs(client, w, new["secret"]).status_code == 200


def test_expired_grace_does_not_count_as_live(client, world):
    w, sid = world, world["sean"]["id"]
    new = _rekey(client, w, sid, grace_seconds=1)
    assert _msgs(client, w, new["secret"]).status_code == 200  # v1 -> grace
    time.sleep(1.1)
    base = f"/{w['ns']}/identities/{sid}/secrets"
    assert client.post(f"{base}/2/burn", headers=w["nsh"]).status_code == 409


def test_cli_burn_sends_confirm_only_with_yes(monkeypatch, capsys):
    from deadrop import cli

    sent = []

    class Resp:
        def json(self):
            return {"live_versions": 0}

    monkeypatch.setattr(cli, "get_namespace_config", lambda ns: object())
    monkeypatch.setattr(
        cli, "_rekey_http", lambda *a, json_data=None: sent.append(json_data) or Resp()
    )
    cli.rekey_burn_cmd("ns", "ident", 1)
    cli.rekey_burn_cmd("ns", "ident", 1, yes=True)
    assert sent == [{"confirm_last_version": False}, {"confirm_last_version": True}]


def test_rollback_survives_restart(client, world):
    w, sid, old = world, world["sean"]["id"], world["sean"]["secret"]
    new = _rekey(client, w, sid)
    assert _msgs(client, w, new["secret"]).status_code == 200
    client.post(f"/{w['ns']}/identities/{sid}/secrets/1/rollback", headers=w["nsh"])
    cache.secret_map.clear()
    db.load_secret_map()
    assert _msgs(client, w, new["secret"]).status_code == 200  # no second switch
    assert _msgs(client, w, old).status_code == 200


def test_dry_run_prints_counts_only(client, world):
    data = _rekey(client, world, world["sean"]["id"], dry_run=True)
    assert "secret" not in data
    assert data["plan"]["versions"] == {"active": 1, "grace": 0, "burned": 0}
    assert data["plan"]["rooms"] == 1
    assert len(_versions(client, world, world["sean"]["id"])) == 1


def test_status_carries_no_secret_material(client, world):
    _rekey(client, world, world["sean"]["id"], pin="135791")
    text = client.get(f"/{world['ns']}/rekeys", headers=world["nsh"]).text
    assert world["sean"]["secret"] not in text
    assert hash_secret(world["sean"]["secret"]) not in text
    assert "scrypt$" not in text and "135791" not in text


def test_delete_identity_drops_its_secrets(client, world):
    w = world
    assert (
        client.delete(f"/{w['ns']}/identities/{w['fritz']['id']}", headers=w["nsh"]).status_code
        == 200
    )
    assert cache.secret_map.get(hash_secret(w["fritz"]["secret"])) is None
    resp = client.get(f"/{w['ns']}/identities", headers={"X-Inbox-Secret": w["fritz"]["secret"]})
    assert resp.status_code == 403


# --- other processes -------------------------------------------------------------


def _burn_behind_our_back(ns, identity_id, version):
    """What another process's burn looks like here: DB changed, map untouched."""
    c = _raw_conn()
    c.execute(
        "UPDATE identity_secrets SET status = 'burned' WHERE ns = ? AND identity_id = ? "
        "AND version = ?",
        (ns, identity_id, version),
        name="test",
    )
    c.execute("UPDATE auth_generation SET gen = gen + 1 WHERE id = 1", name="test")
    c.commit()


def test_other_process_burn_is_stale_until_refresh(client, world):
    w = world
    db.load_secret_map()
    _burn_behind_our_back(w["ns"], w["sean"]["id"], 1)
    assert _msgs(client, w, w["sean"]["secret"]).status_code == 200  # stale copy
    assert db.refresh_secret_map() is True
    assert _msgs(client, w, w["sean"]["secret"]).status_code == 403
    assert db.refresh_secret_map() is False  # one generation read, no reload


def test_refresh_loop_bounds_staleness(world, monkeypatch):
    w = world
    interval = 0.2
    monkeypatch.setattr(db, "AUTH_REFRESH_SECONDS", interval)
    db.load_secret_map()
    secret_hash = hash_secret(w["sean"]["secret"])

    async def run():
        task = asyncio.create_task(api._auth_refresh_loop())
        await asyncio.sleep(0.05)
        _burn_behind_our_back(w["ns"], w["sean"]["id"], 1)
        burned_at = time.monotonic()
        while cache.secret_map.get(secret_hash).status != "burned":
            assert time.monotonic() - burned_at < interval + 0.5, "staleness bound exceeded"
            await asyncio.sleep(0.01)
        task.cancel()
        return time.monotonic() - burned_at

    assert asyncio.run(run()) <= interval + 0.5


def test_new_identity_from_another_process_is_found_on_miss(world):
    db.load_secret_map()
    secret = generate_secret()
    c = _raw_conn()
    c.execute(
        "INSERT INTO identities (id, ns, secret_hash) VALUES ('feedfacefeedface', ?, ?)",
        (world["ns"], hash_secret(secret)),
        name="test",
    )
    db._insert_secret_version(
        c, world["ns"], "feedfacefeedface", hash_secret(secret), 1, switch_grace=None
    )
    db._bump_auth_generation(c)
    c.commit()
    cache.secret_map.last_refresh = 0.0
    assert db.authenticate_secret(secret, world["ns"]) == ("feedfacefeedface", None)


def test_identity_written_by_pre_versioning_code_stays_locked_out_until_seeded(
    client, world, capsys
):
    """Old code (deploy overlap, rollback) inserts into identities only."""
    from deadrop import cli

    db.load_secret_map()
    legacy = generate_secret()
    lid = derive_id(legacy)
    c = _raw_conn()
    c.execute(
        "INSERT INTO identities (id, ns, secret_hash) VALUES (?, ?, ?)",
        (lid, world["ns"], hash_secret(legacy)),
        name="test",
    )
    c.commit()
    inbox = f"/{world['ns']}/inbox/{lid}"
    db.flush_secret_activity()  # the refresh tick does not seed
    assert client.get(inbox, headers={"X-Inbox-Secret": legacy}).status_code == 403

    with pytest.raises(SystemExit) as exc:
        cli.rekey_verify_cmd()
    assert exc.value.code == 1
    assert f"{world['ns']}  {lid}" in capsys.readouterr().out

    cli.rekey_seed_cmd(world["ns"], lid)
    db.refresh_secret_map()
    assert client.get(inbox, headers={"X-Inbox-Secret": legacy}).status_code == 200
    assert (world["ns"], lid) not in db.identities_without_v1()
    assert not db.seed_v1(world["ns"], lid)  # already seeded
    assert not db.seed_v1(world["ns"], "0000000000000000")  # no such identity


def test_burned_v1_is_unmatchable_in_the_legacy_column(client, world):
    """A code rollback authenticates from identities.secret_hash; burned must stay burned."""
    w, sid = world, world["sean"]["id"]

    def legacy_column():
        row = _raw_conn().execute(
            "SELECT secret_hash FROM identities WHERE ns = ? AND id = ?",
            (w["ns"], sid),
            name="test",
        )
        return row.fetchone()[0]

    v1_hash = hash_secret(w["sean"]["secret"])
    new = _rekey(client, w, sid)
    assert legacy_column() == v1_hash  # v1 still live until v2's first use
    assert _msgs(client, w, new["secret"]).status_code == 200
    assert legacy_column() == "retired:" + v1_hash
    resp = client.post(f"/{w['ns']}/identities/{sid}/secrets/1/rollback", headers=w["nsh"])
    assert resp.status_code == 200, resp.text
    assert legacy_column() == v1_hash


# --- recovery invites and PIN ------------------------------------------------------


def _recovery_invite(client, w, identity_id, invite_id, **extra):
    body = {
        "identity_id": identity_id,
        "invite_id": invite_id,
        "encrypted_secret": "00" * 32,
        "recovery": True,
        **extra,
    }
    return client.post(f"/{w['ns']}/invites", headers=w["nsh"], json=body)


def _claim(client, invite_id, pin=None):
    return client.post(f"/api/invites/{invite_id}/claim", json={"pin": pin} if pin else None)


def test_recovery_invite_needs_pin_and_is_single_use(client, world):
    w = world
    assert _recovery_invite(client, w, w["sean"]["id"], "inv-a").status_code == 200
    info = client.get("/api/invites/inv-a/info").json()
    assert info["requires_pin"] is True
    assert _claim(client, "inv-a").status_code == 401
    assert _claim(client, "inv-a", "000000").status_code == 403
    resp = _claim(client, "inv-a", PIN)  # wrong PINs did not consume it
    assert resp.status_code == 200 and resp.json()["identity_id"] == w["sean"]["id"]
    assert _claim(client, "inv-a", PIN).status_code == 410


def test_recovery_invite_needs_a_pin_on_file(client, world):
    assert _recovery_invite(client, world, world["fritz"]["id"], "inv-f").status_code == 409


def test_reissue_revokes_previous_and_ttl_is_capped(client, world):
    w = world
    far = "2999-01-01T00:00:00+00:00"
    _recovery_invite(client, w, w["sean"]["id"], "inv-1", expires_at=far)
    second = _recovery_invite(client, w, w["sean"]["id"], "inv-2", expires_at=far).json()
    assert client.get("/api/invites/inv-1/info").status_code == 404
    from datetime import datetime, timezone

    left = datetime.fromisoformat(second["expires_at"]) - datetime.now(timezone.utc)
    assert left.total_seconds() <= rekey.RECOVERY_INVITE_MAX_SECONDS


def test_expired_recovery_invite(client, world):
    w = world
    _recovery_invite(client, w, w["sean"]["id"], "inv-x", expires_at="2000-01-01T00:00:00+00:00")
    assert _claim(client, "inv-x", PIN).status_code == 410
    rows = client.get(f"/{w['ns']}/rekeys", headers=w["nsh"]).json()
    assert next(r for r in rows if r["identity_id"] == w["sean"]["id"])["pin_failures"] == 0


def test_pin_lockout_and_unlock(client, world):
    w = world
    _recovery_invite(client, w, w["sean"]["id"], "inv-l")
    for _ in range(rekey.PIN_MAX_FAILURES):
        assert _claim(client, "inv-l", "999999").status_code == 403
    assert _claim(client, "inv-l", PIN).status_code == 423  # locked, even with the right PIN
    # Lock is on the identity: a fresh invite is locked too.
    _recovery_invite(client, w, w["sean"]["id"], "inv-m")
    assert _claim(client, "inv-m", PIN).status_code == 423
    unlock = f"/{w['ns']}/identities/{w['sean']['id']}/pin/unlock"
    assert client.post(unlock, headers={"X-Inbox-Secret": w["sean"]["secret"]}).status_code == 401
    assert client.post(unlock, headers=w["nsh"]).status_code == 200
    assert _claim(client, "inv-m", PIN).status_code == 200


def test_set_recovery_email_and_pin(client, world):
    w = world
    url = f"/{w['ns']}/identities/{w['fritz']['id']}/recovery"
    resp = client.put(
        url, headers=w["nsh"], json={"recovery_email": "f@example.invalid", "pin": "246810"}
    )
    assert resp.json() == {
        "identity_id": w["fritz"]["id"],
        "recovery_email": "f@example.invalid",
        "pin_set": True,
    }
    assert client.put(url, headers=w["nsh"], json={"pin": "12"}).status_code == 400
    assert _recovery_invite(client, w, w["fritz"]["id"], "inv-r").status_code == 200


def test_plain_invites_are_unchanged(client, world):
    w = world
    body = {"identity_id": w["fritz"]["id"], "invite_id": "inv-p", "encrypted_secret": "00"}
    assert client.post(f"/{w['ns']}/invites", headers=w["nsh"], json=body).status_code == 200
    assert client.get("/api/invites/inv-p/info").json()["requires_pin"] is False
    assert _claim(client, "inv-p").status_code == 200
    assert _claim(client, "inv-p").status_code == 410


# --- MCP path ------------------------------------------------------------------------


def test_mcp_path_follows_rotation(client, world):
    from deadrop import mcp_server  # noqa: F401  (mounted on api.app)

    w = world
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    new = _rekey(client, w, w["sean"]["id"], revoke_now=True)
    with TestClient(api.app) as c:
        old = c.post(f"/mcp/{w['ns']}/{w['sean']['secret']}", headers=headers, json=body)
        assert old.status_code == 401
        assert w["sean"]["secret"] not in old.text
        fresh = c.post(f"/mcp/{w['ns']}/{new['secret']}", headers=headers, json=body)
        assert fresh.status_code != 401, fresh.text
        assert json.dumps(fresh.status_code)
