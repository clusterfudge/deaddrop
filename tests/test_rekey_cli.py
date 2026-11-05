"""`deadrop rekey` CLI against the in-process API: `rekey all` preflight and namespace lookup."""

import pytest
from fastapi.testclient import TestClient

from deadrop import api, cli
from deadrop.config import GlobalConfig, NamespaceConfig

ADMIN = {"X-Admin-Token": "test-admin-token"}
PIN = "424242"


@pytest.fixture
def server(monkeypatch, tmp_path):
    """Route the CLI's httpx calls to the app; local config under tmp_path."""
    client = TestClient(api.app)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(cli, "get_config", lambda: GlobalConfig(url="http://testserver"))
    fail = {}

    def request(method, url, *, headers=None, json=None, timeout=None):
        if any(part in url for part in fail):
            return client.request(method, "/no-such-route", headers=headers)
        return client.request(method, url, headers=headers, json=json)

    monkeypatch.setattr(cli.httpx, "request", request)
    client.fail = fail
    return client


def _namespace(client, display_name, names, pins=()):
    ns = client.post(
        "/admin/namespaces", headers=ADMIN, json={"metadata": {"display_name": display_name}}
    ).json()
    cfg = NamespaceConfig(ns=ns["ns"], secret=ns["secret"], display_name=display_name)
    ids = {}
    for name in names:
        body = {"metadata": {"display_name": name}}
        if name in pins:
            body["pin"] = PIN
        resp = client.post(
            f"/{ns['ns']}/identities", headers={"X-Namespace-Secret": ns["secret"]}, json=body
        )
        ident = resp.json()
        cfg.add_mailbox(id=ident["id"], secret=ident["secret"], display_name=name)
        ids[name] = ident["id"]
    cfg.save()
    return cfg, ids


def _versions(client, cfg):
    rows = client.get(f"/{cfg.ns}/rekeys", headers={"X-Namespace-Secret": cfg.secret}).json()
    return {r["identity_id"]: len(r["versions"]) for r in rows}


def _local_secrets(cfg):
    return {i: m.secret for i, m in NamespaceConfig.load(cfg.ns).mailboxes.items()}


@pytest.mark.parametrize("dry_run", [False, True])
def test_rekey_all_aborts_before_rotating_when_an_invite_needs_a_missing_pin(
    server, capsys, tmp_path, dry_run
):
    cfg, ids = _namespace(server, "Twin", ["alice", "bob", "carol"], pins={"alice"})
    before = _local_secrets(cfg)
    with pytest.raises(SystemExit) as e:
        cli.rekey_all_cmd(cfg.ns, dry_run=dry_run, invite_dir=str(tmp_path / "inv"))
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "nothing was rotated" in err
    assert ids["bob"] in err and ids["carol"] in err and ids["alice"] not in err
    assert set(_versions(server, cfg).values()) == {1}
    assert _local_secrets(cfg) == before
    assert not (tmp_path / "inv").exists()


def test_rekey_all_runs_when_every_pinless_identity_is_mapped_or_excluded(
    server, capsys, monkeypatch, tmp_path
):
    cfg, ids = _namespace(server, "Twin", ["alice", "bob", "carol"], pins={"alice"})
    cmap = tmp_path / "map.json"
    cmap.write_text(f'{{"{ids["carol"]}": {{"credential": "c", "field": "secret"}}}}')
    monkeypatch.setattr(cli, "_push_credential", lambda *a: True)
    cli.rekey_all_cmd(
        cfg.ns,
        exclude=[ids["bob"]],
        credential_map=str(cmap),
        invite_dir=str(tmp_path / "inv"),
    )
    assert "2/2 rekeyed" in capsys.readouterr().out
    assert _versions(server, cfg) == {ids["alice"]: 2, ids["bob"]: 1, ids["carol"]: 2}
    assert len(list((tmp_path / "inv").iterdir())) == 1  # alice's recovery invite


def test_rekey_all_no_invite_skips_the_pin_check(server, capsys):
    cfg, ids = _namespace(server, "Twin", ["alice", "bob"])
    cli.rekey_all_cmd(cfg.ns, invite=False)
    assert set(_versions(server, cfg).values()) == {2}


def test_rekey_all_mid_run_failure_lists_rotated_and_not_rotated(server, capsys):
    cfg, ids = _namespace(server, "Twin", ["alice", "bob", "carol"])
    before = _local_secrets(cfg)
    order = [
        i["id"]
        for i in server.get(
            f"/{cfg.ns}/identities", headers={"X-Namespace-Secret": cfg.secret}
        ).json()
    ]
    server.fail[f"/identities/{order[1]}/rekey"] = True
    with pytest.raises(SystemExit) as e:
        cli.rekey_all_cmd(cfg.ns, invite=False)
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert f"ABORTED at {order[1]}: 1/3 rotated" in err
    assert f"rotated      {order[0]}  new secret in {cfg.get_path()}" in err
    assert f"NOT rotated  {order[1]}" in err and f"NOT rotated  {order[2]}" in err
    after = _local_secrets(cfg)
    assert [after[i] != before[i] for i in order] == [True, False, False]
    assert [_versions(server, cfg)[i] for i in order] == [2, 1, 1]


def test_rekey_namespace_by_display_name_or_id_prefix(server, capsys):
    cfg, _ = _namespace(server, "Twin", ["alice"])
    _namespace(server, "Other", ["bob"])
    for arg in ("twin", "Twin", cfg.ns[:6], cfg.ns):
        cli.rekey_status_cmd(arg)
        assert capsys.readouterr().out.endswith("1 identities\n")
        assert cli._rekey_ns_config(arg).ns == cfg.ns


def test_rekey_namespace_ambiguous_or_unknown_lists_candidates(server, capsys):
    a, _ = _namespace(server, "Twin", ["alice"])
    b, _ = _namespace(server, "twin", ["bob"])
    with pytest.raises(SystemExit):
        cli.rekey_status_cmd("twin")
    err = capsys.readouterr().err
    assert "ambiguous" in err and f"{a.ns}  Twin" in err and f"{b.ns}  twin" in err
    with pytest.raises(SystemExit):
        cli.rekey_status_cmd("nope")
    err = capsys.readouterr().err
    assert "no local namespace matches 'nope'" in err and a.ns in err and b.ns in err
