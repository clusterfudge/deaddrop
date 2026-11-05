#!/usr/bin/env python3
"""Rehearse migration 010 on a throwaway Turso copy of production.

NOTHING here touches the source database except the copy request itself,
which Turso serves from its own storage (point-in-time seed); the source is
never opened, written or given a token.

    python scripts/rehearse_on_turso_clone.py plan       # offline: print the steps
    python scripts/rehearse_on_turso_clone.py create     # copy deaddrop-east -> clone
    python scripts/rehearse_on_turso_clone.py verify-v9  # read-only checks, pre-migration
    python scripts/rehearse_on_turso_clone.py migrate    # new code's startup path on the clone
    python scripts/rehearse_on_turso_clone.py verify     # read-only checks, post-migration
    python scripts/rehearse_on_turso_clone.py run        # old+new servers vs the clone
    python scripts/rehearse_on_turso_clone.py teardown   # destroy the clone

Credentials: the Turso platform token is read from the credential store
entry ``turso`` inside this process (bridge :9877, else :9876) and never
printed. The clone's database token is minted for the clone only, lives in
memory/env of child processes, and expires in a day.

Guards: every mutating platform call asserts the target name starts with
``deaddrop-rehearsal-`` and is not the source. Child servers get an
environment with no DEADROP_*/GRAFANA_*/VAPID settings, so no push
notifications to real devices, no metrics, no deploy annotations.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

ORG = os.environ.get("TURSO_ORG", "clusterfudge")
SOURCE = "deaddrop-east"
GROUP = os.environ.get("TURSO_GROUP", "east")
CLONE = os.environ.get("REHEARSAL_DB", f"deaddrop-rehearsal-{date.today():%Y%m%d}")
API = "https://api.turso.tech/v1"
HERE = Path(__file__).resolve().parent
NEW_TREE = Path(os.environ.get("NEW_TREE", HERE.parent))


def _guard(name: str) -> None:
    if name == SOURCE or not name.startswith("deaddrop-rehearsal-"):
        sys.exit(f"refusing to touch {name!r}: not a rehearsal database")


def _platform_token() -> str:
    last: Exception | None = None
    for base in ("http://127.0.0.1:9877", "http://127.0.0.1:9876"):
        try:
            with urllib.request.urlopen(f"{base}/api/credentials/turso", timeout=10) as r:
                d = json.load(r)
            d = d.get("data", d)
            tok = d.get("api_token") or d.get("token") or d.get("api_key") or d.get("secret")
            if tok:
                return tok
        except Exception as e:  # noqa: BLE001 - try the next source
            last = e
    sys.exit(
        f"credential 'turso' unavailable ({type(last).__name__ if last else 'no token field'})"
    )


def _api(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "Authorization": f"Bearer {_platform_token()}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path}: HTTP {e.code} {e.read()[:300]!r}")


def _clone_env() -> dict[str, str]:
    """TURSO_URL/TURSO_AUTH_TOKEN for the clone only (token minted, never printed)."""
    _guard(CLONE)
    info = _api("GET", f"/organizations/{ORG}/databases/{CLONE}")["database"]
    host = info["Hostname"]
    if not host.startswith(f"{CLONE}-"):
        sys.exit(f"clone hostname {host!r} does not belong to {CLONE}")
    tok = _api(
        "POST",
        f"/organizations/{ORG}/databases/{CLONE}/auth/tokens?expiration=1d&authorization=full-access",
    )["jwt"]
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("DEADROP_", "GRAFANA_", "VAPID", "TURSO_", "HEARE_AUTH"))
    }
    env["TURSO_URL"] = f"libsql://{host}"
    env["TURSO_AUTH_TOKEN"] = tok
    return env


def cmd_plan() -> None:
    print(__doc__)
    print(f"org={ORG} source={SOURCE} group={GROUP} clone={CLONE}")
    print(
        "pre-checks: GET /organizations/{org}/subscription, /usage, /databases (db count vs plan)"
    )


def cmd_create() -> None:
    _guard(CLONE)
    sub = _api("GET", f"/organizations/{ORG}/subscription")
    dbs = _api("GET", f"/organizations/{ORG}/databases").get("databases", [])
    print(f"plan: {sub.get('subscription', {}).get('plan', '?')}  databases: {len(dbs)}")
    if any(d.get("Name") == CLONE for d in dbs):
        sys.exit(f"{CLONE} already exists; teardown first or set REHEARSAL_DB")
    out = _api(
        "POST",
        f"/organizations/{ORG}/databases",
        {"name": CLONE, "group": GROUP, "seed": {"type": "database", "name": SOURCE}},
    )
    print(f"created {out['database']['Name']} on {out['database']['Hostname']}")


def _checks(env: dict[str, str], expect_version: int) -> int:
    code = r"""
import sys
from deadrop.turso_http import TursoConnection
import os
c = TursoConnection(os.environ["TURSO_URL"], os.environ["TURSO_AUTH_TOKEN"])
q = lambda s: c.execute(s).fetchall()
v = q("SELECT MAX(version) FROM schema_version")[0][0]
fails = 0
def check(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(("PASS " if ok else "FAIL ") + name + ("  " + str(detail) if detail else ""))
check("schema_version", v == EXPECT, v)
n_ident = q("SELECT COUNT(*) FROM identities")[0][0]
print(f"identities={n_ident}  namespaces={q('SELECT COUNT(*) FROM namespaces')[0][0]}"
      f"  rooms={q('SELECT COUNT(*) FROM rooms')[0][0]}"
      f"  room_messages={q('SELECT COUNT(*) FROM room_messages')[0][0]}")
if EXPECT >= 10:
    n_v1 = q("SELECT COUNT(*) FROM identity_secrets WHERE version = 1")[0][0]
    check("every identity has exactly one v1 row", n_v1 == n_ident, f"{n_v1}/{n_ident}")
    check("no identity without versions", q(
        "SELECT COUNT(*) FROM identities i WHERE NOT EXISTS (SELECT 1 FROM identity_secrets s"
        " WHERE s.ns = i.ns AND s.identity_id = i.id)")[0][0] == 0)
    check("no orphan secret rows", q(
        "SELECT COUNT(*) FROM identity_secrets s WHERE NOT EXISTS (SELECT 1 FROM identities i"
        " WHERE i.ns = s.ns AND i.id = s.identity_id)")[0][0] == 0)
    bad = q("SELECT COUNT(*) FROM identity_secrets s JOIN identities i"
            " ON i.ns = s.ns AND i.id = s.identity_id WHERE s.version = 1 AND"
            " (s.secret_hash != i.secret_hash OR substr(s.secret_hash, 1, 16) != i.id)"
            " AND s.status != 'burned'")[0][0]
    check("v1 hash == identities.secret_hash and id == hash[:16] (legacy ids)", bad == 0, bad)
    check("auth_generation seeded", q("SELECT COUNT(*) FROM auth_generation")[0][0] == 1)
    check("no recovery invites yet", q(
        "SELECT COUNT(*) FROM invites WHERE recovery != 0")[0][0] == 0)
    sample = q("SELECT s.identity_id, substr(s.secret_hash,1,16) = s.identity_id"
               " FROM identity_secrets s ORDER BY random() LIMIT 5")
    print("sample id -> hash[:16] match:", [(r[0], bool(r[1])) for r in sample])
sys.exit(1 if fails else 0)
""".replace("EXPECT", str(expect_version))
    return subprocess.call(
        [str(NEW_TREE / ".venv/bin/python"), "-c", code], env=env, cwd=NEW_TREE / "src"
    )


def cmd_verify_v9() -> None:
    sys.exit(_checks(_clone_env(), 9))


def cmd_verify() -> None:
    sys.exit(_checks(_clone_env(), 10))


def cmd_migrate() -> None:
    """Exactly what the lifespan hook runs before serving: init_db + seeding."""
    code = (
        "import time; from deadrop import db; t = time.monotonic(); db.init_db();"
        " n = db.seed_unversioned_identities();"
        " print(f'migrated to v{db.get_schema_version()} in {time.monotonic() - t:.1f}s;'"
        " f' late-seeded {n}')"
    )
    sys.exit(
        subprocess.call(
            [str(NEW_TREE / ".venv/bin/python"), "-c", code], env=_clone_env(), cwd=NEW_TREE / "src"
        )
    )


def cmd_run() -> None:
    env = _clone_env()
    sys.exit(subprocess.call([sys.executable, str(HERE / "compat_old_new.py")], env=env))


def cmd_teardown() -> None:
    _guard(CLONE)
    _api("DELETE", f"/organizations/{ORG}/databases/{CLONE}")
    print(f"destroyed {CLONE}")


if __name__ == "__main__":
    cmds = {
        "plan": cmd_plan,
        "create": cmd_create,
        "verify-v9": cmd_verify_v9,
        "migrate": cmd_migrate,
        "verify": cmd_verify,
        "run": cmd_run,
        "teardown": cmd_teardown,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(f"usage: {sys.argv[0]} {{{','.join(cmds)}}}")
    cmds[sys.argv[1]]()
