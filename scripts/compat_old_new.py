#!/usr/bin/env python3
"""Cross-version compat check: old (pre-#127) and new deaddrop servers on one DB.

Boots real uvicorn processes from two checkouts against the same database and
drives them over HTTP. With no TURSO_URL set it uses a throwaway sqlite file;
with TURSO_URL/TURSO_AUTH_TOKEN in the environment it runs against that
database instead (a rehearsal clone, never production). The database must
be pre-migration (v9) when the script starts: scenario A has the new server
perform migration 010. On a rehearsal clone, run it before `migrate`.

    OLD_TREE=~/src/deaddrop-compat-old NEW_TREE=~/src/deaddrop-compat-audit \
        python scripts/compat_old_new.py

Scenarios:
  A  old server writes the DB (v9), new server starts (runs migration 010):
     old identities authenticate, ids unchanged, rooms/history readable.
  B  overlap: both servers up; an identity created on the OLD server after the
     migration reads on the old server and is REJECTED (403) on the new one,
     also after a restart. Accepted: it stays locked out until seeded by hand.
  C  rollback: new server stopped, old server against the v10 DB: old
     identities work; identities created by new code (random ids) do not.
  D  rollback after a rekey: the burned v1 secret on the old server.
  E  `deadrop rekey verify` lists exactly the identities old code created after
     the migration; `deadrop rekey seed` unlocks them on the new server.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

OLD_TREE = Path(os.path.expanduser(os.environ.get("OLD_TREE", "~/src/deaddrop-compat-old")))
NEW_TREE = Path(os.path.expanduser(os.environ.get("NEW_TREE", "~/src/deaddrop-compat-audit")))
ADMIN = "compat-admin-token"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)


class Server:
    def __init__(self, tree: Path, port: int, env: dict[str, str], log: Path):
        self.tree, self.port, self.env, self.log = tree, port, env, log
        self.proc: subprocess.Popen | None = None

    def start(self) -> "Server":
        fh = open(self.log, "ab")
        self.proc = subprocess.Popen(
            [
                "nice",
                "-n",
                "19",
                str(self.tree / ".venv/bin/uvicorn"),
                "deadrop.api:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
            ],
            cwd=self.tree / "src",
            env=self.env,
            stdout=fh,
            stderr=subprocess.STDOUT,
        )
        for _ in range(150):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=1)
                return self
            except Exception:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"server exited, see {self.log}")
                time.sleep(0.2)
        raise RuntimeError(f"server did not come up, see {self.log}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=15)

    def call(self, method: str, path: str, body=None, headers=None) -> tuple[int, object]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode(errors="replace")


def identity(s: Server, ns: str, nsec: str) -> dict:
    code, out = s.call(
        "POST",
        f"/{ns}/identities",
        {"metadata": {"display_name": "c"}},
        {"X-Namespace-Secret": nsec},
    )
    assert code == 200, (code, out)
    return out


def can_read(s: Server, ns: str, ident: dict) -> int:
    code, _ = s.call(
        "GET", f"/{ns}/inbox/{ident['id']}", headers={"X-Inbox-Secret": ident["secret"]}
    )
    return code


def room_roundtrip(
    s: Server, ns: str, a: dict, b: dict, room: str | None = None
) -> tuple[int, str]:
    h = {"X-Inbox-Secret": a["secret"]}
    if room is None:
        code, out = s.call("POST", f"/{ns}/rooms", {"display_name": "compat"}, h)
        if code != 200:
            return code, ""
        room = out["room_id"]
        code, out = s.call("POST", f"/{ns}/rooms/{room}/members", {"identity_id": b["id"]}, h)
        if code != 200:
            return code, room
    code, _ = s.call(
        "POST", f"/{ns}/rooms/{room}/messages", {"body": "hi"}, {"X-Inbox-Secret": b["secret"]}
    )
    if code != 200:
        return code, room
    code, _ = s.call("GET", f"/{ns}/rooms/{room}/messages", headers=h)
    return code, room


def cli(env: dict[str, str], *args: str) -> tuple[int, str]:
    """Run the NEW tree's `deadrop rekey ...` against the shared database."""
    p = subprocess.run(
        [str(NEW_TREE / ".venv/bin/deadrop"), "rekey", *args],
        env=env,
        cwd=NEW_TREE / "src",
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="dd-compat-"))
    env = {k: v for k, v in os.environ.items() if not k.startswith("DEADROP_")}
    env.update(DEADROP_ADMIN_TOKEN=ADMIN, DEADROP_AUTH_REFRESH_SECONDS="1", DEADROP_PUSH_ENABLED="")
    env.pop("HEARE_AUTH_URL", None)
    if not env.get("TURSO_URL"):
        env["DEADROP_DB"] = str(work / "compat.db")
    old_env = dict(env)
    new_env = dict(env)
    old = Server(OLD_TREE, 18601, old_env, work / "old.log")
    new = Server(NEW_TREE, 18602, new_env, work / "new.log")
    print(f"work dir {work}; db {'turso' if env.get('TURSO_URL') else env['DEADROP_DB']}")
    try:
        # --- A: old writes, new migrates ---
        old.start()
        code, nsr = old.call(
            "POST",
            "/admin/namespaces",
            {"metadata": {"display_name": "compat"}},
            {"X-Admin-Token": ADMIN},
        )
        assert code == 200, (code, nsr)
        ns, nsec = nsr["ns"], nsr["secret"]
        o1, o2 = identity(old, ns, nsec), identity(old, ns, nsec)
        code, room = room_roundtrip(old, ns, o1, o2)
        check("A0 old server baseline room roundtrip", code == 200, f"{code}")

        new.start()  # runs migration 010 while old is still serving
        check("A1 new: pre-migration identity reads inbox", can_read(new, ns, o1) == 200)
        code, _ = room_roundtrip(new, ns, o1, o2, room)
        check("A2 new: pre-migration room post+read", code == 200, f"{code}")
        code, ident = new.call(
            "GET", f"/{ns}/identities/{o1['id']}", headers={"X-Namespace-Secret": nsec}
        )
        check("A3 new: id unchanged for seeded identity", code == 200 and ident["id"] == o1["id"])
        check("A4 old still serves after migration", can_read(old, ns, o1) == 200)

        # --- B: overlap, identity created on OLD after migration ---
        o3 = identity(old, ns, nsec)
        check("B1 old: overlap identity reads on old", can_read(old, ns, o3) == 200)
        time.sleep(2.5)
        c = can_read(new, ns, o3)
        check("B2 new: overlap identity (created by old) rejected [accepted]", c == 403, f"{c}")
        code, _ = room_roundtrip(new, ns, o1, o3)
        check("B3 new: overlap identity cannot post [accepted]", code == 403, f"{code}")
        new.stop()
        new.start()
        c = can_read(new, ns, o3)
        check("B4 new after restart: overlap identity still rejected", c == 403, f"{c}")

        n1 = identity(new, ns, nsec)
        check("B5 new: new identity works on new", can_read(new, ns, n1) == 200)
        c = can_read(old, ns, n1)
        check(
            "B6 old: random-id identity (made by new) rejected [expected break]", c == 403, f"{c}"
        )

        # --- D: rekey o2 with revoke-now on new, then roll back to old ---
        code, rk = new.call(
            "POST",
            f"/{ns}/identities/{o2['id']}/rekey",
            {"revoke_now": True},
            {"X-Namespace-Secret": nsec},
        )
        if code == 200 and isinstance(rk, dict) and rk.get("secret"):
            o2v2 = {"id": o2["id"], "secret": rk["secret"]}
            check("D1 new: burned v1 gets 403", can_read(new, ns, o2) == 403)
            check("D2 new: v2 reads", can_read(new, ns, o2v2) == 200)
        else:
            o2v2 = None
            check("D0 rekey endpoint", False, f"{code} {str(rk)[:200]}")

        # --- C: rollback ---
        new.stop()
        check("C1 old after rollback: seeded identity reads", can_read(old, ns, o1) == 200)
        old.stop()
        old.start()
        check("C2 old restarted on v10 DB: seeded identity reads", can_read(old, ns, o1) == 200)
        o4 = identity(old, ns, nsec)
        check("C3 old on v10 DB: creates + uses identity", can_read(old, ns, o4) == 200)
        c = can_read(old, ns, n1)
        check("C4 old: new-code identity rejected [expected break]", c == 403, f"{c}")
        if o2v2:
            c1, c2 = can_read(old, ns, o2), can_read(old, ns, o2v2)
            check("D3 old after rollback: burned v1 secret REJECTED", c1 != 200, f"{c1}")
            check("D4 old after rollback: v2 secret [expected break]", c2 == 403, f"{c2}")

        # roll forward again: identity o4 made by old code while rolled back
        new.start()
        c = can_read(new, ns, o4)
        check("C5 re-deploy new: identity created during rollback rejected", c == 403, f"{c}")

        # --- E: the manual procedure ---
        code, out = cli(new_env, "verify")
        listed = {line.split()[1] for line in out.splitlines() if line.startswith(ns)}
        check("E1 verify lists exactly the old-code identities", listed == {o3["id"], o4["id"]})
        check("E2 verify exits 1 while any are listed", code == 1, f"{code}")
        for ident in (o3, o4):
            cli(new_env, "seed", ns, ident["id"])
        time.sleep(2.5)
        c3, c4 = can_read(new, ns, o3), can_read(new, ns, o4)
        check("E3 new: seeded identities authenticate", c3 == c4 == 200, f"{c3} {c4}")
        code, out = cli(new_env, "verify")
        check("E4 verify after seeding: 0", code == 0 and out.startswith("0 identities"), out)
    finally:
        old.stop()
        new.stop()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed; logs in {work}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
