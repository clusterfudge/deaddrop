#!/usr/bin/env python3
"""End-to-end credential-rotation harness for deaddrop secret versions.

Real clients (python client, harness1 tools + watcher, MCP, headless Chromium) ride a
`deadrop rekey` grace rotation and a --revoke-now rotation. See README.md.

    nice -n 19 .venv/bin/python scripts/e2e_rotation/fleet_e2e.py --local --h1-tools ~/src/fritz-tools
    STAGING_URL=http://127.0.0.1:<port> DEADROP_ADMIN_TOKEN=<made-up> ... fleet_e2e.py --h1-tools ...

Writes results.json and logs into a fresh work dir; leak-scans them; then deletes everything
except the redacted results.json and logs/harness.log. Never prints a secret. Exit 0 only if
every check passed, the leak scan found nothing and its positive control found something.
"""

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.umask(0o077)

import httpx  # noqa: E402

import fleet_clients as fc  # noqa: E402
from fleet_browser import BrowserFleet  # noqa: E402
from fleet_lib import (  # noqa: E402
    BASE,
    DELIVERED,
    HERE,
    HOME,
    INVITES,
    LOGS,
    OWN_WORK,
    VAULT,
    VBIN,
    XDG,
    CredStore,
    child_env,
    cleanup_work,
    guard_url,
    leak_scan,
    log,
    start_local_server,
    thermal_wait,
)

DELIVER = HERE / "deliver.sh"
# metadata tag on every namespace a rehearsal harness creates; verify steps skip these
TAG = {"rehearsal": "e2e_rotation"}

NAMES = ("pyclient", "h1", "mcp", "browser")
REAL = {
    "pyclient": "real: deadrop.client.Deaddrop (worktree), bundle re-read from store per start",
    "h1-tools": "real: tools/comms deaddrop_send_room.py + deaddrop_read_room.py (verbatim copies); store URL rewritten in-process",
    "h1-watcher": "real: tools/feeds/deaddrop_watcher.py main loop (verbatim copy); store URL rewritten in-process",
    "mcp": "real: mcp package streamable_http_client + ClientSession against /mcp/{ns}/{secret}",
    "browser": "real: headless Chromium on join.html + app.html (playwright)",
    "browser-stale": "real: headless Chromium, localStorage left on the old secret",
}
MANUAL = {
    "pyclient": "none (restart / next start re-reads the store)",
    "h1-tools": "none (every call re-reads the store)",
    "h1-watcher": "none with tools #120 (re-reads the store on 403); before #120, restart the feed",
    "mcp": "human claims recovery invite (PIN) + edits the MCP URL in the client config",
    "browser": "human opens invite link + types PIN",
    "browser-stale": "human asks for a fresh invite (`rekey invite`), opens it, types PIN",
}


class Run:
    def __init__(self, url, admin_token, local):
        self.url, self.admin, self.local = url, admin_token, local
        self.checks, self.rows, self.mids = [], [], []
        self.marker = 0

    # bookkeeping ---------------------------------------------------------
    def check(self, name, ok, detail=""):
        self.checks.append({"check": name, "ok": bool(ok), "detail": VAULT.redact(str(detail))})
        log(f"{'PASS' if ok else 'FAIL'}  {name}  {VAULT.redact(str(detail))}")
        return ok

    def body(self, who):
        self.marker += 1
        return f"ddfleet-{who}-{self.marker:03d}-{secrets.token_hex(3)}"

    def cli(self, *args, timeout=180):
        p = subprocess.run(
            ["nice", "-n", "19", str(VBIN / "deadrop"), *args],
            cwd=BASE,
            env=child_env(XDG_CONFIG_HOME=XDG, HOME=HOME, DDFLEET_DELIVERED=DELIVERED),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = VAULT.redact(p.stdout + p.stderr)
        (LOGS / "cli.log").open("a").write(
            f"$ deadrop {' '.join(args)}  rc={p.returncode}\n{out}\n"
        )
        log(
            f"deadrop {' '.join(a for a in args if not a.startswith(str(BASE)))} -> rc={p.returncode}"
        )
        for line in out.strip().splitlines()[-12:]:
            log(f"    | {line}")
        return p.returncode, out

    def ns_secret_for(self, who, label=None):
        """The CLI's namespace config is where `rekey` stores the current secret."""
        import yaml

        data = yaml.safe_load((XDG / "deadrop" / "namespaces" / f"{self.ns}.yaml").read_text())
        return VAULT.add(label or f"{who}-secret", data["mailboxes"][self.ids[who]]["secret"])

    # setup ---------------------------------------------------------------
    def setup(self):
        h = {"X-Admin-Token": self.admin, "Authorization": f"Bearer {self.admin}"}
        slug = f"ddfleet-{secrets.token_hex(4)}"
        r = httpx.post(
            f"{self.url}/admin/namespaces",
            headers=h,
            timeout=15,
            json={
                "slug": slug,
                "ttl_hours": 24,
                "metadata": {"display_name": "dd-fleet rotation test", **TAG},
            },
        )
        r.raise_for_status()
        d = r.json()
        self.ns, self.slug = d["ns"], d.get("slug") or d["ns"]
        VAULT.add("ns-secret", d["secret"])
        self.ns_secret = d["secret"]
        self.ids, self.pins, self.sec = {}, {}, {}
        for n in NAMES:
            pin = VAULT.add(f"{n}-pin", "".join(secrets.choice("0123456789") for _ in range(8)))
            r = httpx.post(
                f"{self.url}/admin/{self.ns}/identities",
                headers=h,
                timeout=15,
                json={"metadata": {"display_name": f"ddfleet-{n}"}, "pin": pin},
            )
            r.raise_for_status()
            self.ids[n], self.pins[n] = r.json()["id"], pin
            self.sec[n] = {1: VAULT.add(f"{n}-v1", r.json()["secret"])}
        r = httpx.post(
            f"{self.url}/{self.ns}/rooms",
            json={"display_name": "ddfleet-room"},
            headers={"X-Inbox-Secret": self.sec["pyclient"][1]},
            timeout=15,
        )
        r.raise_for_status()
        self.room = r.json()["room_id"]
        for n in NAMES[1:]:
            httpx.post(
                f"{self.url}/{self.ns}/rooms/{self.room}/members",
                json={"identity_id": self.ids[n]},
                headers={"X-Inbox-Secret": self.sec["pyclient"][1]},
                timeout=15,
            ).raise_for_status()
        # CLI config (XDG_CONFIG_HOME) -- the trusted host that runs `rekey`
        import yaml

        (XDG / "deadrop" / "namespaces").mkdir(parents=True, exist_ok=True)
        (XDG / "deadrop" / "config.yaml").write_text(yaml.safe_dump({"url": self.url}))
        nsfile = XDG / "deadrop" / "namespaces" / f"{self.ns}.yaml"
        nsfile.write_text(
            yaml.safe_dump(
                {
                    "ns": self.ns,
                    "secret": self.ns_secret,
                    "display_name": "dd-fleet",
                    "mailboxes": {
                        self.ids[n]: {"secret": self.sec[n][1], "display_name": f"ddfleet-{n}"}
                        for n in NAMES
                    },
                }
            )
        )
        os.chmod(nsfile, 0o600)
        # throwaway credential store + map
        self.store = CredStore(BASE / "credstore.json")
        self.store.put(
            fc.PYCLIENT_CRED,
            {
                "url": self.url,
                "namespace": self.ns,
                "room_id": self.room,
                "secret": self.sec["pyclient"][1],
            },
        )
        self.store.put(
            fc.H1_CRED,
            {
                "url": self.url,
                "namespace": self.ns,
                "twin_id": self.ids["h1"],
                "secret": self.sec["h1"][1],
                "room_id": self.room,
                "default_room": self.room,
                "slug": "ddfleet-h1",
            },
        )
        self.cmap = BASE / "credential_map.json"
        self.cmap.write_text(
            json.dumps(
                {
                    self.ids["pyclient"]: {"credential": fc.PYCLIENT_CRED, "field": "secret"},
                    self.ids["h1"]: {"credential": fc.H1_CRED, "field": "secret"},
                }
            )
        )
        log(f"namespace {self.ns} slug={self.slug} room={self.room} store={self.store.url}")
        log("identities " + " ".join(f"{n}={i}" for n, i in self.ids.items()))

    # client probes ------------------------------------------------------
    def probe(self, client, phase, t0=None):
        """One post+read by a client with whatever credential it currently holds."""
        b = self.body(client)
        if client == "pyclient":
            r = fc.pyclient(self.store.url, b)
        elif client == "h1-tools":
            r = fc.h1_send(self.store.url, b)
            if r["ok"]:
                rr = fc.h1_read(self.store.url, b)
                r["ok"] = rr["ok"]
        elif client == "mcp":
            r = fc.mcp_client(fc.mcp_url(self.url, self.ns, self.mcp_secret), self.room, b)
        else:
            r = self.br.post(client, b, expect_seen=self.mids[-1] if self.mids else None)
            r["ok"] = r["ok"] and r.get("read_ok", True)
        if r.get("ok"):
            self.mids.append(b)
            if t0 is not None:
                r["ttr_s"] = round(time.monotonic() - t0, 2)
        log(f"[{phase}] {client}: {json.dumps({k: v for k, v in r.items() if k not in ('mids',)})}")
        return r

    def old_dead(self, who, version, phase):
        r = fc.raw_post(self.url, self.ns, self.room, self.sec[who][version], "ddfleet-should-fail")
        return self.check(
            f"{phase}: {who} v{version} rejected 403 credential_retired",
            r["status"] == 403 and r["retired"],
            r,
        )

    def history_ok(self, phase):
        """Every body posted successfully so far is still in the room for a reader on a current secret."""
        r = httpx.get(
            f"{self.url}/{self.ns}/rooms/{self.room}/messages?limit=1000",
            headers={"X-Inbox-Secret": self.store.get(fc.PYCLIENT_CRED)["secret"]},
            timeout=15,
        )
        bodies = {m["body"] for m in r.json().get("messages", [])}
        missing = [b for b in self.mids if b not in bodies]
        return self.check(
            f"{phase}: history intact ({len(self.mids)} posted bodies present)",
            not missing,
            f"missing={len(missing)}",
        )

    def watcher_cycle(self, phase, t0):
        """Watcher on the old secret after the burn: it must log a 403 and then either go dark
        (older tools: recovers only on restart) or re-read the store and keep delivering
        (fritz-heare/tools #120). Either way it must also come back after a restart."""
        b = self.body("watch-probe")
        fc.raw_post(self.url, self.ns, self.room, self.store.get(fc.PYCLIENT_CRED)["secret"], b)
        self.mids.append(b)
        saw = self.watcher.saw(b, 20)
        t_saw = round(time.monotonic() - t0, 2)
        got_403 = self.watcher.stderr_has("API 403")
        healed = got_403 and saw and self.watcher.stderr_has("got a new credential")
        dark = got_403 and not saw
        mode = "403, re-read store" if healed else "403, dark until restart" if dark else "?"
        self.check(
            f"{phase}: watcher on burned secret gets 403, then goes dark or re-reads the store",
            dark or healed,
            f"403_logged={got_403} delivered={saw} mode={mode}",
        )
        self.watcher.stop()
        ok = self.watcher.start()
        b2 = self.body("watch-probe")
        fc.raw_post(self.url, self.ns, self.room, self.store.get(fc.PYCLIENT_CRED)["secret"], b2)
        self.mids.append(b2)
        rec = ok and self.watcher.saw(b2, 45)
        ttr = round(time.monotonic() - t0, 2) if rec else None
        self.check(f"{phase}: watcher recovers after restart (re-reads store)", rec, f"ttr={ttr}")
        return {"ok": rec, "ttr_s": t_saw if healed else ttr, "mode": mode}

    # push --------------------------------------------------------------
    def push_register(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from deadrop.push import b64u_encode

        pub = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        )
        self.push_endpoint = f"https://push.ddfleet.invalid/sub/{secrets.token_hex(8)}"
        r = httpx.post(
            f"{self.url}/{self.ns}/push/subscriptions",
            timeout=15,
            headers={"X-Inbox-Secret": self.sec["browser"][1]},
            json={
                "endpoint": self.push_endpoint,
                "keys": {"p256dh": b64u_encode(pub), "auth": b64u_encode(os.urandom(16))},
            },
        )
        return self.check(
            "setup: push subscription registered for browser identity",
            r.status_code == 200,
            r.status_code,
        )

    def push_after(self, phase, old_version):
        cur = self.ns_secret_for("browser")
        r = httpx.get(
            f"{self.url}/{self.ns}/push/subscriptions", headers={"X-Inbox-Secret": cur}, timeout=15
        )
        subs = r.json() if r.status_code == 200 else []
        subs = subs.get("subscriptions", subs) if isinstance(subs, dict) else subs
        kept = any(s.get("endpoint") == self.push_endpoint for s in subs)
        self.check(
            f"{phase}: push subscription survives rotation (listed with new secret)",
            kept,
            r.status_code,
        )
        old = httpx.get(
            f"{self.url}/{self.ns}/push/subscriptions",
            timeout=15,
            headers={"X-Inbox-Secret": self.sec["browser"][old_version]},
        )
        self.check(
            f"{phase}: old secret cannot list push subscriptions",
            old.status_code == 403,
            old.status_code,
        )
        t = httpx.post(
            f"{self.url}/{self.ns}/push/test", headers={"X-Inbox-Secret": cur}, timeout=30
        )
        tj = t.json() if t.status_code == 200 else {}
        self.check(
            f"{phase}: /push/test with new secret targets the kept subscription",
            t.status_code == 200 and tj.get("total") == 1,
            f"status={t.status_code} total={tj.get('total')} sent={tj.get('sent')} (endpoint is .invalid)",
        )
        return kept

    # phases --------------------------------------------------------------
    def rekey_flags(self):
        return [
            "--credential-map",
            str(self.cmap),
            "--credential-store",
            self.store.url,
            "--invite-dir",
            str(INVITES),
            "--deliver-cmd",
            str(DELIVER),
        ]

    def refresh_versions(self, v):
        for n in NAMES:
            self.sec[n][v] = self.ns_secret_for(n, f"{n}-v{v}")

    def phase_healthy(self):
        self.mcp_secret = self.sec["mcp"][1]
        self.watcher = fc.Watcher(self.store.url)
        self.check("healthy: watcher started", self.watcher.start())
        self.br = BrowserFleet(self.url, self.ns, self.slug, self.room)
        self.br.context("browser-stale", self.ids["browser"], self.sec["browser"][1])
        res = {}
        for c in ("pyclient", "h1-tools", "mcp", "browser-stale"):
            res[c] = self.probe(c, "healthy")["ok"]
            self.check(f"healthy: {c} post+read", res[c])
        res["h1-watcher"] = self.watcher.saw(self.mids[-1], 40)
        self.check("healthy: watcher emitted a message posted by another client", res["h1-watcher"])
        res["browser"] = res["browser-stale"]
        return res

    def phase_grace(self):
        P = "grace"
        rc, out = self.cli("rekey", "all", self.ns, "--dry-run", "--credential-map", str(self.cmap))
        self.check("dry-run: plans 4 identities, changes nothing", rc == 0 and "4/4 planned" in out)
        self.check(
            "dry-run: store route for pyclient+h1, invite route for mcp+browser",
            out.count("fix-forward=credential-store") == 2
            and out.count("fix-forward=recovery-invite") == 2,
        )
        self.check(
            "dry-run: v1 still works after dry-run",
            fc.raw_post(self.url, self.ns, self.room, self.sec["pyclient"][1], self.body("dry"))[
                "status"
            ]
            == 200,
        )
        t0 = time.monotonic()
        rc1, _ = self.cli("rekey", "identity", self.ns, self.ids["pyclient"], *self.rekey_flags())
        rc2, out = self.cli(
            "rekey", "all", self.ns, "--exclude", self.ids["pyclient"], *self.rekey_flags()
        )
        self.check(
            "rotation: rekey identity + rekey all succeeded",
            rc1 == 0 and rc2 == 0 and "3/3 rekeyed" in out,
        )
        self.refresh_versions(2)
        self.check(
            "rotation: store PATCHed for both store-driven identities",
            self.store.get(fc.PYCLIENT_CRED)["secret"] == self.sec["pyclient"][2]
            and self.store.get(fc.H1_CRED)["secret"] == self.sec["h1"][2],
        )
        self.check(
            "rotation: invites delivered for mcp+browser via --deliver-cmd (0600)",
            all(
                (DELIVERED / f"{self.ids[n]}.url").exists()
                and (DELIVERED / f"{self.ids[n]}.url").stat().st_mode & 0o077 == 0
                for n in ("mcp", "browser")
            ),
        )
        rows = {c: {"overlap": None} for c in REAL}
        # overlap: every old secret still works until its successor is used
        for n in NAMES:
            r = fc.raw_post(self.url, self.ns, self.room, self.sec[n][1], self.body(f"overlap-{n}"))
            self.check(f"overlap: {n} v1 still accepted", r["status"] == 200, r)
        rows["mcp"]["overlap"] = self.probe("mcp", "overlap")["ok"]
        rows["browser-stale"]["overlap"] = self.probe("browser-stale", "overlap")["ok"]
        rows["h1-watcher"]["overlap"] = self.watcher.saw(self.mids[-1], 40)
        self.check("overlap: watcher (v1) still receiving", rows["h1-watcher"]["overlap"])
        # store-driven clients re-read the store
        for c, n in (("pyclient", "pyclient"), ("h1-tools", "h1")):
            r = self.probe(c, P, t0)
            rows[c].update(
                overlap=True, recovered=r["ok"], ttr_s=r.get("ttr_s"), after="ok on first restart"
            )
            self.check(f"{P}: {c} recovered from store", r["ok"])
            self.old_dead(n, 1, P)
        w = self.watcher_cycle(P, t0)
        rows["h1-watcher"].update(
            recovered=w["ok"],
            ttr_s=w["ttr_s"],
            after=w["mode"],
        )
        # browser: claim the recovery invite on join.html
        self.br.context("browser")
        claimed = self.br.claim(
            "browser", fc.read_delivered(self.ids["browser"]), self.pins["browser"]
        )
        r = self.probe("browser", P, t0) if claimed else {"ok": False}
        rows["browser"].update(
            overlap=None, recovered=r["ok"], ttr_s=r.get("ttr_s"), after="invite+PIN"
        )
        self.check(f"{P}: browser claimed recovery invite + posted", r["ok"])
        self.old_dead("browser", 1, P)
        s = self.probe("browser-stale", P)
        self.check(
            f"{P}: stale browser gets 403 credential_retired + 'ask for a recovery invite' alert",
            s.get("status") == 403 and s.get("retired") and s.get("alert_retired"),
            s,
        )
        rc, _ = self.cli(
            "rekey",
            "invite",
            self.ns,
            self.ids["browser"],
            "--invite-dir",
            str(INVITES),
            "--deliver-cmd",
            str(DELIVER),
        )
        ok = rc == 0 and self.br.claim(
            "browser-stale", fc.read_delivered(self.ids["browser"]), self.pins["browser"]
        )
        r = self.probe("browser-stale", P, t0) if ok else {"ok": False}
        rows["browser-stale"].update(
            recovered=r["ok"],
            ttr_s=r.get("ttr_s"),
            after="403 credential_retired + alert" if s.get("alert_retired") else str(s),
        )
        self.check(f"{P}: stale browser re-onboarded with fresh invite", r["ok"])
        # mcp: old URL holder; re-onboard through the invite
        inv = fc.read_delivered(self.ids["mcp"])
        cc = fc.cli_claim(inv)
        self.check(
            f"{P}: `deadrop claim` cannot claim a recovery invite (no PIN input) - finding",
            cc["rc"] != 0,
            cc,
        )
        new = fc.api_claim(inv, self.pins["mcp"])
        self.check(
            f"{P}: mcp invite claimed with PIN, secret == rekeyed v2", new == self.sec["mcp"][2]
        )
        old_url = fc.mcp_url(self.url, self.ns, self.sec["mcp"][1])
        self.mcp_secret = new or self.sec["mcp"][1]
        r = self.probe("mcp", P, t0)
        st = fc.raw_mcp_status(old_url)
        rows["mcp"].update(
            recovered=r["ok"], ttr_s=r.get("ttr_s"), after=f"old URL -> {st} (opaque)"
        )
        self.check(f"{P}: mcp new URL works", r["ok"])
        self.check(
            f"{P}: mcp old URL rejected (opaque 401, not 403 credential_retired)", st == 401, st
        )
        self.old_dead("mcp", 1, P)
        return rows, t0

    def phase_revoke(self):
        P = "revoke-now"
        self.br.pages["browser-stale"].context.close()
        t0 = time.monotonic()
        rc, out = self.cli("rekey", "all", self.ns, "--revoke-now", *self.rekey_flags())
        self.check(f"{P}: rekey all --revoke-now", rc == 0 and "4/4 rekeyed" in out)
        self.refresh_versions(3)
        for n in NAMES:
            self.old_dead(n, 2, P + " (immediate)")
        st = fc.raw_mcp_status(fc.mcp_url(self.url, self.ns, self.sec["mcp"][2]))
        self.check(f"{P}: mcp v2 URL dark immediately", st == 401, st)
        rows = {c: {"overlap": False} for c in REAL if c != "browser-stale"}
        for c in ("pyclient", "h1-tools"):
            r = self.probe(c, P, t0)
            rows[c].update(recovered=r["ok"], ttr_s=r.get("ttr_s"), after="ok on first restart")
        w = self.watcher_cycle(P, t0)
        rows["h1-watcher"].update(recovered=w["ok"], ttr_s=w["ttr_s"], after=w["mode"])
        s = self.probe("browser", P)
        self.check(
            f"{P}: browser on v2 shows credential_retired",
            s.get("retired") and s.get("alert_retired"),
            s,
        )
        ok = self.br.claim("browser", fc.read_delivered(self.ids["browser"]), self.pins["browser"])
        r = self.probe("browser", P, t0) if ok else {"ok": False}
        rows["browser"].update(
            recovered=r["ok"], ttr_s=r.get("ttr_s"), after="403 credential_retired + alert"
        )
        new = fc.api_claim(fc.read_delivered(self.ids["mcp"]), self.pins["mcp"])
        self.mcp_secret = new or self.mcp_secret
        r = self.probe("mcp", P, t0)
        rows["mcp"].update(recovered=r["ok"], ttr_s=r.get("ttr_s"), after="401 immediately")
        return rows, t0

    def final(self, phase, clients):
        for c in clients:
            self.check(f"{phase} final: {c} posts+reads", self.probe(c, f"{phase}-final")["ok"])
        self.history_ok(phase)


def table(rows_by_phase, healthy):
    hdr = f"{'client':<14}{'phase':<11}{'before':<8}{'overlap':<9}{'after-rotation':<34}{'recovered':<10}{'ttr_s':<8}manual steps"
    lines = [hdr, "-" * len(hdr)]
    for phase, rows in rows_by_phase.items():
        for c, r in rows.items():
            ov = {True: "ok", False: "dark", None: "-"}[r.get("overlap")]
            lines.append(
                f"{c:<14}{phase:<11}{'ok' if healthy.get(c) else 'FAIL':<8}{ov:<9}"
                f"{str(r.get('after', '-'))[:33]:<34}{'yes' if r.get('recovered') else 'NO':<10}"
                f"{str(r.get('ttr_s', '-')):<8}{MANUAL[c]}"
            )
    return "\n".join(lines)


def stop_server(server):
    server.terminate()
    try:
        server.wait(15)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(10)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--local", action="store_true", help="start a throwaway sqlite server from this repo"
    )
    ap.add_argument("--port", type=int, default=0, help="--local server port (default: a free one)")
    ap.add_argument(
        "--h1-tools",
        type=Path,
        default=os.environ.get("DDFLEET_H1TOOLS"),
        help="fritz-heare/tools checkout (comms/, shared/, feeds/); $DDFLEET_H1TOOLS",
    )
    ap.add_argument("--keep-namespace", action="store_true")
    ap.add_argument(
        "--keep-work", action="store_true", help="do not delete the work dir after the scan"
    )
    a = ap.parse_args()
    if not a.h1_tools:
        raise SystemExit(
            "--h1-tools (or DDFLEET_H1TOOLS) is required: a fritz-heare/tools checkout"
        )
    for d in (LOGS, XDG, HOME, DELIVERED, INVITES):
        d.mkdir(parents=True, exist_ok=True)
    if any(DELIVERED.iterdir()) or any(INVITES.iterdir()):
        raise SystemExit(f"{BASE} is not a fresh work dir (delivered/ or invites/ not empty)")
    admin = os.environ.get("DEADROP_ADMIN_TOKEN") or (secrets.token_hex(16) if a.local else None)
    if not admin:
        raise SystemExit("DEADROP_ADMIN_TOKEN is required (made-up admin token of the test server)")
    VAULT.add("admin-token", admin)
    h1_rev = fc.stage_h1tools(a.h1_tools.expanduser())
    log(f"work dir {BASE}; harness1 tools @ {h1_rev}")
    server, vapid = None, None
    if a.local:
        from deadrop.push import generate_vapid_keys

        vapid = generate_vapid_keys()
        VAULT.add("vapid-private", vapid[1])
        thermal_wait()
        server, url = start_local_server(a.port, admin, vapid)
    else:
        url = os.environ.get("STAGING_URL", "").rstrip("/")
        if not url:
            raise SystemExit("STAGING_URL is required (or --local)")
    try:
        guard_url(url)
    except SystemExit:
        if server:
            stop_server(server)
        raise
    log(f"target {url} ({'local' if a.local else 'external'})")
    run = Run(url, admin, a.local)
    result = {
        "target": "local" if a.local else "external",
        "h1_tools_rev": h1_rev,
        "checks": run.checks,
    }
    try:
        run.setup()
        pk = httpx.get(f"{url}/push/vapid-public-key", timeout=10)
        push = pk.status_code == 200 and bool(pk.json().get("enabled")) and run.push_register()
        healthy = run.phase_healthy()
        if push:
            result["browser_push_subscribe"] = run.br.try_push_subscribe(pk.json()["public_key"])
            log(f"headless push subscribe: {result['browser_push_subscribe']}")
        thermal_wait()
        g_rows, _ = run.phase_grace()
        run.final("grace", ("pyclient", "h1-tools", "mcp", "browser", "browser-stale"))
        if push:
            run.push_after("grace", 1)
        run.cli("rekey", "status", run.ns)
        thermal_wait()
        r_rows, _ = run.phase_revoke()
        run.final("revoke-now", ("pyclient", "h1-tools", "mcp", "browser"))
        if push:
            run.push_after("revoke-now", 2)
        rc, out = run.cli("rekey", "status", run.ns)
        run.check("status: burned versions with stale use flagged", "STALE-USE" in out)
        result.update(
            healthy=healthy,
            rows={"grace": g_rows, "revoke-now": r_rows},
            push="server-side tested" if push else "not tested (no VAPID on target)",
            real_code=REAL,
            manual_steps=MANUAL,
        )
        result["table"] = table(result["rows"], healthy)
        log("\n" + result["table"])
    except Exception as e:  # noqa: BLE001
        import traceback

        log("ABORT " + "".join(traceback.format_exception(e))[-3000:])
        result["aborted"] = VAULT.redact(f"{type(e).__name__}: {e}")
    finally:
        for stop in (lambda: run.watcher.stop(), lambda: run.br.close(), lambda: run.store.stop()):
            try:
                stop()
            except Exception:  # noqa: BLE001
                pass
        if hasattr(run, "ns") and not a.keep_namespace:
            try:
                httpx.delete(
                    f"{url}/admin/namespaces/{run.ns}",
                    headers={"X-Admin-Token": admin, "Authorization": f"Bearer {admin}"},
                    timeout=15,
                )
            except httpx.HTTPError:
                pass
        if server:
            try:
                stop_server(server)  # server.log is complete only once the server has exited
            except Exception as e:  # noqa: BLE001
                log(f"local server stop: {type(e).__name__}")
        n_fail = sum(not c["ok"] for c in run.checks)
        result["summary"] = f"{len(run.checks) - n_fail}/{len(run.checks)} checks passed"
        log(result["summary"])
        out = BASE / "results.json"
        out.write_text(VAULT.redact(json.dumps(result, indent=1, default=str)))
        # Scan before anything is deleted: LOGS holds the server's own log (server.log for
        # --local, staging-*.log when turso_stage.py runs the servers).
        scan = leak_scan([LOGS, out])
        servers = sorted(
            p.name for p in LOGS.glob("*.log") if p.name.startswith(("server", "staging-"))
        )
        scan["server_logs_scanned"] = servers
        log(
            f"leak scan: {scan['total']} hits over {scan['files_scanned']} files (server logs: "
            f"{', '.join(servers) or 'NONE'}) for {scan['values']} minted values {scan['hits'] or ''}"
        )
        control = leak_scan(
            [BASE / "credstore.json", XDG]
        )  # files meant to hold secrets: must be > 0
        scan["positive_control_hits"] = control["total"]
        log(f"leak scan positive control (credstore.json + CLI ns config): {control['total']} hits")
        result["leak_scan"] = scan
        out.write_text(VAULT.redact(json.dumps(result, indent=1, default=str)))
        ok = (
            bool(run.checks)
            and n_fail == 0
            and "aborted" not in result
            and scan["total"] == 0
            and control["total"] > 0
            and bool(servers or not a.local)
        )
        if OWN_WORK and not a.keep_work:
            cleanup_work()
            log(f"work dir cleaned; kept {out} and {LOGS / 'harness.log'}")
        print(f"RESULTS: {out}  {'OK' if ok else 'FAILED'}", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
