#!/usr/bin/env python3
"""Run the rotation harness against two staging servers on a Turso rehearsal clone.

Mints the clone env in-process (rehearse_on_turso_clone._clone_env: clone-only token, the
name guard, the hostname check), starts two staging deaddrop processes on 127.0.0.1 against
the clone, runs fleet_e2e.py against process A, then measures cross-process burn
propagation A<->B. No secret is printed, logged, written or put on argv.

    REHEARSAL_DB=deaddrop-rehearsal-<date> nice -n 19 .venv/bin/python \
        scripts/e2e_rotation/turso_stage.py --h1-tools ~/src/fritz-tools [harness|propagation|both]

On the way out -- normal exit, exception, Ctrl-C, SIGTERM, or a server that will not stop --
the servers are stopped, the clone is DESTROYED (rehearse_on_turso_clone.py teardown, same
guard; pass --keep-clone to skip), the staging logs are leak-scanned, and the work dir is
deleted except the redacted results.
"""

import argparse
import atexit
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(HERE))
if not os.environ.get("REHEARSAL_DB", "").startswith("deaddrop-rehearsal-"):
    sys.exit("set REHEARSAL_DB=deaddrop-rehearsal-<suffix> (an existing rehearsal clone)")
os.umask(0o077)
os.environ["DDFLEET_WORK"] = tempfile.mkdtemp(prefix="dd-rotation-stage-")
import fleet_lib as L  # noqa: E402
import rehearse_on_turso_clone as R  # noqa: E402

LOGS = L.LOGS
SENSITIVE: list[str] = []
TAG = {"rehearsal": "e2e_rotation"}
_torn_down = False


def redact(s: str) -> str:
    for v in SENSITIVE:
        s = s.replace(v, "<redacted>")
    return s


def say(msg):
    print(f"{time.strftime('%H:%M:%S')} {redact(str(msg))}", flush=True)


def start(port, env):
    log = open(LOGS / f"staging-{port}.log", "ab")
    p = subprocess.Popen(
        [
            "nice",
            "-n",
            "19",
            str(L.VBIN / "uvicorn"),
            "deadrop.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=REPO / "src",
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    t0 = time.monotonic()
    while time.monotonic() - t0 < 90:
        if p.poll() is not None:
            raise SystemExit(f"staging {port} exited rc={p.returncode}; see staging-{port}.log")
        try:
            if httpx.get(f"{url}/health", timeout=2).status_code == 200:
                say(f"staging {url} healthy in {time.monotonic() - t0:.1f}s (pid {p.pid})")
                return p, url
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    p.kill()
    raise SystemExit(f"staging {port} not healthy")


def poll(fn, want, limit=30.0, step=0.1):
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        got = fn()
        if got == want:
            return round(time.monotonic() - t0, 2)
        time.sleep(step)
    return None


def propagation(A, B, admin):
    """Burn propagation between two server processes sharing the clone."""
    out = {}
    h = {"X-Admin-Token": admin, "Authorization": f"Bearer {admin}"}
    r = httpx.post(
        f"{A}/admin/namespaces",
        headers=h,
        timeout=20,
        json={
            "slug": f"ddprop-{secrets.token_hex(3)}",
            "ttl_hours": 2,
            "metadata": {"display_name": "dd-fleet propagation", **TAG},
        },
    )
    r.raise_for_status()
    ns, nsec = r.json()["ns"], r.json()["secret"]
    SENSITIVE.append(nsec)

    def ident():
        r = httpx.post(
            f"{A}/{ns}/identities",
            headers={"X-Namespace-Secret": nsec},
            timeout=20,
            json={"metadata": {"display_name": "ddprop"}},
        )
        r.raise_for_status()
        SENSITIVE.append(r.json()["secret"])
        return r.json()["id"], r.json()["secret"]

    def read(url, i, s):
        try:
            return httpx.get(
                f"{url}/{ns}/inbox/{i}", headers={"X-Inbox-Secret": s}, timeout=10
            ).status_code
        except httpx.HTTPError as e:
            return type(e).__name__

    def rekey(url, i, **kw):
        r = httpx.post(
            f"{url}/{ns}/identities/{i}/rekey",
            headers={"X-Namespace-Secret": nsec},
            json={"grace_seconds": 0, **kw},
            timeout=30,
        )
        r.raise_for_status()
        SENSITIVE.append(r.json()["secret"])
        return r.json()["secret"]

    try:
        # 1) identity created on A: how long until B accepts it
        i, v1 = ident()
        out["new_identity_visible_on_B_s"] = poll(lambda: read(B, i, v1), 200)
        out["v1_ok_on_A"] = read(A, i, v1)
        # 2) rekey on A; new secret first used on B (burns v1 there); how long until A rejects v1
        v2 = rekey(A, i)
        out["v1_still_ok_on_A_after_rekey_(overlap)"] = read(A, i, v1)
        t = time.monotonic()
        out["v2_accepted_on_B_s"] = poll(lambda: read(B, i, v2), 200)
        out["v1_rejected_on_B_after_burn_s"] = poll(lambda: read(B, i, v1), 403)
        out["burn_on_B_seen_by_A_s"] = poll(lambda: read(A, i, v1), 403)
        out["burn_total_from_first_use_s"] = round(time.monotonic() - t, 2)
        out["v2_ok_on_A"] = read(A, i, v2)
        # 3) revoke-now on A: how long until B rejects v2, accepts v3
        v3 = rekey(A, i, revoke_now=True)
        out["revoke_now_v2_rejected_on_A"] = read(A, i, v2)
        out["revoke_now_seen_by_B_s"] = poll(lambda: read(B, i, v2), 403)
        out["v3_accepted_on_B_s"] = poll(lambda: read(B, i, v3), 200)
        # 4) a burned secret probed during the stale window, repeated (stale-use path), 3 samples
        samples = []
        for _ in range(3):
            j, w1 = ident()
            poll(lambda: read(B, j, w1), 200)
            w2 = rekey(B, j)
            t = time.monotonic()
            poll(lambda: read(B, j, w2), 200)
            samples.append(poll(lambda: read(A, j, w1), 403))
        out["burn_B_to_A_samples_s"] = samples
    finally:
        httpx.delete(f"{A}/admin/namespaces/{ns}", headers=h, timeout=20)
    return out


def teardown_clone(keep: bool):
    """Destroy the rehearsal clone, once, whatever happened before. Guarded by name."""
    global _torn_down
    if _torn_down:
        return
    _torn_down = True
    if keep:
        say(
            f"--keep-clone: {R.CLONE} left in place; destroy it with rehearse_on_turso_clone.py teardown"
        )
        return
    try:
        R._guard(R.CLONE)
        R.cmd_teardown()
    except BaseException as e:  # noqa: BLE001 -- SystemExit from the guard or the API
        say(
            f"CLONE TEARDOWN FAILED ({type(e).__name__}: {e}); run rehearse_on_turso_clone.py teardown"
        )


def stop_all(procs):
    for p in procs:
        try:
            p.terminate()
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(10)
        except BaseException as e:  # noqa: BLE001 -- a stuck server must not skip the teardown
            say(f"staging pid {p.pid} did not stop: {type(e).__name__}")
    say("staging servers stopped: " + ", ".join(f"pid {p.pid} rc={p.returncode}" for p in procs))


def scan_staging_logs():
    hits = {}
    for f in LOGS.glob("staging-*.log"):
        txt = f.read_text(errors="replace")
        hits[f.name] = sum(txt.count(v) for v in SENSITIVE)
    canary = secrets.token_hex(16)  # positive control: a made-up value the scan must find
    SENSITIVE.append(canary)
    control = L.BASE / "control.txt"
    control.write_text(f"x {canary} x\n")
    control_hits = sum(control.read_text().count(v) for v in SENSITIVE)
    control.unlink()
    return hits, control_hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="both", choices=("harness", "propagation", "both"))
    ap.add_argument("--h1-tools", default=os.environ.get("DDFLEET_H1TOOLS"))
    ap.add_argument("--keep-clone", action="store_true", help="do not destroy the clone afterwards")
    ap.add_argument("--keep-work", action="store_true")
    a = ap.parse_args()
    if a.mode != "propagation" and not a.h1_tools:
        sys.exit("--h1-tools (or DDFLEET_H1TOOLS) is required for the harness")
    atexit.register(teardown_clone, a.keep_clone)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    LOGS.mkdir(parents=True, exist_ok=True)
    procs, result = [], {}
    rc = 0
    try:
        env = R._clone_env()  # TURSO_URL/TURSO_AUTH_TOKEN for the clone only
        if R.CLONE not in env["TURSO_URL"] or R.SOURCE in env["TURSO_URL"]:
            sys.exit("clone URL check failed")
        SENSITIVE.append(env["TURSO_AUTH_TOKEN"])
        admin = secrets.token_hex(24)  # made up, staging only
        SENSITIVE.append(admin)
        from deadrop.push import generate_vapid_keys

        vpub, vpriv = generate_vapid_keys()
        SENSITIVE.append(vpriv)
        env = {k: v for k, v in env.items() if k not in L.STRIP_EXACT}
        env.update(
            DEADROP_ADMIN_TOKEN=admin,
            DEADROP_PUSH_ENABLED="1",
            DEADROP_VAPID_PUBLIC_KEY=vpub,
            DEADROP_VAPID_PRIVATE_KEY=vpriv,
            DEADROP_VAPID_SUBJECT="mailto:ddfleet@example.invalid",
            NO_PROXY="127.0.0.1,localhost",
        )
        say(f"clone host ok: {env['TURSO_URL'].split('//')[1].split('.')[0][:40]}...")
        pa, A = start(L.free_port(), env)
        procs.append(pa)
        pb, B = start(L.free_port(), env)
        procs.append(pb)
        if a.mode in ("harness", "both"):
            henv = {k: v for k, v in os.environ.items() if not k.startswith(("TURSO_", "DEADROP_"))}
            henv.update(STAGING_URL=A, DEADROP_ADMIN_TOKEN=admin, DDFLEET_MAX_TEMP="80")
            t0 = time.monotonic()
            rc = subprocess.call(
                [
                    "nice",
                    "-n",
                    "19",
                    sys.executable,
                    str(HERE / "fleet_e2e.py"),
                    "--h1-tools",
                    str(a.h1_tools),
                ],
                env=henv,
                cwd=L.BASE,
            )
            result["harness_rc"], result["harness_wall_s"] = rc, round(time.monotonic() - t0, 1)
            say(f"harness rc={rc} wall={result['harness_wall_s']}s")
        if a.mode in ("propagation", "both"):
            result["propagation"] = propagation(A, B, admin)
            say("propagation " + json.dumps(result["propagation"]))
    except BaseException as e:  # noqa: BLE001
        result["error"] = redact(f"{type(e).__name__}: {e}")
        say("ERROR " + result["error"])
        rc = rc or 2
    finally:
        stop_all(procs)
        teardown_clone(a.keep_clone)
        if SENSITIVE:
            hits, control = scan_staging_logs()
            result["staging_log_leak_hits"], result["staging_log_positive_control"] = hits, control
            say(f"staging log leak hits: {hits}  positive control: {control}")
            if not hits or any(hits.values()) or not control:
                rc = rc or 3
        (L.BASE / "stage-result.json").write_text(redact(json.dumps(result, indent=1)))
        if not a.keep_work:
            L.cleanup_work()
        say(f"results: {L.BASE / 'results.json'} {L.BASE / 'stage-result.json'}")
    sys.exit(rc)


if __name__ == "__main__":
    main()
