"""Client drivers. Each returns plain dicts with no secret values."""

import asyncio
import concurrent.futures
import json
import shutil
import subprocess
import time
from pathlib import Path

import httpx

from fleet_lib import BASE, HERE, HOME, LOGS, PY, VAULT, VBIN, child_env

CLIENTS = HERE / "clients"
H1TOOLS = BASE / "h1tools"
PYCLIENT_CRED = "ddfleet.pyclient"
H1_CRED = "deaddrop.ddfleet-h1"
# fritz-heare/tools layout -> flat copy (the scripts import their helpers as siblings)
H1_FILES = {
    "deaddrop_send_room.py": "comms",
    "deaddrop_read_room.py": "comms",
    "_deaddrop_rooms.py": "shared",
    "_silica_toolspec.py": "shared",
    "deaddrop_watcher.py": "feeds",
}


def stage_h1tools(src: Path) -> str:
    """Copy the harness1 deaddrop scripts, unmodified, from a tools checkout into the work dir."""
    H1TOOLS.mkdir(exist_ok=True)
    for name, sub in H1_FILES.items():
        f = next((p for p in (src / sub / name, src / name) if p.is_file()), None)
        if f is None:
            raise SystemExit(
                f"{name} not found under {src} (expected a fritz-heare/tools checkout)"
            )
        shutil.copy2(f, H1TOOLS / name)
    rev = subprocess.run(
        ["git", "-C", str(src), "rev-parse", "--short", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    return rev or "unknown"


def _run(argv, env, timeout=90):
    p = subprocess.run(
        ["nice", "-n", "19", *argv],
        cwd=BASE,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def _last_json(text: str) -> dict:
    for line in reversed(text.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return {}


# ── raw HTTP probes (assertions, not a client) ─────────────────────────────


def raw_post(url, ns, room, secret, body):
    r = httpx.post(
        f"{url}/{ns}/rooms/{room}/messages",
        json={"body": body},
        headers={"X-Inbox-Secret": secret},
        timeout=15,
    )
    detail = ""
    if r.status_code >= 400:
        try:
            detail = str(r.json().get("detail", ""))[:40]
        except ValueError:
            detail = r.text[:40]
    return {
        "status": r.status_code,
        "retired": detail.startswith("credential_retired"),
        "mid": r.json().get("mid") if r.status_code == 200 else None,
    }


def raw_read_mids(url, ns, room, secret):
    r = httpx.get(
        f"{url}/{ns}/rooms/{room}/messages?limit=500",
        headers={"X-Inbox-Secret": secret},
        timeout=15,
    )
    return [m["mid"] for m in r.json().get("messages", [])] if r.status_code == 200 else None


# ── 1. real deadrop python client, store-driven ────────────────────────────


def pyclient(store_url, body):
    rc, out, err = _run(
        [PY, str(CLIENTS / "pyclient_op.py"), PYCLIENT_CRED, body],
        child_env(DDFLEET_CREDSTORE=store_url, HOME=HOME),
    )
    (LOGS / "pyclient.log").open("a").write(VAULT.redact(out + err))
    res = _last_json(out)
    res.setdefault("ok", False)
    return res


# ── 2. harness1 tools (fritz-heare/tools, verbatim copies) ─────────────────


def _h1_env(store_url):
    return child_env(
        DDFLEET_CREDSTORE=store_url, H1_DEADDROP_CRED=H1_CRED, H1_PERSONA="ddfleet-h1", HOME=HOME
    )


def h1_send(store_url, body):
    rc, out, err = _run(
        [PY, str(CLIENTS / "h1_run.py"), str(H1TOOLS / "deaddrop_send_room.py"), "--message", body],
        _h1_env(store_url),
    )
    (LOGS / "h1_tools.log").open("a").write(VAULT.redact(f"[send rc={rc}] {out}{err}"))
    res = _last_json(out)
    return {
        "ok": bool(res.get("success")),
        "mid": res.get("mid"),
        "status": 403 if "403" in str(res.get("error", "")) else None,
    }


def h1_read(store_url, expect_body):
    rc, out, err = _run(
        [PY, str(CLIENTS / "h1_run.py"), str(H1TOOLS / "deaddrop_read_room.py"), "--limit", "200"],
        _h1_env(store_url),
    )
    (LOGS / "h1_tools.log").open("a").write(VAULT.redact(f"[read rc={rc}] {out[-2000:]}{err}"))
    failed = out.strip().startswith('{"success": false')
    return {
        "ok": (not failed) and expect_body in out,
        "status": 403 if failed and "403" in out else None,
    }


class Watcher:
    """feeds/deaddrop_watcher.py as a long-running subprocess (its real main loop)."""

    def __init__(self, store_url):
        self.store_url = store_url
        self.n = 0
        self.proc = None

    def start(self):
        self.n += 1
        self.out = LOGS / f"watcher-{self.n}.out"
        self.err = LOGS / f"watcher-{self.n}.err"
        self.proc = subprocess.Popen(
            [
                "nice",
                "-n",
                "19",
                PY,
                "-u",
                str(CLIENTS / "h1_run.py"),
                str(H1TOOLS / "deaddrop_watcher.py"),
            ],
            cwd=BASE,
            env=_h1_env(self.store_url),
            stdout=open(self.out, "w"),
            stderr=open(self.err, "w"),
        )
        deadline = time.time() + 30
        while time.time() < deadline and "subscribing to" not in self.err.read_text():
            time.sleep(0.5)
        time.sleep(2)  # first subscribe in flight
        return "subscribing to" in self.err.read_text()

    def saw(self, body, timeout=40):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if body in self.out.read_text():
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.5)
        return False

    def stderr_has(self, needle):
        return needle in self.err.read_text()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        for f in (self.out, self.err):
            f.write_text(VAULT.redact(f.read_text()))


# ── 3. MCP (mcp package streamable-http client) ────────────────────────────


def mcp_url(url, ns, secret):
    return f"{url}/mcp/{ns}/{secret}"


async def _mcp(url, room, body):
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with streamable_http_client(url) as streams:
        async with ClientSession(streams[0], streams[1]) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            rooms = await s.call_tool("list_rooms", {})
            sent = await s.call_tool("send_message", {"room_id": room, "body": body})
            read = await s.call_tool("read_room", {"room_id": room, "limit": 200})

            def text(r):
                return "".join(getattr(c, "text", "") for c in r.content)

            return {
                "ok": not (rooms.is_error or sent.is_error or read.is_error)
                and room in text(rooms)
                and body in text(read),
                "tools": tools,
            }


def mcp_client(url, room, body):
    try:
        # playwright's sync API owns this thread's event loop; MCP gets its own thread + loop
        with concurrent.futures.ThreadPoolExecutor(1) as ex:
            return ex.submit(
                lambda: asyncio.run(asyncio.wait_for(_mcp(url, room, body), 30))
            ).result()
    except BaseException as e:  # noqa: BLE001 -- ExceptionGroup from anyio
        status = raw_mcp_status(url)
        return {"ok": False, "status": status, "error": VAULT.redact(type(e).__name__)}


def raw_mcp_status(url):
    r = httpx.post(
        url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ddfleet", "version": "0"},
            },
        },
        headers={"Accept": "application/json, text/event-stream"},
        timeout=15,
    )
    return r.status_code


# ── invites: claim the way a non-browser client must ───────────────────────


def read_delivered(identity_id):
    p = BASE / "delivered" / f"{identity_id}.url"
    url = p.read_text().strip()
    VAULT.add("invite-url", url)
    VAULT.add("invite-key", url.split("#", 1)[1])
    return url


def cli_claim(invite_url):
    """The real `deadrop claim` against a recovery invite (it has no PIN input)."""
    xdg = BASE / "xdg-claim"
    xdg.mkdir(exist_ok=True)
    (xdg / "deadrop").mkdir(exist_ok=True)
    (xdg / "deadrop" / "config.yaml").write_text("url: http://127.0.0.1:1\n")
    p = subprocess.run(
        ["nice", "-n", "19", str(VBIN / "deadrop"), "claim", invite_url],
        cwd=BASE,
        env=child_env(XDG_CONFIG_HOME=xdg, HOME=HOME),
        capture_output=True,
        text=True,
        timeout=60,
    )
    (LOGS / "cli.log").open("a").write(
        VAULT.redact(f"$ deadrop claim <invite-url>  rc={p.returncode}\n{p.stdout}{p.stderr}\n")
    )
    return {
        "rc": p.returncode,
        "pin_required": "PIN" in (p.stdout + p.stderr) or "pin" in (p.stdout + p.stderr),
    }


def api_claim(invite_url, pin):
    """POST /api/invites/<id>/claim {pin} + deadrop.crypto.decrypt_invite_secret (what join.html does)."""
    from urllib.parse import urlparse

    from deadrop.crypto import decrypt_invite_secret

    u = urlparse(invite_url)
    invite_id = u.path.rsplit("/", 1)[1]
    r = httpx.post(
        f"{u.scheme}://{u.netloc}/api/invites/{invite_id}/claim", json={"pin": pin}, timeout=15
    )
    if r.status_code != 200:
        return None
    d = r.json()
    secret = decrypt_invite_secret(
        encrypted_secret_hex=d["encrypted_secret"], key_base64=u.fragment, invite_id=invite_id
    )
    return VAULT.add("claimed-secret", secret)
