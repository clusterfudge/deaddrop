"""Shared plumbing for fleet_e2e.py: secret vault, child envs, throwaway credential store,
local server, leak scan.

Every run works in its own fresh directory (``$DDFLEET_WORK``, else a new 0700 temp dir),
so nothing from an earlier run is deleted at startup and nothing a later scan needs is
deleted before it.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import httpx

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
# The interpreter running the harness is the repo venv; `deadrop` and `uvicorn` sit beside it.
VBIN = Path(sys.executable).parent
PY = sys.executable
_work = os.environ.get("DDFLEET_WORK")
OWN_WORK = not _work  # a caller-supplied work dir is the caller's to scan and delete
BASE = Path(_work) if _work else Path(tempfile.mkdtemp(prefix="dd-rotation-e2e-"))
BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
LOGS = BASE / "logs"
XDG = BASE / "xdg"
HOME = BASE / "home"
DELIVERED = BASE / "delivered"
INVITES = BASE / "invites"
KEEP = ("results.json", "stage-result.json", "logs/harness.log")  # redacted and scanned
LOOPBACK = ("127.0.0.1", "localhost", "::1")
REAL_CREDSTORE_PORTS = (9876, 9877)
STRIP_PREFIXES = (
    "DEADROP_",
    "DEADDROP_",
    "TURSO_",
    "GRAFANA_",
    "VAPID",
    "HEARE_AUTH",
    "H1_",
    "AGENTBOX_",
)
STRIP_EXACT = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy")


class Vault:
    """Every secret value minted or received; used to redact output and for the final leak scan."""

    def __init__(self):
        self.values: dict[str, str] = {}

    def add(self, label: str, value: str | None):
        if value and len(value) >= 6:
            self.values[value] = label
        return value

    def redact(self, text: str) -> str:
        for v in sorted(self.values, key=len, reverse=True):
            if v in text:
                text = text.replace(v, f"<{self.values[v]}>")
        return text


VAULT = Vault()
_logf = None


def log(msg: str):
    global _logf
    if _logf is None:
        LOGS.mkdir(parents=True, exist_ok=True)
        _logf = open(LOGS / "harness.log", "a")
    line = f"{time.strftime('%H:%M:%S')} {VAULT.redact(str(msg))}"
    print(line, flush=True)
    _logf.write(line + "\n")
    _logf.flush()


def child_env(**overrides) -> dict:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(STRIP_PREFIXES) and k not in STRIP_EXACT
    }
    env["PATH"] = f"{VBIN}:{env.get('PATH', '/usr/bin:/bin')}"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env.update({k: str(v) for k, v in overrides.items()})
    return env


def guard_url(url: str):
    """Loopback test servers only, and never the credential-store bridge ports."""
    u = urlparse(url)
    if u.hostname not in LOOPBACK or u.port in REAL_CREDSTORE_PORTS:
        raise SystemExit(
            f"refusing to run against {u.hostname}:{u.port}: loopback test server only"
        )


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def thermal_wait(limit: float = float(os.environ.get("DDFLEET_MAX_TEMP", "85"))):
    while True:
        try:
            out = subprocess.run(["sensors"], capture_output=True, text=True, timeout=10).stdout
            line = next((ln for ln in out.splitlines() if "Package id 0" in ln), "")
            temp = float(line.split("+")[1].split("°")[0]) if line else 0.0
        except Exception:
            return
        if temp <= limit:
            return
        log(f"thermal: {temp}C > {limit}C, sleeping 20s")
        time.sleep(20)


# ── throwaway credential store ─────────────────────────────────────────────
# Implements the two calls the clients make: GET /api/credentials/<name>
# -> {"ok": true, "data": {field: value}} and PATCH {"fields": {...}} (cli._push_credential).


class CredStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self.requests: list[tuple[str, str, int]] = []
        self._persist()
        store = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _name(self):
                pre = "/api/credentials/"
                return self.path[len(pre) :] if self.path.startswith(pre) else None

            def do_GET(self):
                name = self._name()
                with store.lock:
                    entry = store.data.get(name) if name else None
                code = 200 if entry else 404
                store.requests.append(("GET", str(name), code))
                self._reply(
                    code,
                    {"ok": True, "data": dict(entry)}
                    if entry
                    else {"ok": False, "error": "not found"},
                )

            def do_PATCH(self):
                name = self._name()
                body = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
                )
                fields = body.get("fields")
                with store.lock:
                    if not name or name not in store.data or not isinstance(fields, dict):
                        code = 404 if name not in store.data else 400
                    else:
                        store.data[name].update({k: str(v) for k, v in fields.items()})
                        store._persist()
                        code = 200
                store.requests.append(("PATCH", str(name), code))
                self._reply(code, {"ok": code == 200})

        self.server = ThreadingHTTPServer(("127.0.0.1", free_port()), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _persist(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=1)
        os.chmod(self.path, 0o600)

    def put(self, name: str, fields: dict):
        with self.lock:
            self.data[name] = {k: str(v) for k, v in fields.items()}
            self._persist()

    def get(self, name: str) -> dict:
        with self.lock:
            return dict(self.data[name])

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# ── local server (--local) ─────────────────────────────────────────────────


def start_local_server(port: int, admin_token: str, vapid: tuple[str, str] | None):
    port = port or free_port()
    db = BASE / "local.db"
    for suffix in ("", "-wal", "-shm"):
        Path(f"{db}{suffix}").unlink(missing_ok=True)
    env = child_env(DEADROP_DB=db, DEADROP_MIGRATE_ON_START="", DEADROP_ADMIN_TOKEN=admin_token)
    if vapid:
        env.update(
            DEADROP_PUSH_ENABLED="1",
            DEADROP_VAPID_PUBLIC_KEY=vapid[0],
            DEADROP_VAPID_PRIVATE_KEY=vapid[1],
            DEADROP_VAPID_SUBJECT="mailto:ddfleet@example.invalid",
        )
    mig = subprocess.run(
        ["nice", "-n", "19", PY, "-m", "deadrop.migrate"],
        cwd=REPO / "src",
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    (LOGS / "migrate.log").write_text(VAULT.redact(mig.stdout + mig.stderr))
    if mig.returncode != 0:
        raise SystemExit(f"migrate failed rc={mig.returncode}, see logs/migrate.log")
    out = open(LOGS / "server.log", "w")
    proc = subprocess.Popen(
        [
            "nice",
            "-n",
            "19",
            str(VBIN / "uvicorn"),
            "deadrop.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=REPO / "src",
        env=env,
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit("local server exited early, see logs/server.log")
        try:
            if httpx.get(f"{url}/health", timeout=1).status_code == 200:
                return proc, url
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    proc.kill()
    raise SystemExit("local server did not become healthy")


def leak_scan(paths: list[Path]) -> dict:
    """Count occurrences of every vault value in every file under paths."""
    hits: dict[str, int] = {}
    files = 0
    for root in paths:
        for f in [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file()):
            files += 1
            text = f.read_text(errors="replace")
            for v, label in VAULT.values.items():
                n = text.count(v)
                if n:
                    key = f"{f.relative_to(BASE)}:{label}"
                    hits[key] = hits.get(key, 0) + n
    return {
        "files_scanned": files,
        "values": len(VAULT.values),
        "hits": hits,
        "total": sum(hits.values()),
    }


def cleanup_work():
    """After the leak scan: delete everything in the work dir except the redacted KEEP files."""
    for f in sorted(BASE.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        rel = str(f.relative_to(BASE))
        if rel in KEEP or any(k.startswith(rel + "/") for k in KEEP):
            continue
        if f.is_dir() and not f.is_symlink():
            shutil.rmtree(f, ignore_errors=True)
        else:
            f.unlink(missing_ok=True)
