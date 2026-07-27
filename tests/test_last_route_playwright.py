"""
Playwright test: PWA last-route restore.

An installed PWA always relaunches at the manifest `start_url` (`/app`), so the
app has to resume the last route itself. These tests drive a real uvicorn server
with a real database, exercising three behaviors:

1. A bare launch at `/app` with a saved route resumes that route.
2. A launch carrying an explicit route is never overridden by the saved one
   (deep links, invites, and notification taps must win).
3. A saved route pointing at a room that 404s/403s falls back to the room list
   instead of leaving the room view stuck on its loading state.
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from playwright.sync_api import sync_playwright

pytestmark = pytest.mark.integration

REPO_ROOT = pathlib.Path(__file__).parent.parent
ADMIN_TOKEN = "test-admin-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(url: str, body: dict | None, headers: dict) -> dict:
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", **headers}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


@pytest.fixture(scope="module")
def live_server():
    """Real uvicorn server on a file-backed sqlite database."""
    port = _free_port()
    db_path = f"/tmp/deadrop-last-route-{port}.db"
    if os.path.exists(db_path):
        os.unlink(db_path)

    env = {
        **os.environ,
        "DEADROP_DB": db_path,
        "DEADROP_ADMIN_TOKEN": ADMIN_TOKEN,
    }
    env.pop("HEARE_AUTH_URL", None)

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "deadrop.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"server exited early: {proc.stdout.read().decode(errors='replace')}"
            )
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1):
                break
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("server did not become healthy")

    yield base

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture(scope="module")
def fixture_data(live_server):
    """Namespace + identity + two rooms, created through the real API."""
    admin = {"X-Admin-Token": ADMIN_TOKEN}
    ns = _post(
        f"{live_server}/admin/namespaces",
        {"slug": "restore-test", "ttl_hours": 24},
        admin,
    )
    identity = _post(f"{live_server}/admin/{ns['ns']}/identities", {}, admin)
    ident_hdr = {"X-Inbox-Secret": identity["secret"]}

    alpha = _post(f"{live_server}/{ns['ns']}/rooms", {"display_name": "Room Alpha"}, ident_hdr)
    beta = _post(f"{live_server}/{ns['ns']}/rooms", {"display_name": "Room Beta"}, ident_hdr)

    return {
        "slug": ns["slug"],
        "credentials": {
            "version": 1,
            "namespaces": {
                ns["slug"]: {
                    "ns": ns["ns"],
                    "slug": ns["slug"],
                    "displayName": "Restore Test",
                    "ttlHours": 24,
                    "identities": {
                        identity["id"]: {
                            "id": identity["id"],
                            "secret": identity["secret"],
                            "displayName": "Tester",
                            "addedAt": "2026-01-01T00:00:00.000Z",
                        }
                    },
                    "activeIdentity": identity["id"],
                }
            },
        },
        "alpha": alpha["room_id"],
        "beta": beta["room_id"],
    }


@pytest.fixture
def launch(live_server, fixture_data):
    """Open the app with credentials (and optionally a saved route) already stored.

    Seeding via an init script rather than a post-load `evaluate` means the very
    first document load sees the same storage an installed PWA would.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch()

        def _launch(path: str, last_route: str | None = None):
            entries = [
                {
                    "name": "deadrop_credentials",
                    "value": json.dumps(fixture_data["credentials"]),
                }
            ]
            if last_route:
                entries.append({"name": "deadrop_last_route", "value": last_route})
            # Service workers are blocked: a fresh context installs sw.js on
            # first load, and base.html reloads the page on `controllerchange`.
            # That mid-boot reload re-enters init() with whatever URL the SPA
            # had already pushed, which is a harness artifact rather than a
            # launch path a user hits (in a real install the SW is resident).
            context = browser.new_context(
                service_workers="block",
                storage_state={
                    "cookies": [],
                    "origins": [{"origin": live_server, "localStorage": entries}],
                },
            )
            pg = context.new_page()

            # Report the app as an installed PWA. The restore guard keys off the
            # URL rather than display-mode, but this keeps the launch realistic.
            cdp = context.new_cdp_session(pg)
            cdp.send(
                "Emulation.setEmulatedMedia",
                {"features": [{"name": "display-mode", "value": "standalone"}]},
            )

            pg.goto(f"{live_server}{path}")
            return pg

        yield _launch
        browser.close()


def _visible_view(page) -> str:
    return page.evaluate(
        """() => {
            const ids = ['namespaces', 'inbox', 'conversation', 'room-chat', 'archived'];
            return ids.find(i => !document.getElementById('view-' + i).classList.contains('hidden'));
        }"""
    )


def test_bare_launch_restores_last_room(launch, live_server, fixture_data):
    """A launch at the manifest start_url resumes the last-viewed room."""
    slug, alpha = fixture_data["slug"], fixture_data["alpha"]

    page = launch(f"/app/{slug}/room/{alpha}")
    page.wait_for_function(
        "() => document.getElementById('room-chat-title').textContent === 'Room Alpha'"
    )
    assert page.evaluate("() => localStorage.getItem('deadrop_last_route')") == (
        f"/app/{slug}/room/{alpha}"
    )

    # Relaunch at the bare start_url, as an installed PWA always does.
    page.goto(f"{live_server}/app")
    page.wait_for_function(
        "() => document.getElementById('room-chat-title').textContent === 'Room Alpha'"
    )

    assert _visible_view(page) == "room-chat"
    assert page.url == f"{live_server}/app/{slug}/room/{alpha}"


def test_explicit_route_is_not_overridden(launch, live_server, fixture_data):
    """A deep link wins over the saved route."""
    slug = fixture_data["slug"]
    alpha, beta = fixture_data["alpha"], fixture_data["beta"]

    page = launch(f"/app/{slug}/room/{beta}", last_route=f"/app/{slug}/room/{alpha}")
    page.wait_for_function(
        "() => document.getElementById('room-chat-title').textContent === 'Room Beta'"
    )

    assert page.url == f"{live_server}/app/{slug}/room/{beta}"
    assert alpha not in page.url


def test_stale_saved_room_falls_back_to_room_list(launch, live_server, fixture_data):
    """A saved room that no longer resolves lands on the room list, not a dead view."""
    slug = fixture_data["slug"]
    page = launch(
        "/app",
        last_route=f"/app/{slug}/room/0198e39d-0000-7000-8000-000000000000",
    )
    page.wait_for_function(
        "() => !document.getElementById('view-inbox').classList.contains('hidden')"
    )

    assert _visible_view(page) == "inbox"
    assert page.url == f"{live_server}/app/{slug}"


def test_unknown_namespace_falls_back_to_namespace_list(launch, live_server):
    """A saved route for a namespace we hold no credentials for is ignored."""
    page = launch("/app", last_route="/app/gone/room/abc")
    page.wait_for_timeout(500)

    assert _visible_view(page) == "namespaces"
    assert page.url == f"{live_server}/app"
