"""
Playwright tests: a non-v7 cursor stored in localStorage must not drive the
web client's subscription loop.

Cursors are compared as strings, so a stored v4 ('1e14…') sorts above every
v7 ('06af…') and can never be advanced. The client drops non-v7 entries in
`_loadCursors` and refuses them in `updateCursor`.

The poll fallback is the path that loops (SSE tracks its own cursor
server-side), so these tests abort `mode: "stream"` requests to force it.
Runs against a real uvicorn server on a scratch sqlite database.
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
POISONED_V4 = "1e141d46-f442-4391-b714-98aeb44c442f"
UUID7_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"

# How long the page is observed. A looping client issues hundreds of
# subscribes in this window; a healthy one issues at most two polls.
OBSERVE_MS = 3000


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
    db_path = f"/tmp/deadrop-bad-cursor-{port}.db"
    if os.path.exists(db_path):
        os.unlink(db_path)

    env = {
        **os.environ,
        "DEADROP_DB": db_path,
        "DEADROP_ADMIN_TOKEN": ADMIN_TOKEN,
        "DEADROP_MIGRATE_ON_START": "1",
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
    """Namespace, two identities, a room with messages from the other identity."""
    admin = {"X-Admin-Token": ADMIN_TOKEN}
    ns = _post(f"{live_server}/admin/namespaces", {"slug": "bad-cursor", "ttl_hours": 24}, admin)
    me = _post(f"{live_server}/admin/{ns['ns']}/identities", {}, admin)
    other = _post(f"{live_server}/admin/{ns['ns']}/identities", {}, admin)
    room = _post(
        f"{live_server}/{ns['ns']}/rooms",
        {"display_name": "Room"},
        {"X-Inbox-Secret": me["secret"]},
    )
    _post(
        f"{live_server}/{ns['ns']}/rooms/{room['room_id']}/members",
        {"identity_id": other["id"]},
        {"X-Inbox-Secret": me["secret"]},
    )
    for i in range(3):
        _post(
            f"{live_server}/{ns['ns']}/rooms/{room['room_id']}/messages",
            {"body": f"message {i}"},
            {"X-Inbox-Secret": other["secret"]},
        )

    return {
        "slug": ns["slug"],
        "room_id": room["room_id"],
        "topic": f"room:{room['room_id']}",
        "cursor_key": f"deadrop_cursors_{ns['ns']}_{me['id']}",
        "credentials": {
            "version": 1,
            "namespaces": {
                ns["slug"]: {
                    "ns": ns["ns"],
                    "slug": ns["slug"],
                    "displayName": "Bad Cursor",
                    "ttlHours": 24,
                    "identities": {
                        me["id"]: {
                            "id": me["id"],
                            "secret": me["secret"],
                            "displayName": "Tester",
                            "addedAt": "2026-01-01T00:00:00.000Z",
                        }
                    },
                    "activeIdentity": me["id"],
                }
            },
        },
    }


@pytest.fixture
def poisoned_page(live_server, fixture_data):
    """Open the room with a v4 cursor stored for it and SSE unavailable.

    Yields (page, polls) where `polls` records the cursor each poll-mode
    subscribe carried, in order.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            service_workers="block",
            storage_state={
                "cookies": [],
                "origins": [
                    {
                        "origin": live_server,
                        "localStorage": [
                            {
                                "name": "deadrop_credentials",
                                "value": json.dumps(fixture_data["credentials"]),
                            },
                            {
                                "name": fixture_data["cursor_key"],
                                "value": json.dumps({fixture_data["topic"]: POISONED_V4}),
                            },
                        ],
                    }
                ],
            },
        )
        page = context.new_page()
        polls: list[str | None] = []

        def route_subscribe(route):
            body = json.loads(route.request.post_data or "{}")
            if body.get("mode") == "stream":
                route.abort()
                return
            polls.append(body.get("topics", {}).get(fixture_data["topic"]))
            route.continue_()

        page.route("**/subscribe", route_subscribe)
        page.goto(f"{live_server}/app/{fixture_data['slug']}/room/{fixture_data['room_id']}")
        yield page, polls
        browser.close()


def test_poisoned_cursor_does_not_hot_loop(poisoned_page, fixture_data):
    """One first-load poll, then exactly one poll that waits on a v7 cursor."""
    page, polls = poisoned_page
    page.wait_for_timeout(OBSERVE_MS)

    assert POISONED_V4 not in polls, f"client sent the stored v4 cursor: {polls}"
    assert len(polls) <= 2, f"{len(polls)} polls in {OBSERVE_MS} ms — hot loop"
    waiting = [c for c in polls if c is not None]
    assert len(waiting) == 1, f"expected one waiting poll, got {polls}"
    assert page.evaluate(f"() => /{UUID7_RE}/i.test({json.dumps(waiting[0])})")


def test_poisoned_cursor_is_replaced_in_storage(poisoned_page, fixture_data):
    """The stored v4 is replaced by a v7 mid with no manual step."""
    page, _ = poisoned_page
    page.wait_for_timeout(1000)

    stored = json.loads(
        page.evaluate(f"() => localStorage.getItem({json.dumps(fixture_data['cursor_key'])})")
    )
    cursor = stored.get(fixture_data["topic"])
    assert cursor != POISONED_V4
    assert page.evaluate(f"() => window.isUuidV7({json.dumps(cursor)})"), cursor
    assert page.evaluate(
        "() => document.getElementById('room-catchup-indicator').classList.contains('hidden')"
    )


def test_update_cursor_refuses_non_v7(poisoned_page, fixture_data):
    page, _ = poisoned_page
    result = page.evaluate(
        """(poison) => {
            const m = new SubscriptionManager({ns: 'x', id: 'y', secret: 's'});
            m.cursors = {};
            m.updateCursor('room:a', poison);
            const refused = !('room:a' in m.cursors);
            m.cursors = {'room:b': poison};
            m.updateCursor('room:b', '06af11e6-86a1-7416-8000-0de7cf199b29');
            return {refused, replaced: m.cursors['room:b']};
        }""",
        POISONED_V4,
    )
    assert result == {"refused": True, "replaced": "06af11e6-86a1-7416-8000-0de7cf199b29"}
