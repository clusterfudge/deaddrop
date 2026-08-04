"""
Playwright test: per-conversation DM read state.

The thread list renders every 1:1 conversation from one inbox fetch. These
tests drive a real uvicorn server with a real database and assert the read
state the server holds after each interaction:

1. Rendering the thread list leaves every message unread.
2. Opening one conversation marks only that peer's messages read.
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
import uuid

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


def _get(url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


@pytest.fixture(scope="module")
def live_server():
    """Real uvicorn server on a file-backed sqlite database."""
    port = _free_port()
    db_path = f"/tmp/deadrop-dm-read-{port}.db"
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


@pytest.fixture
def fixture_data(live_server):
    """An inbox owner holding one unread message from each of two peers."""
    admin = {"X-Admin-Token": ADMIN_TOKEN}
    slug = f"dm-read-{uuid.uuid4().hex[:8]}"
    ns = _post(f"{live_server}/admin/namespaces", {"slug": slug, "ttl_hours": 24}, admin)
    owner = _post(
        f"{live_server}/admin/{ns['ns']}/identities",
        {"metadata": {"display_name": "Owner"}},
        admin,
    )
    alice = _post(
        f"{live_server}/admin/{ns['ns']}/identities",
        {"metadata": {"display_name": "Alice"}},
        admin,
    )
    bob = _post(
        f"{live_server}/admin/{ns['ns']}/identities",
        {"metadata": {"display_name": "Bob"}},
        admin,
    )

    for peer, body in ((alice, "from alice"), (bob, "from bob")):
        _post(
            f"{live_server}/{ns['ns']}/send",
            {"to": owner["id"], "body": body},
            {"X-Inbox-Secret": peer["secret"]},
        )

    return {
        "ns": ns["ns"],
        "slug": ns["slug"],
        "owner": owner,
        "alice": alice,
        "bob": bob,
        "credentials": {
            "version": 1,
            "namespaces": {
                ns["slug"]: {
                    "ns": ns["ns"],
                    "slug": ns["slug"],
                    "displayName": "DM Read",
                    "ttlHours": 24,
                    "identities": {
                        owner["id"]: {
                            "id": owner["id"],
                            "secret": owner["secret"],
                            "displayName": "Owner",
                            "addedAt": "2026-01-01T00:00:00.000Z",
                        }
                    },
                    "activeIdentity": owner["id"],
                }
            },
        },
    }


@pytest.fixture
def launch(live_server, fixture_data):
    """Open the app with the owner's credentials already stored."""
    with sync_playwright() as p:
        browser = p.chromium.launch()

        def _launch(path: str):
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
                                }
                            ],
                        }
                    ],
                },
            )
            pg = context.new_page()
            pg.goto(f"{live_server}{path}")
            return pg

        yield _launch
        browser.close()


def _read_state(live_server, fixture_data) -> dict[str, bool]:
    """Server-side read state per sender, fetched without marking anything."""
    owner = fixture_data["owner"]
    result = _get(
        f"{live_server}/{fixture_data['ns']}/inbox/{owner['id']}?mark_read=false",
        {"X-Inbox-Secret": owner["secret"]},
    )
    return {m["from"]: m["read_at"] is not None for m in result["messages"]}


def test_thread_list_does_not_mark_anything_read(launch, live_server, fixture_data):
    page = launch(f"/app/{fixture_data['slug']}")
    page.wait_for_selector(".thread-item")

    assert page.locator(".thread-item.unread").count() == 2
    assert _read_state(live_server, fixture_data) == {
        fixture_data["alice"]["id"]: False,
        fixture_data["bob"]["id"]: False,
    }


def test_opening_a_conversation_marks_only_that_peer(launch, live_server, fixture_data):
    page = launch(f"/app/{fixture_data['slug']}")
    page.wait_for_selector(".thread-item")

    page.locator(".thread-item", has_text="Alice").click()
    page.wait_for_function(
        "() => document.getElementById('conversation-title').textContent === 'Alice'"
    )

    expected = {fixture_data["alice"]["id"]: True, fixture_data["bob"]["id"]: False}
    deadline = time.time() + 5
    while time.time() < deadline:
        state = _read_state(live_server, fixture_data)
        if state == expected:
            break
        time.sleep(0.1)
    assert state == expected

    page.locator("#conversation-back").click()
    page.wait_for_function("() => document.querySelectorAll('.thread-item').length === 2")
    page.wait_for_function("() => document.querySelectorAll('.thread-item.unread').length === 1")

    assert page.locator(".thread-item.unread").count() == 1
