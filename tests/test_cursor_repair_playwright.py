"""Playwright test: the web client repairs poisoned (non-v7) cursors.

A UUIDv4 held in localStorage sorts above every UUIDv7, so the old
`mid > this.cursors[topic]` comparison could never advance past one. The
client now treats a non-v7 stored cursor as unset and drops non-v7 entries
on load.
"""

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

POISONED_V4 = "1e141d46-f442-4391-b714-98aeb44c442f"
V7_OLDER = "0194aaaa-0000-7000-8000-000000000001"
V7_NEWER = "01f0bbbb-0000-7000-8000-000000000002"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_server():
    """Real uvicorn server — the page must be same-origin to use localStorage."""
    port = _free_port()
    db_path = f"/tmp/deadrop-cursor-repair-{port}.db"
    if os.path.exists(db_path):
        os.unlink(db_path)

    env = {**os.environ, "DEADROP_DB": db_path, "DEADROP_ADMIN_TOKEN": "test-admin-token"}
    env.pop("HEARE_AUTH_URL", None)

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "deadrop.api:app", "--port", str(port)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{base}/health", timeout=1)
            break
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("server did not start")

    yield base
    proc.terminate()
    proc.wait(timeout=10)
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def page(live_server):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        # Any same-origin document works and localStorage needs a real
        # origin; the asset itself is the most inert page available.
        page.goto(f"{live_server}/static/js/api.js")
        page.wait_for_load_state("load")
        page.add_script_tag(url="/static/js/api.js")
        page.wait_for_function("() => typeof window.isUuidV7 === 'function'")
        yield page
        browser.close()


def _manager(page, stored):
    """Seed localStorage with `stored` and build a SubscriptionManager over it."""
    return page.evaluate(
        """([stored]) => {
            localStorage.setItem('deadrop_cursors_ns1_id1', JSON.stringify(stored));
            const m = new window.SubscriptionManager({ns: 'ns1', id: 'id1', secret: 's'});
            return m.cursors;
        }""",
        [stored],
    )


def test_is_uuid_v7(page):
    assert page.evaluate("(v) => window.isUuidV7(v)", V7_NEWER) is True
    assert page.evaluate("(v) => window.isUuidV7(v)", POISONED_V4) is False
    assert page.evaluate("() => window.isUuidV7(null)") is False
    assert page.evaluate("() => window.isUuidV7(undefined)") is False
    assert page.evaluate("() => window.isUuidV7('')") is False
    assert page.evaluate("() => window.isUuidV7('pending-1748900000')") is False


def test_v7_mid_replaces_a_poisoned_v4_cursor(page):
    """The regression that matters: a v4 must not wedge the cursor."""
    result = page.evaluate(
        """([poisoned, mid]) => {
            localStorage.setItem('deadrop_cursors_ns1_id1', JSON.stringify({}));
            const m = new window.SubscriptionManager({ns: 'ns1', id: 'id1', secret: 's'});
            m.cursors['room:r1'] = poisoned;   // bypass load-time filtering
            m.updateCursor('room:r1', mid);
            return m.cursors['room:r1'];
        }""",
        [POISONED_V4, V7_NEWER],
    )
    assert result == V7_NEWER


def test_load_drops_non_v7_entries(page):
    cursors = _manager(page, {"room:r1": POISONED_V4, "room:r2": V7_NEWER})
    assert cursors == {"room:r2": V7_NEWER}


def test_v7_ordering_still_holds(page):
    result = page.evaluate(
        """([older, newer]) => {
            localStorage.setItem('deadrop_cursors_ns1_id1', JSON.stringify({'room:r1': newer}));
            const m = new window.SubscriptionManager({ns: 'ns1', id: 'id1', secret: 's'});
            m.updateCursor('room:r1', older);
            return m.cursors['room:r1'];
        }""",
        [V7_OLDER, V7_NEWER],
    )
    assert result == V7_NEWER, "cursor moved backwards"


def test_absent_cursor_is_set_by_first_v7(page):
    result = page.evaluate(
        """(mid) => {
            localStorage.removeItem('deadrop_cursors_ns1_id1');
            const m = new window.SubscriptionManager({ns: 'ns1', id: 'id1', secret: 's'});
            m.updateCursor('room:r1', mid);
            return m.cursors['room:r1'];
        }""",
        V7_NEWER,
    )
    assert result == V7_NEWER


def test_non_v7_mid_cannot_repoison(page):
    result = page.evaluate(
        """([mid, poisoned]) => {
            localStorage.setItem('deadrop_cursors_ns1_id1', JSON.stringify({'room:r1': mid}));
            const m = new window.SubscriptionManager({ns: 'ns1', id: 'id1', secret: 's'});
            m.updateCursor('room:r1', poisoned);
            return m.cursors['room:r1'];
        }""",
        [V7_NEWER, POISONED_V4],
    )
    assert result == V7_NEWER
