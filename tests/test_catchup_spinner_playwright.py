"""
Playwright tests for the room "Catching up…" indicator.

The indicator (`#room-catchup-indicator`) is visible while a room's message
backlog is in flight and hidden once every in-flight fetch has settled. Two
paths reach it:

1. `loadRoomMessages()` — initial room open and the foreground/`online`
   refresh, which replays the newest page.
2. `fetchNewRoomMessages()` — the incremental catch-up driven by a
   subscription event (SSE or poll fallback).

The mock room-messages endpoint sleeps `RESPONSE_DELAY_S` seconds so the
in-flight window is wide enough to observe deterministically.

Test approach mirrors tests/test_reverse_scroll_playwright.py: serve the app
template directly from a local HTTP server (bypassing FastAPI/Jinja2) and
point DeadropAPI at a mock API server.
"""

import http.server
import json
import pathlib
import re
import socket
import threading
import time

import pytest

from playwright.sync_api import sync_playwright

pytestmark = pytest.mark.integration

REPO_ROOT = pathlib.Path(__file__).parent.parent
STATIC_DIR = REPO_ROOT / "src" / "deadrop" / "static"
TEMPLATES_DIR = REPO_ROOT / "src" / "deadrop" / "templates"

TEST_HTTP_PORT = 19110
TEST_API_PORT = 19111

PAGE_SIZE = 20

# Seconds the mock endpoint stalls a room-messages response. Wide enough that
# Playwright can assert on the visible indicator without racing the fetch.
RESPONSE_DELAY_S = 1.0

ALL_MESSAGES = [
    {
        "mid": f"m{i:03d}",
        "room_id": "room-test",
        "from_id": "alice-id",
        "from": "alice-id",
        "body": f"Message number {i}",
        "content_type": "text/plain",
        "reference_mid": None,
        "created_at": f"2024-01-01T{(i // 60):02d}:{(i % 60):02d}:00Z",
        "attachments": [],
    }
    for i in range(1, 41)
]


# ---------------------------------------------------------------------------
# Mock API
# ---------------------------------------------------------------------------


class MockAPIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        qs = self.path.split("?")[1] if "?" in self.path else ""
        params = dict(kv.split("=", 1) for kv in qs.split("&") if "=" in kv)

        if re.match(r"^/[^/]+/rooms/[^/]+/messages$", path):
            time.sleep(RESPONSE_DELAY_S)
            before = params.get("before")
            after = params.get("after")
            limit = int(params.get("limit", PAGE_SIZE))

            msgs = list(ALL_MESSAGES)
            if before:
                msgs = [m for m in msgs if m["mid"] < before][-limit:]
            elif after:
                msgs = [m for m in msgs if m["mid"] > after][:limit]
            else:
                msgs = msgs[-limit:]
            self._json({"messages": msgs, "room_id": "room-test"})

        elif re.match(r"^/[^/]+/rooms/[^/]+/members$", path):
            self._json([{"identity_id": "alice-id", "metadata": {"display_name": "Alice"}}])

        elif re.match(r"^/[^/]+/rooms/[^/]+$", path):
            self._json({"room_id": "room-test", "display_name": "Catch-up Room", "member_count": 1})

        else:
            self._json({})

    def do_POST(self):
        self._json({})


# ---------------------------------------------------------------------------
# Static server — renders app.html with minimal Jinja2 substitution
# ---------------------------------------------------------------------------

_rendered_app_html: str | None = None


def _build_app_html() -> str:
    global _rendered_app_html
    if _rendered_app_html is not None:
        return _rendered_app_html

    base_html = (TEMPLATES_DIR / "base.html").read_text()
    app_html = (TEMPLATES_DIR / "app.html").read_text()

    def block(name: str, source: str) -> str:
        m = re.search(r"\{%% block %s %%\}(.+?)\{%% endblock %%\}" % name, source, re.DOTALL)
        return m.group(1) if m else ""

    title = block("title", app_html).strip() or "Deadrop"
    body_content = block("body", app_html)
    scripts_content = block("scripts", app_html)

    rendered = base_html
    for name, value in (
        ("title", title),
        ("body", body_content),
        ("scripts", scripts_content),
        ("head", ""),
    ):
        rendered = re.sub(
            r"\{%% block %s %%\}.*?\{%% endblock %%\}" % name,
            lambda _, v=value: v,
            rendered,
            flags=re.DOTALL,
        )

    rendered = (
        rendered.replace("{{ slug | tojson if slug else 'null' }}", "null")
        .replace("{{ peer_id | tojson if peer_id is defined and peer_id else 'null' }}", "null")
        .replace("{{ view | tojson if view is defined and view else 'null' }}", "null")
        .replace("{{ room_id | tojson if room_id is defined and room_id else 'null' }}", "null")
        .replace("{{ ROOM_PAGE_SIZE }}", str(PAGE_SIZE))
    )

    _rendered_app_html = rendered
    return rendered


class StaticHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/app", "/app/"):
            data = _build_app_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path.startswith("/static/"):
            file_path = STATIC_DIR / path[len("/static/") :]
            if file_path.exists() and file_path.is_file():
                data = file_path.read_bytes()
                ct = {
                    ".js": "application/javascript",
                    ".css": "text/css",
                    ".html": "text/html",
                }.get(file_path.suffix, "application/octet-stream")
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        self.send_response(404)
        self.end_headers()


def _serve(handler, port):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return server


@pytest.fixture(scope="module")
def servers():
    api = _serve(MockAPIHandler, TEST_API_PORT)
    static = _serve(StaticHandler, TEST_HTTP_PORT)
    yield {
        "app": f"http://127.0.0.1:{TEST_HTTP_PORT}",
        "api": f"http://127.0.0.1:{TEST_API_PORT}",
    }
    for server in (api, static):
        server.shutdown()
        server.server_close()


INJECT_JS = f"""
    const slug = 'test-slug';
    localStorage.setItem('deadrop_credentials', JSON.stringify({{
        version: 1,
        namespaces: {{
            [slug]: {{
                ns: 'test-ns',
                slug,
                displayName: 'Test NS',
                ttlHours: 0,
                identities: {{
                    'alice-id': {{
                        id: 'alice-id',
                        secret: 'alice-secret',
                        displayName: 'Alice',
                        addedAt: '2024-01-01T00:00:00.000Z',
                    }}
                }},
                activeIdentity: 'alice-id',
            }}
        }}
    }}));
    window._MOCK_API_BASE = 'http://127.0.0.1:{TEST_API_PORT}';
"""

PATCH_API_JS = """
    DeadropAPI.request = async function(method, path, options) {
        const headers = {};
        if (options?.credentials?.secret) headers['X-Inbox-Secret'] = options.credentials.secret;
        let body;
        if (options?.body) {
            headers['Content-Type'] = 'application/json';
            body = JSON.stringify(options.body);
        }
        const resp = await fetch(window._MOCK_API_BASE + path, { method, headers, body });
        if (!resp.ok) throw new Error(`API error: ${resp.status}`);
        return resp.json();
    };
    // Trailing non-function value: Playwright invokes an evaluated
    // expression whose result is a function.
    'patched';
"""

# Playwright awaits an evaluated expression that resolves to a promise, so the
# openRoom promise is parked on `window` and a literal is returned instead —
# otherwise the call would not return until the load it starts has finished.
OPEN_ROOM_JS = """
    credentials = CredentialStore.getCredentials('test-slug');
    currentSlug = 'test-slug';
    currentRoomId = 'room-test';
    window.__open = openRoom('room-test');
    'opening';
"""


def _boot(page, servers):
    """Load the app, wire up credentials + mock API, and return the page."""
    page.goto(servers["app"])
    page.wait_for_load_state("networkidle")
    page.evaluate(INJECT_JS)
    page.wait_for_function("typeof openRoom === 'function'", timeout=10000)
    page.evaluate(PATCH_API_JS)
    return page


class TestCatchupIndicator:
    def test_initial_room_load_shows_then_hides_indicator(self, servers):
        """Opening a room shows the indicator for the duration of the fetch."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_context(viewport={"width": 420, "height": 800}).new_page()
            _boot(page, servers)

            indicator = page.locator("#room-catchup-indicator")
            assert indicator.is_hidden(), "Indicator should start hidden"

            page.evaluate(OPEN_ROOM_JS)

            # Visible while the backlog fetch is in flight.
            indicator.wait_for(state="visible", timeout=5000)
            assert page.locator("#room-catchup-indicator .spinner").count() == 1

            # Hidden once the fetch (page + reactions) settles.
            indicator.wait_for(state="hidden", timeout=15000)

            page.wait_for_function(
                "document.querySelectorAll('.room-message').length > 0", timeout=10000
            )
            assert page.evaluate("roomCatchupDepth") == 0
            browser.close()

    def test_catchup_fetch_shows_then_hides_indicator(self, servers):
        """A subscription-driven catch-up fetch drives the same indicator."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_context(viewport={"width": 420, "height": 800}).new_page()
            _boot(page, servers)

            page.evaluate(OPEN_ROOM_JS)
            page.wait_for_function(
                "document.querySelectorAll('.room-message').length > 0", timeout=15000
            )
            page.locator("#room-catchup-indicator").wait_for(state="hidden", timeout=15000)

            # Fire the catch-up path without awaiting it.
            page.evaluate("window.__catchup = fetchNewRoomMessages('room-test'); 'fetching';")

            indicator = page.locator("#room-catchup-indicator")
            indicator.wait_for(state="visible", timeout=5000)
            indicator.wait_for(state="hidden", timeout=15000)
            assert page.evaluate("roomCatchupDepth") == 0
            browser.close()

    def test_overlapping_fetches_keep_indicator_visible(self, servers):
        """The last fetch to settle is the one that hides the indicator."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_context(viewport={"width": 420, "height": 800}).new_page()
            _boot(page, servers)

            page.evaluate(OPEN_ROOM_JS)
            page.wait_for_function(
                "document.querySelectorAll('.room-message').length > 0", timeout=15000
            )
            page.locator("#room-catchup-indicator").wait_for(state="hidden", timeout=15000)

            page.evaluate("setRoomCatchupBusy(true); setRoomCatchupBusy(true);")
            assert page.locator("#room-catchup-indicator").is_visible()

            page.evaluate("setRoomCatchupBusy(false);")
            assert page.locator("#room-catchup-indicator").is_visible(), (
                "One fetch is still in flight — indicator must stay visible"
            )

            page.evaluate("setRoomCatchupBusy(false);")
            page.locator("#room-catchup-indicator").wait_for(state="hidden", timeout=2000)

            # Depth never goes negative, so a stray hide cannot desync it.
            page.evaluate("setRoomCatchupBusy(false);")
            assert page.evaluate("roomCatchupDepth") == 0
            browser.close()

    @pytest.mark.parametrize("theme", ["light", "dark"])
    def test_spinner_colors_come_from_theme_tokens(self, servers, theme):
        """The ring reads --border-color / --primary-color, not literals."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_context(viewport={"width": 420, "height": 800}).new_page()
            _boot(page, servers)

            page.evaluate(f"applyTheme('{theme}'); 'themed';")
            page.evaluate(OPEN_ROOM_JS)
            page.locator("#room-catchup-indicator").wait_for(state="visible", timeout=5000)

            colors = page.evaluate("""
                (() => {
                    const el = document.querySelector('#room-catchup-indicator .spinner');
                    const cs = getComputedStyle(el);
                    const root = getComputedStyle(document.documentElement);
                    return {
                        ring: cs.borderTopColor,
                        track: cs.borderRightColor,
                        primaryToken: root.getPropertyValue('--primary-color').trim(),
                        borderToken: root.getPropertyValue('--border-color').trim(),
                        width: cs.width,
                    };
                })()
            """)

            def to_rgb(hex_color):
                h = hex_color.lstrip("#")
                return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))

            assert colors["ring"] == "rgb(%d, %d, %d)" % to_rgb(colors["primaryToken"])
            assert colors["track"] == "rgb(%d, %d, %d)" % to_rgb(colors["borderToken"])
            assert colors["width"] == "14px", "Header ring should use the inline size"
            browser.close()
