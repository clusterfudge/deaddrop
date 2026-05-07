"""
Playwright test: tab visibility refresh of room messages.

Symptom (pre-fix): When the browser tab loses visibility, the subscription
is stopped (correct). While hidden, new messages arrive on the server.
When the tab regains visibility, the viewer is supposed to call
`loadRoomMessages()` which refetches the latest page — and new messages
should appear in the DOM.

This test drives a mocked API and simulates visibility change events to
verify that new messages arriving during the hidden window *do* show up
after the tab becomes visible again.

If this test fails, the visibility handler in `app.html` is not
delivering missed messages, and a fix is needed.
"""

import http.server
import json
import pathlib
import re
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

# Mutable message list — we'll add to this to simulate new server-side msgs
_messages_lock = threading.Lock()
_all_messages: list[dict] = []


def _seed_messages() -> None:
    """Reset message store to 20 seeded messages."""
    global _all_messages
    with _messages_lock:
        _all_messages = [
            {
                "mid": f"m{i:03d}",
                "room_id": "room-test",
                "from_id": "alice-id",
                "from": "alice-id",
                "body": f"Seed message {i}",
                "content_type": "text/plain",
                "reference_mid": None,
                "created_at": f"2024-01-01T00:{i:02d}:00Z",
                "attachments": [],
            }
            for i in range(1, PAGE_SIZE + 1)
        ]


def _append_message(mid: str, body: str) -> None:
    """Append a new message to the mock store (simulates server-side arrival)."""
    with _messages_lock:
        _all_messages.append(
            {
                "mid": mid,
                "room_id": "room-test",
                "from_id": "bob-id",
                "from": "bob-id",
                "body": body,
                "content_type": "text/plain",
                "reference_mid": None,
                "created_at": "2024-01-02T00:00:00Z",
                "attachments": [],
            }
        )


class MockAPIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        qs = self.path.split("?")[1] if "?" in self.path else ""
        params = {}
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v

        if re.match(r"^/[^/]+/rooms/[^/]+/messages$", path):
            before = params.get("before")
            after = params.get("after")
            limit = int(params.get("limit", PAGE_SIZE))

            with _messages_lock:
                msgs = list(_all_messages)

            if before:
                msgs = [m for m in msgs if m["mid"] < before]
                msgs = msgs[-limit:]
            elif after:
                msgs = [m for m in msgs if m["mid"] > after]
                msgs = msgs[:limit]
            else:
                msgs = msgs[-limit:]

            body = json.dumps({"messages": msgs, "room_id": "room-test"}).encode()
            self._respond(200, body, "application/json")
            return

        if re.match(r"^/[^/]+/rooms/[^/]+/members$", path):
            body = json.dumps(
                [{"identity_id": "alice-id", "metadata": {"display_name": "Alice"}}]
            ).encode()
            self._respond(200, body, "application/json")
            return

        if re.match(r"^/[^/]+/rooms/[^/]+$", path):
            body = json.dumps(
                {
                    "room_id": "room-test",
                    "display_name": "Visibility Test Room",
                    "member_count": 1,
                }
            ).encode()
            self._respond(200, body, "application/json")
            return

        if re.match(r"^/[^/]+/rooms/[^/]+/read_cursor$", path):
            self._respond(200, b"{}", "application/json")
            return

        # Stub subscribe endpoint — just hang briefly so the client
        # doesn't thrash. We don't exercise SSE in this test.
        if "/subscribe" in path:
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            # Keep open briefly; test triggers visibilitychange anyway.
            try:
                time.sleep(0.5)
            except Exception:
                pass
            return

        self.send_response(404)
        self._cors()
        self.end_headers()

    def do_POST(self):
        # Accept subscribe poll + read cursor + anything else
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        # Default: empty poll response (no events)
        self._respond(200, b'{"events": {}, "timeout": true}', "application/json")

    def _respond(self, status, body, ctype):
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_mock_api():
    server = http.server.HTTPServer(("127.0.0.1", TEST_API_PORT), MockAPIHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


_rendered_app_html: str | None = None


def _build_app_html() -> str:
    global _rendered_app_html
    if _rendered_app_html is not None:
        return _rendered_app_html

    base_html = (TEMPLATES_DIR / "base.html").read_text()
    app_html = (TEMPLATES_DIR / "app.html").read_text()

    title_match = re.search(r"\{% block title %\}(.+?)\{% endblock %\}", app_html, re.DOTALL)
    body_match = re.search(r"\{% block body %\}(.+?)\{% endblock %\}", app_html, re.DOTALL)
    scripts_match = re.search(r"\{% block scripts %\}(.+?)\{% endblock %\}", app_html, re.DOTALL)

    title = title_match.group(1).strip() if title_match else "Deadrop"
    body_content = body_match.group(1) if body_match else ""
    scripts_content = scripts_match.group(1) if scripts_match else ""

    rendered = base_html
    rendered = re.sub(
        r"\{% block title %\}.*?\{% endblock %\}", lambda _: title, rendered, flags=re.DOTALL
    )
    rendered = re.sub(
        r"\{% block body %\}.*?\{% endblock %\}", lambda _: body_content, rendered, flags=re.DOTALL
    )
    rendered = re.sub(
        r"\{% block scripts %\}.*?\{% endblock %\}",
        lambda _: scripts_content,
        rendered,
        flags=re.DOTALL,
    )
    rendered = re.sub(
        r"\{% block head %\}.*?\{% endblock %\}", lambda _: "", rendered, flags=re.DOTALL
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
            body_bytes = _build_app_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)
            return

        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            file_path = STATIC_DIR / rel
            if file_path.exists() and file_path.is_file():
                data = file_path.read_bytes()
                suffix = file_path.suffix
                ct = {
                    ".js": "application/javascript",
                    ".css": "text/css",
                    ".html": "text/html",
                }.get(suffix, "application/octet-stream")
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        self.send_response(404)
        self.end_headers()


def start_static_server():
    server = http.server.HTTPServer(("127.0.0.1", TEST_HTTP_PORT), StaticHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    import socket

    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", TEST_HTTP_PORT), timeout=0.2)
            s.close()
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return server


@pytest.fixture(scope="module")
def servers():
    _seed_messages()
    api_server = start_mock_api()
    http_server = start_static_server()
    yield {
        "app": f"http://127.0.0.1:{TEST_HTTP_PORT}",
        "api": f"http://127.0.0.1:{TEST_API_PORT}",
    }
    api_server.shutdown()
    http_server.shutdown()


INJECT_JS = f"""
    const ns = 'test-ns';
    const slug = 'test-slug';
    const creds = {{
        version: 1,
        namespaces: {{
            [slug]: {{
                ns,
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
    }};
    localStorage.setItem('deadrop_credentials', JSON.stringify(creds));
    window._MOCK_API_BASE = 'http://127.0.0.1:{TEST_API_PORT}';
"""

PATCH_API_JS = """
    const origRequest = DeadropAPI.request.bind(DeadropAPI);
    DeadropAPI.request = async function(method, path, options) {
        const url = window._MOCK_API_BASE + path;
        const headers = {};
        if (options?.credentials?.secret) {
            headers['X-Inbox-Secret'] = options.credentials.secret;
        }
        let body = undefined;
        if (options?.body) {
            headers['Content-Type'] = 'application/json';
            body = JSON.stringify(options.body);
        }
        const resp = await fetch(url, { method, headers, body });
        if (!resp.ok) throw new Error(`API error: ${resp.status}`);
        return resp.json();
    };
    // Neutralize the subscription stream so tests don't rely on SSE infra
    if (window.SubscriptionManager) {
        SubscriptionManager.prototype._runSSE = async function () {
            // Resolve quickly; outer start() loop will keep scheduling retries.
            await new Promise(r => setTimeout(r, 10));
            throw new Error('stream closed (test stub)');
        };
        SubscriptionManager.prototype._runPollLoop = async function () {
            await new Promise(r => setTimeout(r, 10));
            throw new Error('poll closed (test stub)');
        };
    }
    console.log('DeadropAPI + SubscriptionManager patched for test');
"""


class TestVisibilityRefresh:
    def test_messages_arriving_while_hidden_appear_on_return(self, servers):
        """
        1. Open the room view — 20 seed messages render.
        2. Fire visibilitychange 'hidden'.
        3. Append a new message to the mock API (simulating server-side arrival).
        4. Fire visibilitychange 'visible'.
        5. Assert: the new message appears in the DOM.
        """
        _seed_messages()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1024, "height": 768})
            page = context.new_page()

            page.goto(servers["app"])
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(300)

            page.evaluate(INJECT_JS)
            page.evaluate(PATCH_API_JS)

            page.wait_for_function("typeof openRoom === 'function'", timeout=10000)

            page.evaluate("""
                const slug = 'test-slug';
                const roomId = 'room-test';
                credentials = CredentialStore.getCredentials(slug);
                currentSlug = slug;
                currentRoomId = roomId;
                openRoom(roomId);
            """)

            msg_list = page.locator("#room-message-list")
            msg_list.wait_for(state="visible", timeout=10000)

            page.wait_for_function(
                "document.querySelectorAll('.room-message').length > 0",
                timeout=10000,
            )
            page.wait_for_timeout(400)

            initial_count = page.locator(".room-message").count()
            print(f"\nInitial message count: {initial_count}")
            assert initial_count == PAGE_SIZE

            # Simulate tab hidden
            page.evaluate("""
                Object.defineProperty(document, 'hidden', {
                    configurable: true, get: () => true,
                });
                Object.defineProperty(document, 'visibilityState', {
                    configurable: true, get: () => 'hidden',
                });
                document.dispatchEvent(new Event('visibilitychange'));
            """)
            page.wait_for_timeout(200)

            # New message arrives on the server while hidden
            _append_message("m021", "Hello from the future")
            _append_message("m022", "Another hidden-window message")

            # Simulate tab visible again
            page.evaluate("""
                Object.defineProperty(document, 'hidden', {
                    configurable: true, get: () => false,
                });
                Object.defineProperty(document, 'visibilityState', {
                    configurable: true, get: () => 'visible',
                });
                document.dispatchEvent(new Event('visibilitychange'));
            """)

            # Give the handler a beat to refetch + render
            page.wait_for_timeout(1500)

            # The new messages should now be in the DOM
            body_texts = page.locator(".room-message").all_inner_texts()
            print(f"Post-return (visibilitychange) count: {len(body_texts)}")
            joined = "\n".join(body_texts)
            assert "Hello from the future" in joined, (
                f"New message missing after visibility return. "
                f"Have {len(body_texts)} messages:\n{joined[:500]}"
            )
            assert "Another hidden-window message" in joined, (
                "Second new message missing after visibility return"
            )

            browser.close()

    def test_window_focus_refreshes_even_without_visibility_change(self, servers):
        """
        Desktop-specific scenario: the tab never goes `hidden` (alt-tab
        between apps leaves document.hidden === false in most browsers),
        but the user considers themselves "away." A window focus event
        must still trigger a refresh, otherwise messages that arrived
        during the blurred window never appear.

        Pre-fix: `window.focus` has no handler → DOM stays stale.
        Post-fix: `window.focus` calls refreshOnForeground() → messages appear.
        """
        _seed_messages()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1024, "height": 768})
            page = context.new_page()

            page.goto(servers["app"])
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(300)

            page.evaluate(INJECT_JS)
            page.evaluate(PATCH_API_JS)

            page.wait_for_function("typeof openRoom === 'function'", timeout=10000)

            page.evaluate("""
                const slug = 'test-slug';
                const roomId = 'room-test';
                credentials = CredentialStore.getCredentials(slug);
                currentSlug = slug;
                currentRoomId = roomId;
                openRoom(roomId);
            """)

            page.locator("#room-message-list").wait_for(state="visible", timeout=10000)
            page.wait_for_function(
                "document.querySelectorAll('.room-message').length > 0",
                timeout=10000,
            )
            page.wait_for_timeout(400)

            assert page.locator(".room-message").count() == PAGE_SIZE

            # Note: we do NOT fire visibilitychange here. document.hidden
            # stays false throughout — this is the alt-tab scenario.

            # New messages arrive on the server during the blurred window
            _append_message("m023", "Focus-path message")

            # Fire window.focus — this is what triggers on desktop when
            # the user alt-tabs back to the browser.
            page.evaluate("""
                window.dispatchEvent(new Event('focus'));
            """)

            page.wait_for_timeout(1200)

            body_texts = page.locator(".room-message").all_inner_texts()
            joined = "\n".join(body_texts)
            print(f"Post-focus message count: {len(body_texts)}")
            assert "Focus-path message" in joined, (
                f"window.focus did not trigger refresh; new message missing.\n"
                f"Have {len(body_texts)} messages:\n{joined[:500]}"
            )

            browser.close()
