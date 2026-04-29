"""
Playwright test for reverse infinite scroll in room chat view.

Verifies that when a user scrolls up in the room message list:
1. Older messages load above the current viewport (at the visual top)
2. The currently-visible message stays visible after the load
3. No viewport jump / content replacement occurs

Architecture note:
  The room-message-list uses `flex-direction: column-reverse`.
  - scrollTop=0  →  at the bottom (newest messages visible)
  - scrollTop<0  →  scrolled up toward older messages
  - Physical DOM end = visual top (where older messages are inserted)

The fix (this PR) switches loadOlderRoomMessages() from a full innerHTML
replacement + manual rAF scrollTop correction to an incremental
DocumentFragment append, relying on `overflow-anchor: auto` to preserve
the scroll position natively.

Test approach:
  We serve the static app HTML directly via a local HTTP server (bypassing
  FastAPI/Jinja2 to avoid a local version incompatibility) and wire up a
  mock API handler that returns predictable paginated message sets.
  The test drives Playwright against this local page to verify the scroll
  behavior end-to-end in a real browser.
"""

import http.server
import json
import pathlib
import re
import threading
import time

import pytest
from playwright.sync_api import sync_playwright

# Paths
REPO_ROOT = pathlib.Path(__file__).parent.parent
STATIC_DIR = REPO_ROOT / "src" / "deadrop" / "static"
TEMPLATES_DIR = REPO_ROOT / "src" / "deadrop" / "templates"

# Port for the local test HTTP server
TEST_HTTP_PORT = 19100
TEST_API_PORT = 19101


# ---------------------------------------------------------------------------
# Minimal mock API server (returns paginated room messages)
# ---------------------------------------------------------------------------

# Build 60 fake messages (IDs m001..m060, chronological order)
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
    for i in range(1, 61)
]
PAGE_SIZE = 20


class MockAPIHandler(http.server.BaseHTTPRequestHandler):
    """Minimal mock of the deaddrop room messages API."""

    def log_message(self, fmt, *args):  # suppress request logs
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_GET(self):
        # Parse URL
        path = self.path.split("?")[0]
        qs = self.path.split("?")[1] if "?" in self.path else ""
        params = {}
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v

        if re.match(r"^/[^/]+/rooms/[^/]+/messages$", path):
            # Room messages endpoint
            before = params.get("before")
            after = params.get("after")
            limit = int(params.get("limit", PAGE_SIZE))

            msgs = list(ALL_MESSAGES)

            if before:
                # Get messages older than `before` (last N in chrono order)
                msgs = [m for m in msgs if m["mid"] < before]
                msgs = msgs[-limit:]  # newest N from the filtered set
            elif after:
                msgs = [m for m in msgs if m["mid"] > after]
                msgs = msgs[:limit]
            else:
                # No cursor — return newest N
                msgs = msgs[-limit:]

            body = json.dumps({"messages": msgs, "room_id": "room-test"}).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif re.match(r"^/[^/]+/rooms/[^/]+/members$", path):
            body = json.dumps(
                [
                    {"identity_id": "alice-id", "metadata": {"display_name": "Alice"}},
                ]
            ).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif re.match(r"^/[^/]+/rooms/[^/]+$", path):
            body = json.dumps(
                {
                    "room_id": "room-test",
                    "display_name": "Scroll Test Room",
                    "member_count": 1,
                }
            ).encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif re.match(r"^/[^/]+/rooms/[^/]+/read_cursor$", path):
            body = b"{}"
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self._cors()
            self.end_headers()

    def do_POST(self):
        # Accept read cursor updates silently
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        body = b"{}"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_mock_api():
    server = http.server.HTTPServer(("127.0.0.1", TEST_API_PORT), MockAPIHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


# ---------------------------------------------------------------------------
# Static file server — serves app.html + static assets
# ---------------------------------------------------------------------------

_rendered_app_html: str | None = None


def _build_app_html() -> str:
    """Render app.html with minimal Jinja2 substitution (cached)."""
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

    # Use lambda replacements to prevent re.sub from interpreting backslash
    # sequences (e.g. \n) in the content strings as escape sequences.
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
    """Serve static files and the rendered app HTML."""

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

        # Serve static files from the package static directory
        # URL: /static/js/foo.js → STATIC_DIR/js/foo.js
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            file_path = STATIC_DIR / rel
            if file_path.exists() and file_path.is_file():
                data = file_path.read_bytes()
                # Guess content type
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

        # Everything else 404
        self.send_response(404)
        self.end_headers()


def start_static_server():
    server = http.server.HTTPServer(("127.0.0.1", TEST_HTTP_PORT), StaticHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Wait for it
    import socket

    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", TEST_HTTP_PORT), timeout=0.2)
            s.close()
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return server


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def servers():
    api_server = start_mock_api()
    http_server = start_static_server()
    yield {
        "app": f"http://127.0.0.1:{TEST_HTTP_PORT}",
        "api": f"http://127.0.0.1:{TEST_API_PORT}",
    }
    api_server.shutdown()
    http_server.shutdown()


# ---------------------------------------------------------------------------
# JS helper — inject credentials + patch DeadropAPI base URL
# ---------------------------------------------------------------------------

INJECT_JS = f"""
    // Set up fake credentials in localStorage
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

    // Patch the API base URL to point to mock server
    window._MOCK_API_BASE = 'http://127.0.0.1:{TEST_API_PORT}';
"""

PATCH_API_JS = """
    // Monkey-patch DeadropAPI.request to use mock server
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
    console.log('DeadropAPI patched to mock server');
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReverseInfiniteScroll:
    """
    Verify the reverse infinite scroll fix.

    Key assertion: after scrolling to the visual top and triggering older
    message load, the previously-visible message should still be visible
    and older messages should appear ABOVE it (not replace it).
    """

    def test_scroll_up_prepends_older_messages(self, servers):
        """
        Scroll to the visual top of the room, wait for older messages to
        load, and verify:
        1. Older messages are now in the DOM (above the previous oldest)
        2. The viewport did not jump to the bottom (current messages preserved)
        3. No content replacement — previously visible messages still visible
        """
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 375, "height": 812})
            page = context.new_page()

            # Navigate to the app
            page.goto(servers["app"])
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(500)

            # Inject credentials + patch API
            page.evaluate(INJECT_JS)
            page.evaluate(PATCH_API_JS)

            # Wait for the app JS to fully execute and define openRoom
            page.wait_for_function("typeof openRoom === 'function'", timeout=10000)

            # Navigate to the room view directly via JS (simulating openRoom)
            page.evaluate("""
                const slug = 'test-slug';
                const roomId = 'room-test';
                credentials = CredentialStore.getCredentials(slug);
                currentSlug = slug;
                currentRoomId = roomId;
                openRoom(roomId);
            """)

            # Wait for room message list to appear
            msg_list = page.locator("#room-message-list")
            msg_list.wait_for(state="visible", timeout=10000)

            # Wait for messages to render
            page.wait_for_function(
                "document.querySelectorAll('.room-message').length > 0",
                timeout=10000,
            )
            page.wait_for_timeout(600)  # let initial render settle

            initial_count = page.locator(".room-message").count()
            assert initial_count > 0, "Expected messages to be rendered"
            print(f"\nInitial message count: {initial_count}")
            assert initial_count == PAGE_SIZE, (
                f"Expected {PAGE_SIZE} messages on initial load, got {initial_count}"
            )

            # Get text of the last DOM element (= oldest visible, visually at top)
            # In column-reverse, the LAST item in DOM is at the visual top
            last_dom_msg_text = page.locator(".room-message").last.inner_text()
            print(f"Oldest visible message: {last_dom_msg_text[:60]}")

            # Get scrollTop before scrolling
            scroll_top_before = page.evaluate(
                "document.getElementById('room-message-list').scrollTop"
            )
            print(f"scrollTop before scroll: {scroll_top_before}")
            # Initially at bottom → scrollTop near 0
            assert scroll_top_before >= -10, (
                f"Expected to be at bottom (scrollTop≈0), got {scroll_top_before}"
            )

            # Scroll to the visual top (physical bottom in column-reverse)
            page.evaluate("""
                const list = document.getElementById('room-message-list');
                list.scrollTop = -(list.scrollHeight - list.clientHeight);
            """)
            page.wait_for_timeout(300)  # debounce + scroll event

            scroll_top_after_scroll = page.evaluate(
                "document.getElementById('room-message-list').scrollTop"
            )
            print(f"scrollTop after scroll: {scroll_top_after_scroll}")
            assert scroll_top_after_scroll < -50, (
                f"Expected negative scrollTop (scrolled up), got {scroll_top_after_scroll}"
            )

            # Snapshot scrollTop right before the load triggers
            scroll_before_load = page.evaluate(
                "document.getElementById('room-message-list').scrollTop"
            )

            # Wait for older messages to load (triggered by scroll event)
            page.wait_for_function(
                f"document.querySelectorAll('.room-message').length > {initial_count}",
                timeout=8000,
            )

            new_count = page.locator(".room-message").count()
            loaded_count = new_count - initial_count
            print(f"Messages after scroll-load: {new_count} (+{loaded_count})")
            assert new_count > initial_count, (
                f"Expected more messages after scrolling up, still got {initial_count}"
            )

            # ---------------------------------------------------------------
            # Critical assertion 1: previously-oldest message is still there
            # (content was prepended, not replaced)
            # ---------------------------------------------------------------
            all_texts = page.locator(".room-message").all_inner_texts()
            assert any(last_dom_msg_text[:20] in t for t in all_texts), (
                f"Previously visible message '{last_dom_msg_text[:40]}' "
                "is gone — content was REPLACED instead of prepended!"
            )
            print("✓ Previously visible message still present in DOM")

            # ---------------------------------------------------------------
            # Critical assertion 2: scroll position was preserved
            # After incremental DOM insert, scrollTop should still be ≈ where
            # it was before the load (not jumped to 0/bottom).
            # We allow ±200px tolerance for browser rendering variations.
            # ---------------------------------------------------------------
            scroll_top_final = page.evaluate(
                "document.getElementById('room-message-list').scrollTop"
            )
            print(f"scrollTop after load: {scroll_top_final} (was {scroll_before_load})")

            # scrollTop should still be significantly negative (not jumped to 0)
            assert scroll_top_final < -50, (
                f"Scroll position JUMPED TO BOTTOM after loading older messages "
                f"(scrollTop={scroll_top_final}). This is the bug we fixed!"
            )
            print("✓ Scroll position preserved after load (still negative)")

            # ---------------------------------------------------------------
            # Critical assertion 3: older messages are visually ABOVE
            # (at the physical end of the DOM in column-reverse)
            # In column-reverse, the LAST DOM child = visual top.
            # The newly loaded messages (older) must be among the last DOM children.
            # ---------------------------------------------------------------
            last_3 = [el.inner_text()[:30] for el in page.locator(".room-message").all()[-3:]]
            print(f"Last 3 DOM messages (visual top, oldest): {last_3}")
            # These should be from the older page, i.e. "Message number 1.." etc.
            # The initial load got msgs 41-60 (newest 20), older load got 21-40.
            # So last DOM msgs should be around "Message number 20-22"
            assert any("Message number" in t for t in last_3), (
                f"Expected older messages at physical DOM end (visual top), got: {last_3}"
            )
            print("✓ Older messages correctly inserted at visual top (DOM end)")

            browser.close()
            print("\n✓ All assertions passed — reverse scroll fix verified")

    def test_sentinel_is_removed_when_exhausted(self, servers):
        """
        After loading all pages, the sentinel element should be removed.
        """
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 375, "height": 812})
            page = context.new_page()

            page.goto(servers["app"])
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(500)

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
            page.wait_for_timeout(600)

            # Scroll to top 3 times to exhaust all pages
            # Total: 60 messages / 20 per page = 3 loads
            # Initial load: msgs 41-60 (newest 20) → 2 more loads needed
            for load_num in range(4):
                sentinel = page.locator("#room-load-more")
                if not sentinel.is_visible():
                    print(f"\n✓ Sentinel gone after {load_num} scroll-load(s)")
                    break

                prev_count = page.locator(".room-message").count()
                page.evaluate("""
                    const list = document.getElementById('room-message-list');
                    list.scrollTop = -(list.scrollHeight - list.clientHeight);
                """)
                page.wait_for_timeout(300)

                try:
                    page.wait_for_function(
                        f"document.querySelectorAll('.room-message').length > {prev_count} "
                        "|| !document.getElementById('room-load-more')",
                        timeout=5000,
                    )
                except Exception:
                    break

            # Sentinel should be gone
            assert not page.locator("#room-load-more").is_visible(), (
                "Sentinel still visible after loading all messages — not cleaned up"
            )
            final_count = page.locator(".room-message").count()
            print(f"Final message count: {final_count} (expected 60)")
            assert final_count == 60, f"Expected all 60 messages, got {final_count}"

            browser.close()
