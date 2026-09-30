"""
Playwright test for the accessible names of the room-view controls.

Assertions go through ``get_by_role(name=...)``, which resolves against the
browser's computed accessible name rather than the DOM attribute. A control
whose contents are a glyph computes to that glyph unless an ``aria-label``
overrides it, and ``title`` does not participate when contents are present —
so attribute-presence assertions would not establish the property under test.

Covered: the back link, refresh, attach, and send controls in the room header
and composer, plus the reaction badge, add-reaction, and reaction-picker
controls rendered by ``renderReactionBadges`` / ``showReactionPicker``.

Harness mirrors tests/test_reply_playwright.py: app.html is rendered with
minimal Jinja2 substitution and served from a local HTTP server, so the real
client JS runs in a real browser with no FastAPI/Jinja2 at runtime.
"""

import http.server
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

TEST_HTTP_PORT = 19120

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
        .replace("{{ ROOM_PAGE_SIZE }}", "20")
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


def start_static_server(port: int = TEST_HTTP_PORT):
    server = http.server.HTTPServer(("127.0.0.1", port), StaticHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return server


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server()
    yield f"http://127.0.0.1:{TEST_HTTP_PORT}"
    http_server.shutdown()


TARGET_MID = "0192a000-0000-7000-8000-000000000001"

# Seed the room view with one message and one 👀 reaction on it, so a reaction
# badge and an add-reaction control both render.
SETUP_ROOM_JS = """
    () => {
        credentials = {id: 'alice-id', secret: 'alice-secret', ns: 'test-ns'};
        currentRoomId = 'room-test';
        roomMembers = {
            'alice-id': {display_name: 'Alice'},
            'bob-id': {display_name: 'Bob'},
        };
        roomHasOlderMessages = false;
        roomMessages = [
            {mid: '0192a000-0000-7000-8000-000000000001', room_id: 'room-test',
             from_id: 'bob-id', body: 'Audit the labels.',
             content_type: 'text/markdown', created_at: '2026-08-01T10:00:00Z'},
            {mid: '0192a000-0000-7000-8000-000000000002', room_id: 'room-test',
             from_id: 'alice-id', body: '\\u{1F440}', content_type: 'reaction',
             reference_mid: '0192a000-0000-7000-8000-000000000001',
             created_at: '2026-08-01T10:01:00Z'},
        ];
        document.getElementById('view-room-chat').classList.remove('hidden');
        renderRoomMessages({skipReadCursor: true});
    }
"""


@pytest.fixture
def page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 375, "height": 812})
        pg = context.new_page()
        pg.goto(server)
        pg.wait_for_load_state("networkidle")
        pg.wait_for_function("typeof renderRoomMessages === 'function'", timeout=10000)
        pg.evaluate(SETUP_ROOM_JS)
        yield pg
        browser.close()


class TestRoomControlAccessibleNames:
    @pytest.mark.parametrize(
        "role,name",
        [
            ("link", "Back"),
            ("button", "Refresh messages"),
            ("button", "Attach image"),
            ("button", "Send message"),
        ],
    )
    def test_header_and_composer_controls_are_named(self, page, role, name):
        """Each glyph-bearing room control resolves by its spoken name."""
        assert page.get_by_role(role, name=name, exact=True).count() == 1

    def test_composer_input_is_named(self, page):
        """The composer resolves by name via its placeholder."""
        assert page.get_by_role("textbox", name="Type a message...", exact=True).count() == 1

    def test_reaction_badge_is_named_by_word_not_glyph(self, page):
        """An existing reaction resolves by word and carries its count."""
        assert page.get_by_role("button", name="Eyes reaction, 1", exact=True).count() == 1

    def test_add_reaction_is_named(self, page):
        assert page.get_by_role("button", name="Add reaction", exact=True).count() == 1

    def test_reaction_picker_buttons_are_named_by_word(self, page):
        """Opening the picker exposes one named control per offered reaction."""
        page.evaluate(
            f"showReactionPicker({{stopPropagation(){{}}, target: "
            f"document.querySelector('.add-reaction')}}, '{TARGET_MID}')"
        )
        page.wait_for_selector("#reaction-picker")

        offered = page.evaluate("REACTION_EMOJIS.length")
        picker = page.locator("#reaction-picker .reaction-picker-btn")
        assert picker.count() == offered

        for word in ("Thumbs up", "Heart", "Laugh", "Party", "Eyes", "Thanks"):
            assert page.get_by_role("button", name=f"React with {word}", exact=True).count() == 1
