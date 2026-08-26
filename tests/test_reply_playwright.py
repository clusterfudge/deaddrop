"""
Playwright test for reply-to-message in the room view.

Verifies, against the real client JS in a real browser:
  1. Every message carries a Reply affordance, and using it shows a compose
     banner naming the target's author with a one-line snippet.
  2. Sending passes the target mid as ``reference_mid`` and clears the banner.
  3. A message with ``reference_mid`` renders a quote block above its body;
     clicking the quote flashes the referenced message.
  4. A reply whose target is not in the loaded page renders as a plain
     message (no empty quote) with its body intact.
  5. A target body containing markup is escaped inside the quote.

Test approach mirrors tests/test_paste_attachment_playwright.py: the app.html
template is rendered with minimal Jinja2 substitution and served via a local
HTTP server, so the real client JS runs in a real browser without needing
FastAPI/Jinja2 at runtime. ``DeadropAPI.sendRoomMessage`` is stubbed in-page to
capture its arguments, so the send assertion needs no API server.

``renderRoomMessages({skipReadCursor: true})`` is used throughout: read-cursor
updates are not under test here and the stub API would not serve them.
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

TEST_HTTP_PORT = 19112

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


def start_static_server():
    server = http.server.HTTPServer(("127.0.0.1", TEST_HTTP_PORT), StaticHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", TEST_HTTP_PORT), timeout=0.2)
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


# Seed the room view: two members, three messages (one of them a reply), and a
# stub sendRoomMessage that records its arguments instead of hitting the API.
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
             from_id: 'bob-id', body: 'Ship it on **Monday** or wait for the audit?',
             content_type: 'text/markdown', created_at: '2026-08-01T10:00:00Z'},
            {mid: '0192a000-0000-7000-8000-000000000002', room_id: 'room-test',
             from_id: 'alice-id', body: 'Monday. The audit is orthogonal.',
             content_type: 'text/markdown',
             reference_mid: '0192a000-0000-7000-8000-000000000001',
             created_at: '2026-08-01T10:01:00Z'},
            {mid: '0192a000-0000-7000-8000-000000000003', room_id: 'room-test',
             from_id: 'bob-id', body: 'Reply to something off-page.',
             content_type: 'text/markdown',
             reference_mid: '0192a000-0000-7000-8000-0000000000ff',
             created_at: '2026-08-01T10:02:00Z'},
        ];
        document.getElementById('view-room-chat').classList.remove('hidden');
        window.__sent = [];
        DeadropAPI.sendRoomMessage = async (creds, roomId, body, ct, refMid, atts) => {
            window.__sent.push({body, content_type: ct, reference_mid: refMid});
            return {mid: '0192a000-0000-7000-8000-00000000000a', room_id: roomId,
                    from_id: creds.id, body, content_type: ct,
                    reference_mid: refMid, created_at: '2026-08-01T10:03:00Z'};
        };
        renderRoomMessages({skipReadCursor: true});
    }
"""

TARGET_MID = "0192a000-0000-7000-8000-000000000001"
REPLY_MID = "0192a000-0000-7000-8000-000000000002"
ORPHAN_REPLY_MID = "0192a000-0000-7000-8000-000000000003"


@pytest.fixture
def page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 375, "height": 812})
        pg = context.new_page()
        pg.goto(server)
        pg.wait_for_load_state("networkidle")
        pg.wait_for_function("typeof startReply === 'function'", timeout=10000)
        pg.evaluate(SETUP_ROOM_JS)
        yield pg
        browser.close()


class TestReplyToMessage:
    def test_reply_affordance_opens_compose_banner(self, page):
        """Each message offers Reply; using it names the target in the banner."""
        assert page.locator(".room-message .reaction-badge.reply-action").count() == 3

        assert page.locator("#room-reply-preview.hidden").count() == 1
        page.evaluate(f"startReply('{TARGET_MID}')")

        banner = page.locator("#room-reply-preview")
        assert "hidden" not in (banner.get_attribute("class") or "")
        assert "Replying to Bob" in banner.inner_text()
        assert "Ship it on Monday" in banner.inner_text()

        # The composer takes focus so the user can type immediately.
        assert page.evaluate("document.activeElement.id") == "room-message-input"

        # Cancel clears the banner and the pending target.
        page.click(".reply-preview-cancel")
        assert page.evaluate("replyTarget") is None
        assert "hidden" in (banner.get_attribute("class") or "")

    def test_send_passes_reference_mid_and_clears_banner(self, page):
        """The reply travels as an ordinary message carrying reference_mid."""
        page.evaluate(f"startReply('{TARGET_MID}')")
        page.fill("#room-message-input", "Monday, then.")
        page.click("#room-send-btn")
        page.wait_for_function("window.__sent.length === 1", timeout=5000)

        sent = page.evaluate("window.__sent[0]")
        assert sent["body"] == "Monday, then."
        assert sent["reference_mid"] == TARGET_MID
        # Not a new content_type: readers that ignore reference_mid still get
        # a normally-rendered message.
        assert sent["content_type"] == "text/markdown"

        assert page.evaluate("replyTarget") is None
        assert "hidden" in (page.locator("#room-reply-preview").get_attribute("class") or "")

    def test_reply_renders_quote_block_and_scrolls_to_target(self, page):
        """The quote shows the target's author + snippet; clicking flashes it."""
        reply = page.locator(f'.room-message[data-mid="{REPLY_MID}"]')
        quote = reply.locator(".reply-quote")
        assert quote.count() == 1
        assert quote.locator(".reply-quote-author").inner_text() == "Bob"
        # Inline markdown markers are stripped, not shown literally.
        assert "Ship it on Monday or wait" in quote.locator(".reply-quote-body").inner_text()

        # The quote sits above the body, and the body is the reply text only.
        assert "Monday. The audit is orthogonal." in reply.locator(".message-body").inner_text()
        assert page.evaluate(
            f"""() => {{
                const el = document.querySelector('.room-message[data-mid="{REPLY_MID}"]');
                return el.querySelector('.reply-quote').compareDocumentPosition(
                    el.querySelector('.message-body')) & Node.DOCUMENT_POSITION_FOLLOWING;
            }}"""
        )

        quote.click()
        assert (
            page.locator(f'.room-message[data-mid="{TARGET_MID}"].reply-target-flash').count() == 1
        )

    def test_snippet_is_one_line_and_truncated(self, page):
        """Snippets collapse newlines, strip markdown chrome, and cap length."""
        assert page.evaluate("replySnippet({body: 'a\\n\\nb   c'})") == "a b c"
        assert page.evaluate("replySnippet({body: '[docs](http://x/y)'})") == "docs"
        assert (
            page.evaluate("replySnippet({body: '', attachments: [{id: 'x'}]})") == "📎 Attachment"
        )
        long_snippet = page.evaluate("replySnippet({body: 'z'.repeat(200)})")
        assert len(long_snippet) == 80 and long_snippet.endswith("\u2026")

    def test_unresolvable_reference_renders_plain_message(self, page):
        """A reply whose target is off-page degrades to a plain message."""
        orphan = page.locator(f'.room-message[data-mid="{ORPHAN_REPLY_MID}"]')
        assert orphan.locator(".reply-quote").count() == 0
        assert "Reply to something off-page." in orphan.locator(".message-body").inner_text()

    def test_quote_escapes_markup_in_target_body(self, page):
        """A target body carrying markup is escaped, not injected, in the quote."""
        page.evaluate("""() => {
            roomMessages[0].body = '<img src=x onerror="window.__pwned=1">hi';
            renderRoomMessages({skipReadCursor: true});
        }""")
        page.wait_for_timeout(300)
        quote_body = page.locator(f'.room-message[data-mid="{REPLY_MID}"] .reply-quote-body')
        assert "<img" in quote_body.inner_text()
        assert page.evaluate("document.querySelector('.reply-quote-body img') === null")
        assert page.evaluate("window.__pwned || 0") == 0
