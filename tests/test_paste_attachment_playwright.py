"""
Playwright test for the large-paste-to-attachment feature.

Verifies that pasting a large (>= 10 KB) block of text into the room message
composer:
  1. Triggers the paste-to-attachment metadata dialog (does NOT insert the
     text inline into the composer).
  2. Pre-fills a file name and a sniffed content-type.
  3. On confirm, produces an attachment chip in the compose preview (NOT a
     giant inline message body), leaving the composer empty.

It also directly exercises the client-side content sniffer.

Test approach mirrors tests/test_reverse_scroll_playwright.py: the app.html
template is rendered with minimal Jinja2 substitution and served via a local
HTTP server, so we drive the real client JS in a real browser without needing
FastAPI/Jinja2 at runtime.

Paste events: a real OS-clipboard paste is unreliable in headless browsers
(clipboard permission prompts, no real clipboard). Instead we dispatch a
synthetic `paste` ClipboardEvent carrying a DataTransfer with >= 10 KB of
text/plain — this drives the exact handler wired at
templates/app.html (room-message-input 'paste' listener).
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

TEST_HTTP_PORT = 19110

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


# Dispatch a synthetic paste of `text` into #room-message-input.
DISPATCH_PASTE_JS = """
    (text) => {
        const el = document.getElementById('room-message-input');
        const dt = new DataTransfer();
        dt.setData('text/plain', text);
        const evt = new ClipboardEvent('paste', {
            clipboardData: dt,
            bubbles: true,
            cancelable: true,
        });
        el.dispatchEvent(evt);
    }
"""


class TestLargePasteToAttachment:
    def _open_composer(self, page):
        # Reveal the room view + compose input; the app hides it behind routing,
        # but the elements exist in the DOM. We show the room view container and
        # the input so the paste handler (attached on DOMContentLoaded) can fire.
        page.evaluate("""
            const view = document.getElementById('view-room');
            if (view) view.classList.remove('hidden');
            const input = document.getElementById('room-message-input');
            if (input) input.focus();
        """)

    def test_large_paste_shows_dialog_and_produces_chip(self, server):
        big_text = "x" * 15000  # 15 KB, well over the 10 KB threshold

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 375, "height": 812})
            page = context.new_page()

            page.goto(server)
            page.wait_for_load_state("networkidle")
            page.wait_for_function("typeof addFileToPreview === 'function'", timeout=10000)
            self._open_composer(page)

            # Sanity: sniffer + threshold constant are wired.
            assert page.evaluate("LARGE_PASTE_THRESHOLD_BYTES") == 10240
            assert page.evaluate("sniffContentType('{\"a\":1}')") == "application/json"
            assert page.evaluate("sniffContentType('# Title\\n\\n- a\\n')") == "text/markdown"
            assert page.evaluate("sniffContentType('<!DOCTYPE html><html></html>')") == "text/html"
            assert page.evaluate("sniffContentType('a,b,c\\n1,2,3\\n')") == "text/csv"
            assert page.evaluate("sniffContentType('plain words here')") == "text/plain"

            # Dispatch the large paste.
            page.evaluate(DISPATCH_PASTE_JS, big_text)

            # The metadata dialog must appear.
            dialog = page.locator("#paste-attach-modal")
            dialog.wait_for(state="visible", timeout=5000)
            assert "hidden" not in (dialog.get_attribute("class") or "")

            # Composer must NOT have received the giant text inline.
            composer_value = page.evaluate("document.getElementById('room-message-input').value")
            assert len(composer_value) < 100, (
                f"Composer should be empty, got {len(composer_value)} chars inline"
            )

            # Name + content-type are pre-filled.
            name_val = page.input_value("#paste-attach-name")
            assert name_val.startswith("pasted-"), name_val
            type_val = page.input_value("#paste-attach-type")
            assert type_val in {
                "text/plain",
                "text/markdown",
                "text/csv",
                "application/json",
                "text/html",
            }

            # Confirm the dialog.
            page.click("#paste-attach-confirm")

            # Dialog closes and an attachment chip appears in the preview.
            dialog.wait_for(state="hidden", timeout=5000)
            page.wait_for_function(
                "document.querySelectorAll('#room-attachment-preview .thumb').length === 1",
                timeout=5000,
            )
            chip_count = page.evaluate(
                "document.querySelectorAll('#room-attachment-preview .thumb').length"
            )
            assert chip_count == 1, f"Expected 1 attachment chip, got {chip_count}"

            # The pending attachment carries the full 15 KB payload (as a file),
            # not an inline body.
            pending_size = page.evaluate("pendingAttachments[0].size")
            assert pending_size == 15000, pending_size

            browser.close()

    def test_small_paste_falls_through_inline(self, server):
        small_text = "just a little text"

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 375, "height": 812})
            page = context.new_page()

            page.goto(server)
            page.wait_for_load_state("networkidle")
            page.wait_for_function("typeof addFileToPreview === 'function'", timeout=10000)
            self._open_composer(page)

            page.evaluate(DISPATCH_PASTE_JS, small_text)
            page.wait_for_timeout(300)

            # No dialog for small pastes.
            dialog = page.locator("#paste-attach-modal")
            assert "hidden" in (dialog.get_attribute("class") or "")
            # No attachment chip either.
            chip_count = page.evaluate(
                "document.querySelectorAll('#room-attachment-preview .thumb').length"
            )
            assert chip_count == 0

            browser.close()
