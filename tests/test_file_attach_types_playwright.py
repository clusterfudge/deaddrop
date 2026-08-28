"""
Playwright test for the file-picker attachment path.

Verifies that the composer's file input (#room-file-input):
  1. Offers text, image, audio, video and PDF files, not images only.
  2. Resolves a content type the server will accept when the browser reports
     application/octet-stream for a text file (e.g. debug.log), instead of
     handing the API an opaque binary type that default-deny rejects.

Test approach mirrors tests/test_paste_attachment_playwright.py: the app.html
template is rendered with minimal Jinja2 substitution and served via a local
HTTP server, so the real client JS runs in a real browser.
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

TEST_HTTP_PORT = 19114

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


class TestFileAttachTypes:
    def _open_composer(self, page):
        page.evaluate("""
            const view = document.getElementById('view-room');
            if (view) view.classList.remove('hidden');
        """)

    def test_file_input_accepts_text_and_media(self, server):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{server}/app", wait_until="domcontentloaded")

            accept = page.get_attribute("#room-file-input", "accept")
            for token in ("text/*", "image/*", "audio/*", "video/*", "application/pdf"):
                assert token in accept, f"{token} missing from accept={accept!r}"

            browser.close()

    def test_untyped_text_file_becomes_text_plain(self, server):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{server}/app", wait_until="domcontentloaded")
            self._open_composer(page)

            page.set_input_files(
                "#room-file-input",
                {
                    "name": "debug.log",
                    "mimeType": "application/octet-stream",
                    "buffer": b"2026-08-28 boom\n",
                },
            )
            page.wait_for_function("pendingAttachments.length === 1", timeout=5000)

            att = page.evaluate("pendingAttachments[0]")
            assert att["filename"] == "debug.log"
            assert att["content_type"] == "text/plain"

            browser.close()

    def test_typed_file_keeps_browser_content_type(self, server):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{server}/app", wait_until="domcontentloaded")
            self._open_composer(page)

            page.set_input_files(
                "#room-file-input",
                {
                    "name": "page.html",
                    "mimeType": "text/html",
                    "buffer": b"<html><body>hi</body></html>",
                },
            )
            page.wait_for_function("pendingAttachments.length === 1", timeout=5000)

            att = page.evaluate("pendingAttachments[0]")
            assert att["content_type"] == "text/html"

            browser.close()
