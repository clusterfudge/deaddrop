"""
Playwright test for the auto-growing message composer.

Verifies that the room composer (#room-message-input):
  1. Renders one line tall when empty.
  2. Grows one line at a time as content wraps, through 4 lines.
  3. Stops growing at 4 lines and switches to internal scrolling.
  4. Shrinks back to one line when the content shrinks, including at phone
     width, where the placeholder wraps to two lines and so must not be used
     as the empty-state measurement.
  5. Keeps the existing send semantics: Enter sends, Shift+Enter inserts a
     newline (and the newline grows the box).

Test approach mirrors tests/test_paste_attachment_playwright.py: the app.html
template is rendered with minimal Jinja2 substitution and served via a local
HTTP server, so the real client JS + CSS run in a real browser without needing
FastAPI/Jinja2 at runtime.
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

TEST_HTTP_PORT = 19111

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
        if path.startswith("/static/") or path == "/sw.js":
            # /sw.js is served from the root so the app's service-worker
            # registration doesn't log a 404 into the console we assert on.
            rel = "sw.js" if path == "/sw.js" else path[len("/static/") :]
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


# Set the composer value and fire the same 'input' event a keystroke would.
SET_VALUE_JS = """
    (text) => {
        const el = document.getElementById('room-message-input');
        el.value = text;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        return {
            height: el.getBoundingClientRect().height,
            overflowY: getComputedStyle(el).overflowY,
        };
    }
"""

MEASURE_JS = """
    () => {
        const el = document.getElementById('room-message-input');
        const cs = getComputedStyle(el);
        return {
            height: el.getBoundingClientRect().height,
            overflowY: cs.overflowY,
            lineHeight: parseFloat(cs.lineHeight),
            tagName: el.tagName,
        };
    }
"""


def _show_room_view(page):
    # The room view is hidden behind client-side routing; reveal it so the
    # composer has a layout box to measure.
    page.evaluate("""
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        document.getElementById('view-room-chat').classList.remove('hidden');
        document.getElementById('room-message-input').focus();
    """)


class TestComposerAutoGrow:
    def test_grows_to_four_lines_then_scrolls_then_shrinks(self, server):
        console_errors = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            # Phone-sized viewport: the app is used from a phone.
            context = browser.new_context(viewport={"width": 375, "height": 812})
            page = context.new_page()
            page.on(
                "console", lambda m: console_errors.append(m.text) if m.type == "error" else None
            )
            page.on("pageerror", lambda e: console_errors.append(str(e)))

            page.goto(server)
            page.wait_for_load_state("networkidle")
            page.wait_for_function("typeof autoGrowComposer === 'function'", timeout=10000)
            _show_room_view(page)

            assert page.evaluate("MAX_COMPOSER_LINES") == 4

            base = page.evaluate(MEASURE_JS)
            assert base["tagName"] == "TEXTAREA"
            line_h = base["lineHeight"]

            # Pristine (never touched) composer is one line tall.
            pristine = base["height"]
            assert abs(pristine - (line_h + 26)) < 2, (pristine, line_h)

            one = page.evaluate(SET_VALUE_JS, "x")
            assert one["overflowY"] == "hidden"
            assert abs(one["height"] - pristine) < 2

            # 2, 3, 4 lines: height grows by ~one line-height per line.
            heights = {1: one["height"]}
            for n in (2, 3, 4):
                m = page.evaluate(SET_VALUE_JS, "\n".join(f"line {i}" for i in range(n)))
                heights[n] = m["height"]
                assert m["overflowY"] == "hidden", f"{n} lines should not scroll yet"

            for n in (2, 3, 4):
                delta = heights[n] - heights[n - 1]
                assert abs(delta - line_h) < 2, (
                    f"{n - 1}->{n} lines grew {delta}px, expected ~{line_h}px"
                )

            # Beyond 4 lines: height is capped and the textarea scrolls.
            for n in (5, 8, 20):
                m = page.evaluate(SET_VALUE_JS, "\n".join(f"line {i}" for i in range(n)))
                assert abs(m["height"] - heights[4]) < 1, (
                    f"{n} lines: height {m['height']}px should stay at the 4-line cap "
                    f"{heights[4]}px"
                )
                assert m["overflowY"] == "auto", f"{n} lines should scroll internally"

            # Content that overflows is reachable by scrolling.
            scrollable = page.evaluate(
                "() => { const el = document.getElementById('room-message-input');"
                " return el.scrollHeight > el.clientHeight; }"
            )
            assert scrollable

            # Shrink back down.
            two_again = page.evaluate(SET_VALUE_JS, "line 0\nline 1")
            assert abs(two_again["height"] - heights[2]) < 1
            one_again = page.evaluate(SET_VALUE_JS, "x")
            assert abs(one_again["height"] - heights[1]) < 1

            # Cleared (as after a send): back to one line. The placeholder wraps
            # to two lines at this width, so a scrollHeight-based empty state
            # would leave the box double-height.
            empty_again = page.evaluate(SET_VALUE_JS, "")
            assert abs(empty_again["height"] - pristine) < 2, (
                f"cleared composer is {empty_again['height']}px, expected one line ({pristine}px)"
            )
            assert empty_again["overflowY"] == "hidden"

            # The composer never pushes past the viewport on a phone.
            assert heights[4] < 200, heights[4]

            browser.close()

        assert console_errors == [], console_errors

    def test_send_semantics_unchanged(self, server):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 375, "height": 812})
            page = context.new_page()

            page.goto(server)
            page.wait_for_load_state("networkidle")
            page.wait_for_function("typeof autoGrowComposer === 'function'", timeout=10000)
            _show_room_view(page)

            # Stub the network-bound send so we can count invocations. Wrapped in
            # an arrow function: Playwright invokes a bare expression that
            # evaluates to a function.
            page.evaluate(
                "() => { window.__sends = 0;"
                " window.sendRoomMessage = () => { window.__sends++; }; }"
            )

            page.click("#room-message-input")
            page.keyboard.type("hello")
            one_line = page.evaluate(MEASURE_JS)["height"]

            # Shift+Enter inserts a newline and grows the box; it must not send.
            page.keyboard.press("Shift+Enter")
            page.keyboard.type("world")
            two_lines = page.evaluate(MEASURE_JS)["height"]
            assert page.evaluate("document.getElementById('room-message-input').value") == (
                "hello\nworld"
            )
            assert page.evaluate("window.__sends") == 0
            assert two_lines > one_line

            # Enter sends and does not insert a newline.
            page.keyboard.press("Enter")
            assert page.evaluate("window.__sends") == 1
            assert page.evaluate("document.getElementById('room-message-input').value") == (
                "hello\nworld"
            )

            browser.close()
