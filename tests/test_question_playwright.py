"""Playwright test for interactive question cards in the room view.

Verifies, against the real client JS in a real browser:
  1. An ``application/x-question`` message renders a prompt plus one tappable
     button per option; a malformed payload degrades to readable text.
  2. Tapping an option posts an ordinary ``text/markdown`` reply carrying
     ``reference_mid`` and an ``answer:<qid>:<id>`` machine line.
  3. A double-tap posts once.
  4. The answered state is derived from the reply at render time: the chosen
     option is highlighted, the others dimmed, and the answerers are named.
  5. ``multi`` stages a selection and sends it as one reply.
  6. ``allow_free_text`` posts the typed text under the reserved ``_free`` id.
  7. Agent-authored payload fields are escaped, never injected.

Harness mirrors tests/test_reply_playwright.py: app.html is rendered with
minimal Jinja2 substitution and served locally, and
``DeadropAPI.sendRoomMessage`` is stubbed in-page to capture its arguments.
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

TEST_HTTP_PORT = 19118

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


QUESTION_MID = "0192a000-0000-7000-8000-000000000001"
MULTI_MID = "0192a000-0000-7000-8000-000000000002"
BROKEN_MID = "0192a000-0000-7000-8000-000000000003"
ANSWER_MID = "0192a000-0000-7000-8000-00000000000a"

SETUP_ROOM_JS = """
    () => {
        credentials = {id: 'alice-id', secret: 'alice-secret', ns: 'test-ns'};
        currentRoomId = 'room-test';
        roomMembers = {
            'alice-id': {display_name: 'Alice'},
            'bob-id': {display_name: 'Bob'},
        };
        roomHasOlderMessages = false;
        window.__question = {
            qid: 'q-deploy',
            prompt: 'Deploy tonight or Monday?',
            options: [
                {id: 'tonight', label: 'Tonight', description: 'After bedtime'},
                {id: 'monday', label: 'Monday morning'},
            ],
            allow_free_text: true,
            multi: false,
        };
        window.__multi = {
            qid: 'q-review',
            prompt: 'Who should review?',
            options: [
                {id: 'sean', label: 'Sean'},
                {id: 'nobody', label: 'Nobody'},
            ],
            allow_free_text: false,
            multi: true,
        };
        roomMessages = [
            {mid: '0192a000-0000-7000-8000-000000000001', room_id: 'room-test',
             from_id: 'bob-id', body: JSON.stringify(window.__question),
             content_type: 'application/x-question',
             created_at: '2026-08-01T10:00:00Z'},
            {mid: '0192a000-0000-7000-8000-000000000002', room_id: 'room-test',
             from_id: 'bob-id', body: JSON.stringify(window.__multi),
             content_type: 'application/x-question',
             created_at: '2026-08-01T10:01:00Z'},
            {mid: '0192a000-0000-7000-8000-000000000003', room_id: 'room-test',
             from_id: 'bob-id',
             body: JSON.stringify({prompt: 'No options here', options: []}),
             content_type: 'application/x-question',
             created_at: '2026-08-01T10:02:00Z'},
        ];
        document.getElementById('view-room-chat').classList.remove('hidden');
        window.__sent = [];
        DeadropAPI.sendRoomMessage = async (creds, roomId, body, ct, refMid) => {
            window.__sent.push({body, content_type: ct, reference_mid: refMid});
            await new Promise(r => setTimeout(r, 50));
            return {mid: '0192a000-0000-7000-8000-00000000000a', room_id: roomId,
                    from_id: creds.id, body, content_type: ct,
                    reference_mid: refMid, created_at: '2026-08-01T10:03:00Z'};
        };
        renderRoomMessages({skipReadCursor: true});
    }
"""


@pytest.fixture
def page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 390, "height": 844})
        pg = context.new_page()
        pg.goto(server)
        pg.wait_for_load_state("networkidle")
        pg.wait_for_function("typeof answerQuestion === 'function'", timeout=10000)
        pg.evaluate(SETUP_ROOM_JS)
        yield pg
        browser.close()


def _card(page, mid):
    return page.locator(f'.room-message[data-mid="{mid}"] .question-card')


class TestQuestionRendering:
    def test_question_renders_prompt_and_option_buttons(self, page):
        card = _card(page, QUESTION_MID)
        assert card.count() == 1
        assert card.get_attribute("data-qid") == "q-deploy"
        assert card.locator(".question-prompt").inner_text() == "Deploy tonight or Monday?"

        options = card.locator(".question-option")
        assert options.count() == 2
        assert options.nth(0).locator(".question-option-label").inner_text() == "Tonight"
        assert options.nth(0).locator(".question-option-desc").inner_text() == "After bedtime"
        assert options.nth(1).locator(".question-option-label").inner_text() == "Monday morning"

        # The raw JSON never reaches the reader.
        assert "qid" not in card.inner_text()

    def test_option_targets_are_at_least_44px_tall(self, page):
        """Phone-first: the tap target is a thumb, not a cursor."""
        heights = page.eval_on_selector_all(
            f'.room-message[data-mid="{QUESTION_MID}"] .question-option',
            "els => els.map(e => e.getBoundingClientRect().height)",
        )
        assert heights and all(h >= 44 for h in heights), heights

    def test_malformed_payload_degrades_to_text(self, page):
        """No card, no raw JSON — the prompt survives as plain text."""
        msg = page.locator(f'.room-message[data-mid="{BROKEN_MID}"]')
        assert msg.locator(".question-card").count() == 0
        body = msg.locator(".message-body").inner_text()
        assert "No options here" in body
        assert "{" not in body

    def test_payload_fields_are_escaped(self, page):
        page.evaluate("""() => {
            roomMessages[0].body = JSON.stringify({
                qid: 'q-xss', prompt: '<img src=x onerror="window.__pwned=1">pick',
                options: [{id: 'a', label: '<b>bold</b>'}],
            });
            renderRoomMessages({skipReadCursor: true});
        }""")
        card = _card(page, QUESTION_MID)
        assert "<img" in card.locator(".question-prompt").inner_text()
        assert "<b>bold</b>" in card.locator(".question-option-label").inner_text()
        assert page.evaluate("document.querySelector('.question-card img') === null")
        assert page.evaluate("document.querySelector('.question-card b') === null")
        assert page.evaluate("window.__pwned || 0") == 0


class TestAnswering:
    def test_tap_posts_a_plain_reply_with_machine_line(self, page):
        _card(page, QUESTION_MID).locator('.question-option[data-option-id="monday"]').click()
        page.wait_for_function("window.__sent.length === 1", timeout=5000)

        sent = page.evaluate("window.__sent[0]")
        assert sent["content_type"] == "text/markdown"
        assert sent["reference_mid"] == QUESTION_MID
        assert sent["body"] == "\u25b8 Monday morning\nanswer:q-deploy:monday"

    def test_double_tap_posts_once(self, page):
        opt = _card(page, QUESTION_MID).locator('.question-option[data-option-id="tonight"]')
        opt.dispatch_event("click")
        opt.dispatch_event("click")
        page.wait_for_timeout(400)
        assert page.evaluate("window.__sent.length") == 1

    def test_answered_state_is_derived_from_the_reply(self, page):
        _card(page, QUESTION_MID).locator('.question-option[data-option-id="tonight"]').click()
        page.wait_for_function(f"roomMessages.some(m => m.mid === '{ANSWER_MID}')", timeout=5000)
        page.wait_for_timeout(200)

        card = _card(page, QUESTION_MID)
        assert "answered" in (card.get_attribute("class") or "")
        chosen = card.locator('.question-option[data-option-id="tonight"]')
        other = card.locator('.question-option[data-option-id="monday"]')
        assert "chosen" in (chosen.get_attribute("class") or "")
        assert "dimmed" in (other.get_attribute("class") or "")
        # Who answered, on the option and in the footer.
        assert chosen.locator(".question-option-who").inner_text() == "You"
        assert "Answered by You" in card.locator(".question-answered-by").inner_text()
        # Answered means locked, and the free-text row is gone.
        assert page.evaluate(
            f"""[...document.querySelectorAll(
                '.room-message[data-mid="{QUESTION_MID}"] .question-option')
            ].every(b => b.disabled)"""
        )
        assert card.locator(".question-free-text").count() == 0

    def test_another_members_answer_is_attributed(self, page):
        """The answered view is a stream read — any member's reply counts."""
        page.evaluate("""() => {
            roomMessages.push({
                mid: '0192a000-0000-7000-8000-0000000000bb', room_id: 'room-test',
                from_id: 'bob-id', content_type: 'text/markdown',
                reference_mid: '0192a000-0000-7000-8000-000000000001',
                body: '\\u25b8 Monday morning\\nanswer:q-deploy:monday',
                created_at: '2026-08-01T10:05:00Z'});
            renderRoomMessages({skipReadCursor: true});
        }""")
        card = _card(page, QUESTION_MID)
        assert (
            "Bob"
            in card.locator(
                '.question-option[data-option-id="monday"] .question-option-who'
            ).inner_text()
        )
        assert "Answered by Bob" in card.locator(".question-answered-by").inner_text()

    def test_reply_with_a_mismatched_qid_is_not_an_answer(self, page):
        page.evaluate("""() => {
            roomMessages.push({
                mid: '0192a000-0000-7000-8000-0000000000cc', room_id: 'room-test',
                from_id: 'bob-id', content_type: 'text/markdown',
                reference_mid: '0192a000-0000-7000-8000-000000000001',
                body: 'answer:q-other:monday',
                created_at: '2026-08-01T10:06:00Z'});
            renderRoomMessages({skipReadCursor: true});
        }""")
        assert "answered" not in (_card(page, QUESTION_MID).get_attribute("class") or "")


class TestMultiAndFreeText:
    def test_multi_stages_a_selection_then_sends_one_reply(self, page):
        card = _card(page, MULTI_MID)
        send = card.locator(".question-multi-send")
        assert send.is_disabled()

        card.locator('.question-option[data-option-id="sean"]').click()
        card.locator('.question-option[data-option-id="nobody"]').click()
        assert "staged" in (
            _card(page, MULTI_MID)
            .locator('.question-option[data-option-id="sean"]')
            .get_attribute("class")
            or ""
        )
        assert page.evaluate("window.__sent.length") == 0

        _card(page, MULTI_MID).locator(".question-multi-send").click()
        page.wait_for_function("window.__sent.length === 1", timeout=5000)
        assert page.evaluate("window.__sent[0].body") == (
            "\u25b8 Sean\n\u25b8 Nobody\nanswer:q-review:sean,nobody"
        )

    def test_multi_toggle_off_removes_the_staged_option(self, page):
        card = _card(page, MULTI_MID)
        card.locator('.question-option[data-option-id="sean"]').click()
        _card(page, MULTI_MID).locator('.question-option[data-option-id="sean"]').click()
        assert _card(page, MULTI_MID).locator(".question-multi-send").is_disabled()

    def test_free_text_posts_under_the_reserved_id(self, page):
        card = _card(page, QUESTION_MID)
        card.locator(".question-free-input").fill("Wednesday, after the audit")
        card.locator(".question-free-send").click()
        page.wait_for_function("window.__sent.length === 1", timeout=5000)
        assert page.evaluate("window.__sent[0].body") == (
            "\u25b8 Wednesday, after the audit\nanswer:q-deploy:_free"
        )

        page.wait_for_timeout(200)
        assert (
            "Wednesday, after the audit"
            in _card(page, QUESTION_MID).locator(".question-answered-by").inner_text()
        )

    def test_empty_free_text_sends_nothing(self, page):
        card = _card(page, QUESTION_MID)
        card.locator(".question-free-input").fill("   ")
        card.locator(".question-free-send").click()
        page.wait_for_timeout(300)
        assert page.evaluate("window.__sent.length") == 0

    def test_multi_card_has_no_free_text_row(self, page):
        assert _card(page, MULTI_MID).locator(".question-free-text").count() == 0


class TestAnswerQuoting:
    def test_reply_quote_of_a_question_shows_the_prompt_not_json(self, page):
        """An answer quotes its question; the quote is chrome, not a payload."""
        _card(page, QUESTION_MID).locator('.question-option[data-option-id="monday"]').click()
        page.wait_for_function(f"roomMessages.some(m => m.mid === '{ANSWER_MID}')", timeout=5000)
        page.wait_for_timeout(200)

        quote = page.locator(f'.room-message[data-mid="{ANSWER_MID}"] .reply-quote-body')
        text = quote.inner_text()
        assert "Deploy tonight or Monday?" in text
        assert "qid" not in text and "{" not in text
