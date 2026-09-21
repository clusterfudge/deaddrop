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

from deadrop.api import _app_version

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
        # Jinja globals, substituted so the fixture carries values rather than
        # template literals: asset_v lands inside asset URLs, app_version
        # inside the app-version meta tag the shell reads at runtime.
        .replace("{{ asset_v }}", "test")
        .replace("{{ app_version }}", _app_version())
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
FORM_MID = "0192a000-0000-7000-8000-000000000004"
BROKEN_FORM_MID = "0192a000-0000-7000-8000-000000000005"
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
        window.__form = {
            title: 'Ship checklist',
            questions: [
                {qid: 'q-when', prompt: 'Deploy when?',
                 options: [{id: 'tonight', label: 'Tonight'},
                           {id: 'monday', label: 'Monday morning'}]},
                {qid: 'q-who', prompt: 'Who reviews?', multi: true,
                 options: [{id: 'sean', label: 'Sean'}, {id: 'fritz', label: 'Fritz'}]},
                {qid: 'q-note', prompt: 'Anything to add?', optional: true,
                 allow_free_text: true, options: [{id: 'no', label: 'Nothing'}]},
            ],
        };
        window.__brokenForm = {
            title: 'Half-built',
            questions: [
                {qid: 'q-ok', prompt: 'A real question', options: [{id: 'y', label: 'Yes'}]},
                {qid: 'q-bad', prompt: 'No options here', options: []},
            ],
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
            {mid: '0192a000-0000-7000-8000-000000000004', room_id: 'room-test',
             from_id: 'bob-id', body: JSON.stringify(window.__form),
             content_type: 'application/x-question',
             created_at: '2026-08-01T10:03:00Z'},
            {mid: '0192a000-0000-7000-8000-000000000005', room_id: 'room-test',
             from_id: 'bob-id', body: JSON.stringify(window.__brokenForm),
             content_type: 'application/x-question',
             created_at: '2026-08-01T10:04:00Z'},
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


def _form(page):
    return _card(page, FORM_MID)


def _next(page):
    _form(page).locator(".question-wizard-next").click()


def _back(page):
    _form(page).locator(".question-wizard-prev").click()


def _shown_qid(page):
    return _form(page).locator(".question-item").get_attribute("data-qid")


def _tap_targets_under_44px(page, mid):
    """Every tappable control in a card, measured; returns the ones too small."""
    return page.evaluate(
        """(mid) => {
            const card = document.querySelector(
                '.room-message[data-mid="' + mid + '"] .question-card');
            const bad = [];
            card.querySelectorAll('button, input').forEach(el => {
                const r = el.getBoundingClientRect();
                if (r.height < 44 || r.width < 44) {
                    bad.push({cls: el.className, w: r.width, h: r.height});
                }
            });
            return bad;
        }""",
        mid,
    )


def _stage_all(page):
    """Answer every question, paging through the wizard. Ends on review."""
    _form(page).locator('.question-item[data-qid="q-when"] [data-option-id="monday"]').click()
    _next(page)
    _form(page).locator('.question-item[data-qid="q-who"] [data-option-id="sean"]').click()
    _form(page).locator('.question-item[data-qid="q-who"] [data-option-id="fritz"]').click()
    _next(page)
    _form(page).locator('.question-item[data-qid="q-note"] .question-free-input').fill(
        "watch the queue"
    )
    _next(page)


class TestFormRendering:
    def test_form_renders_one_question_at_a_time_with_arrow_nav(self, page):
        form = _form(page)
        assert form.count() == 1
        assert "question-form" in (form.get_attribute("class") or "")
        assert "question-wizard" in (form.get_attribute("class") or "")
        assert form.locator(".question-title").inner_text() == "Ship checklist"
        # One card, one question. The rest of the stack is behind the arrows.
        assert form.locator(".question-item").count() == 1
        assert _shown_qid(page) == "q-when"
        assert form.locator(".question-prompt").inner_text() == "Deploy when?"
        assert form.locator(".question-wizard-nav").count() == 1
        # Submit belongs to the review step, not to a question step.
        assert form.locator(".question-form-submit").count() == 0
        # No per-question send button: the form submits once.
        assert form.locator(".question-multi-send").count() == 0

    def test_progress_names_the_step_and_required_items_are_marked(self, page):
        form = _form(page)
        assert form.locator(".question-form-progress").inner_text() == "Question 1 of 3"
        assert form.locator(".question-item.unanswered").count() == 1

        _next(page)
        assert _form(page).locator(".question-form-progress").inner_text() == "Question 2 of 3"

        _next(page)
        form = _form(page)
        assert form.locator(".question-form-progress").inner_text() == "Question 3 of 3"
        # The optional question is not an open slot.
        assert form.locator(".question-item.unanswered").count() == 0
        assert "OPTIONAL" in form.locator('.question-item[data-qid="q-note"]').inner_text()

    def test_every_tappable_control_clears_44px_on_every_step(self, page):
        """Sean answers these with a thumb at 390px: measure the boxes, on
        each step including review, rather than eyeballing a screenshot."""
        assert page.viewport_size == {"width": 390, "height": 844}
        for expected in ("Question 1 of 3", "Question 2 of 3", "Question 3 of 3"):
            assert expected in _form(page).locator(".question-form-progress").inner_text()
            assert _tap_targets_under_44px(page, FORM_MID) == []
            _next(page)
        # The review step's Submit and its jump-back lines are targets too.
        assert "Review" in _form(page).locator(".question-form-progress").inner_text()
        assert _form(page).locator(".question-form-submit").count() == 1
        assert _form(page).locator(".question-review-line").count() == 3
        assert _tap_targets_under_44px(page, FORM_MID) == []

    def test_tap_targets_hold_up_in_landscape(self, page):
        page.set_viewport_size({"width": 844, "height": 390})
        page.wait_for_timeout(100)
        assert _tap_targets_under_44px(page, FORM_MID) == []
        _next(page)
        assert _tap_targets_under_44px(page, FORM_MID) == []

    def test_nav_sits_at_the_foot_of_the_card(self, page):
        """Thumb zone: the arrows are the last thing in the card, below the
        options, not stranded above them."""
        assert (
            page.eval_on_selector(
                f'.room-message[data-mid="{FORM_MID}"] .question-card',
                "c => c.lastElementChild.className",
            )
            == "question-wizard-nav"
        )
        boxes = page.evaluate(
            f"""() => {{
                const card = document.querySelector(
                    '.room-message[data-mid="{FORM_MID}"] .question-card');
                const opts = [...card.querySelectorAll('.question-option')];
                const nav = card.querySelector('.question-wizard-nav');
                return {{
                    lastOption: Math.max(...opts.map(o => o.getBoundingClientRect().bottom)),
                    navTop: nav.getBoundingClientRect().top,
                }};
            }}"""
        )
        assert boxes["navTop"] >= boxes["lastOption"]

    def test_a_form_with_one_malformed_question_degrades_to_text(self, page):
        """Dropping the bad entry would leave a watcher waiting on a qid that
        was never rendered, so the whole payload falls back."""
        msg = page.locator(f'.room-message[data-mid="{BROKEN_FORM_MID}"]')
        assert msg.locator(".question-card").count() == 0
        body = msg.locator(".message-body").inner_text()
        assert "Half-built" in body and "A real question" in body
        assert "{" not in body and "qid" not in body


class TestFormStaging:
    def test_tapping_stages_without_posting(self, page):
        _form(page).locator('.question-item[data-qid="q-when"] [data-option-id="monday"]').click()
        form = _form(page)
        assert page.evaluate("window.__sent.length") == 0
        assert "staged" in (
            form.locator(
                '.question-item[data-qid="q-when"] [data-option-id="monday"]'
            ).get_attribute("class")
            or ""
        )
        assert "unanswered" not in (
            form.locator('.question-item[data-qid="q-when"]').get_attribute("class") or ""
        )

    def test_single_select_question_in_a_form_replaces_its_choice(self, page):
        _form(page).locator('.question-item[data-qid="q-when"] [data-option-id="monday"]').click()
        _form(page).locator('.question-item[data-qid="q-when"] [data-option-id="tonight"]').click()
        form = _form(page)
        item = form.locator('.question-item[data-qid="q-when"]')
        assert "staged" in (item.locator('[data-option-id="tonight"]').get_attribute("class") or "")
        assert "staged" not in (
            item.locator('[data-option-id="monday"]').get_attribute("class") or ""
        )
        assert form.locator(".question-item").count() == 1

    def test_multi_question_in_a_form_toggles(self, page):
        who = '.question-item[data-qid="q-who"]'
        _next(page)
        _form(page).locator(f'{who} [data-option-id="sean"]').click()
        _form(page).locator(f'{who} [data-option-id="fritz"]').click()
        assert _form(page).locator(f"{who} .question-option.staged").count() == 2
        _form(page).locator(f'{who} [data-option-id="sean"]').click()
        assert _form(page).locator(f"{who} .question-option.staged").count() == 1

    def test_free_text_stages_and_keeps_focus(self, page):
        _next(page)
        _next(page)
        inp = _form(page).locator('.question-item[data-qid="q-note"] .question-free-input')
        inp.click()
        inp.type("watch the queue")
        assert page.evaluate("document.activeElement.className") == "question-free-input"
        assert _form(page).locator(".question-form-progress").inner_text() == "Question 3 of 3"
        assert page.evaluate("window.__sent.length") == 0

    def test_staged_state_survives_a_reload(self, page):
        """Sean's ask: choose now, lock the phone, come back to the choices."""
        _stage_all(page)
        assert (
            _form(page).locator(".question-form-progress").inner_text()
            == "Review \u00b7 3 of 3 chosen"
        )

        page.reload()
        page.wait_for_load_state("networkidle")
        page.wait_for_function("typeof submitQuestionForm === 'function'", timeout=10000)
        page.evaluate(SETUP_ROOM_JS)

        # The step is page state and resets to the first question; the staged
        # answers are persisted and are all still there.
        form = _form(page)
        assert form.locator(".question-form-progress").inner_text() == "Question 1 of 3"
        assert "staged" in (
            form.locator(
                '.question-item[data-qid="q-when"] [data-option-id="monday"]'
            ).get_attribute("class")
            or ""
        )
        _next(page)
        assert _form(page).locator(".question-option.staged").count() == 2
        _next(page)
        assert _form(page).locator(".question-free-input").input_value() == "watch the queue"
        _next(page)
        assert _form(page).locator(".question-form-submit").is_enabled()


class TestFormWizardNav:
    def test_next_and_back_walk_the_stack(self, page):
        assert _shown_qid(page) == "q-when"
        _next(page)
        assert _shown_qid(page) == "q-who"
        assert _form(page).locator(".question-prompt").inner_text() == "Who reviews?"
        _next(page)
        assert _shown_qid(page) == "q-note"
        _back(page)
        assert _shown_qid(page) == "q-who"
        _back(page)
        assert _shown_qid(page) == "q-when"

    def test_back_is_disabled_on_the_first_question(self, page):
        assert _form(page).locator(".question-wizard-prev").is_disabled()
        _next(page)
        assert _form(page).locator(".question-wizard-prev").is_enabled()

    def test_next_is_not_gated_on_answering(self, page):
        """The gate is Submit: a question can be paged past and answered on
        the way back."""
        assert _form(page).locator(".question-wizard-next").is_enabled()
        _next(page)
        assert _shown_qid(page) == "q-who"
        assert page.evaluate("window.__sent.length") == 0

    def test_a_staged_choice_is_still_there_when_you_navigate_back(self, page):
        _form(page).locator('.question-item[data-qid="q-when"] [data-option-id="monday"]').click()
        _next(page)
        _form(page).locator('.question-item[data-qid="q-who"] [data-option-id="fritz"]').click()
        _back(page)

        item = _form(page).locator('.question-item[data-qid="q-when"]')
        assert "staged" in (item.locator('[data-option-id="monday"]').get_attribute("class") or "")
        assert item.locator('[data-option-id="monday"]').get_attribute("aria-pressed") == "true"
        assert "unanswered" not in (item.get_attribute("class") or "")
        # Forward again and the other question's choice survived too.
        _next(page)
        assert "staged" in (
            _form(page)
            .locator('.question-item[data-qid="q-who"] [data-option-id="fritz"]')
            .get_attribute("class")
            or ""
        )
        assert page.evaluate("window.__sent.length") == 0

    def test_typed_free_text_is_still_there_when_you_navigate_back(self, page):
        _next(page)
        _next(page)
        _form(page).locator(".question-free-input").fill("watch the queue")
        _back(page)
        assert _shown_qid(page) == "q-who"
        _next(page)
        assert _form(page).locator(".question-free-input").input_value() == "watch the queue"

    def test_review_is_the_step_after_the_last_question(self, page):
        assert _form(page).locator(".question-wizard-next").inner_text() == "Next \u203a"
        _next(page)
        _next(page)
        assert _form(page).locator(".question-wizard-next").inner_text() == "Review \u203a"
        _next(page)

        form = _form(page)
        assert form.locator(".question-item").count() == 0
        assert form.locator(".question-review-line").count() == 3
        assert form.locator(".question-form-submit").count() == 1
        assert form.locator(".question-wizard-next").count() == 0
        # Back out of review and you land on the last question.
        _back(page)
        assert _shown_qid(page) == "q-note"

    def test_a_review_line_jumps_back_to_its_question(self, page):
        _next(page)
        _next(page)
        _next(page)
        _form(page).locator('.question-review-line[data-qid="q-who"]').click()
        assert _shown_qid(page) == "q-who"
        assert _form(page).locator(".question-form-progress").inner_text() == "Question 2 of 3"


class TestFormReviewAndSubmit:
    def test_submit_is_gated_on_every_required_question(self, page):
        for _ in range(3):
            _next(page)
        submit = _form(page).locator(".question-form-submit")
        assert submit.is_disabled()
        assert submit.inner_text() == "2 left to choose"

        _form(page).locator('.question-review-line[data-qid="q-when"]').click()
        _form(page).locator('[data-option-id="monday"]').click()
        for _ in range(3):
            _next(page)
        assert _form(page).locator(".question-form-submit").inner_text() == "1 left to choose"
        assert _form(page).locator(".question-form-submit").is_disabled()

        _form(page).locator('.question-review-line[data-qid="q-who"]').click()
        _form(page).locator('[data-option-id="sean"]').click()
        _next(page)
        _next(page)
        submit = _form(page).locator(".question-form-submit")
        assert submit.is_enabled()
        # The optional question is still unanswered, and that is allowed.
        assert submit.inner_text() == "Submit 2 answers"

    def test_review_pane_lists_each_prompt_and_its_choice(self, page):
        _form(page).locator('.question-item[data-qid="q-when"] [data-option-id="monday"]').click()
        _next(page)
        _form(page).locator('.question-item[data-qid="q-who"] [data-option-id="sean"]').click()
        _form(page).locator('.question-item[data-qid="q-who"] [data-option-id="fritz"]').click()
        _next(page)
        _next(page)

        lines = _form(page).locator(".question-review-line")
        assert lines.count() == 3
        assert lines.nth(0).locator(".question-review-prompt").inner_text() == "Deploy when?"
        assert lines.nth(0).locator(".question-review-answer").inner_text() == "Monday morning"
        assert lines.nth(1).locator(".question-review-answer").inner_text() == "Sean, Fritz"
        # Unanswered and optional reads as skipped, not as a hole.
        assert lines.nth(2).locator(".question-review-answer").inner_text() == "Skipped"
        assert "missing" in (
            lines.nth(2).locator(".question-review-answer").get_attribute("class") or ""
        )

    def test_submit_posts_one_reply_with_a_machine_line_per_question(self, page):
        _stage_all(page)
        _form(page).locator(".question-form-submit").click()
        page.wait_for_function("window.__sent.length === 1", timeout=5000)

        sent = page.evaluate("window.__sent[0]")
        assert sent["content_type"] == "text/markdown"
        assert sent["reference_mid"] == FORM_MID
        assert sent["body"] == (
            "\u25b8 Deploy when? \u2014 Monday morning\n"
            "\u25b8 Who reviews? \u2014 Sean, Fritz\n"
            "\u25b8 Anything to add? \u2014 watch the queue\n"
            "answer:q-when:monday\n"
            "answer:q-who:sean,fritz\n"
            "answer:q-note:_free"
        )

    def test_double_tap_on_submit_posts_once(self, page):
        _stage_all(page)
        submit = _form(page).locator(".question-form-submit")
        submit.dispatch_event("click")
        submit.dispatch_event("click")
        page.wait_for_timeout(400)
        assert page.evaluate("window.__sent.length") == 1

    def test_submitted_form_locks_and_shows_each_choice(self, page):
        _stage_all(page)
        _form(page).locator(".question-form-submit").click()
        page.wait_for_function(f"roomMessages.some(m => m.mid === '{ANSWER_MID}')", timeout=5000)
        page.wait_for_timeout(200)

        # An answered form is a read-back, not something to navigate: every
        # question flat, no wizard.
        form = _form(page)
        assert "answered" in (form.get_attribute("class") or "")
        assert "question-wizard" not in (form.get_attribute("class") or "")
        assert form.locator(".question-item").count() == 3
        assert form.locator(".question-wizard-nav").count() == 0
        assert form.locator(".question-form-submit").count() == 0
        assert form.locator(".question-form-progress").count() == 0
        assert form.locator(".question-free-text").count() == 0
        assert page.evaluate(
            f"""[...document.querySelectorAll(
                '.room-message[data-mid="{FORM_MID}"] .question-option')
            ].every(b => b.disabled)"""
        )
        # Every machine line locks its own question, chosen options outlined.
        item = form.locator('.question-item[data-qid="q-who"]')
        assert item.locator(".question-option.chosen").count() == 2
        assert (
            form.locator('.question-item[data-qid="q-when"] [data-option-id="monday"]')
            .locator(".question-option-who")
            .inner_text()
            == "You"
        )
        assert "dimmed" in (
            form.locator(
                '.question-item[data-qid="q-when"] [data-option-id="tonight"]'
            ).get_attribute("class")
            or ""
        )
        answers = form.locator(".question-item-answer").all_inner_texts()
        assert answers == ["Monday morning", "Sean, Fritz", "watch the queue"]
        assert "Answered by You" in form.locator(".question-answered-by").inner_text()

    def test_submit_clears_the_staged_state(self, page):
        _stage_all(page)
        _form(page).locator(".question-form-submit").click()
        page.wait_for_function(f"roomMessages.some(m => m.mid === '{ANSWER_MID}')", timeout=5000)
        assert (
            page.evaluate(
                f"Object.keys(localStorage).filter(k => k.startsWith('ddq:{FORM_MID}:')).length"
            )
            == 0
        )

    def test_another_members_form_answer_is_attributed(self, page):
        page.evaluate(
            """() => {
            roomMessages.push({
                mid: '0192a000-0000-7000-8000-0000000000dd', room_id: 'room-test',
                from_id: 'bob-id', content_type: 'text/markdown',
                reference_mid: '0192a000-0000-7000-8000-000000000004',
                body: '\\u25b8 Deploy when? \\u2014 Tonight\\nanswer:q-when:tonight',
                created_at: '2026-08-01T10:09:00Z'});
            renderRoomMessages({skipReadCursor: true});
        }"""
        )
        form = _form(page)
        assert (
            form.locator('.question-item[data-qid="q-when"] [data-option-id="tonight"]')
            .locator(".question-option-who")
            .inner_text()
            == "Bob"
        )
        assert "Answered by Bob" in form.locator(".question-answered-by").inner_text()
        # Bob's answer does not lock the form for me: my wizard is still live.
        assert "question-wizard" in (form.get_attribute("class") or "")
        assert form.locator(".question-wizard-nav").count() == 1

    def test_form_quote_uses_the_title(self, page):
        _stage_all(page)
        _form(page).locator(".question-form-submit").click()
        page.wait_for_function(f"roomMessages.some(m => m.mid === '{ANSWER_MID}')", timeout=5000)
        page.wait_for_timeout(200)
        quote = page.locator(f'.room-message[data-mid="{ANSWER_MID}"] .reply-quote-body')
        assert "Ship checklist" in quote.inner_text()
        assert "{" not in quote.inner_text()
