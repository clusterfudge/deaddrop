"""
Playwright test for jump-to-message from the thread panel.

The panel's jump affordance targets a message that is usually outside the
loaded page, so the reveal has to backfill history first. Verifies, against
the real client JS in a real browser:

  1. Jumping from the search tab to a message outside the loaded page backfills
     history and puts the target inside the message list's box *on the frame the
     highlight starts* — the highlight and the scroll run on separate clocks, so
     a scroll that is still travelling when the animation begins is the bug.
  2. Jumping from the attachments tab does the same, through the same path.
  3. The highlight paints an accent rule plus a tint, in both themes, and
     clears itself afterwards without dropping the target out of view.

Test approach mirrors tests/test_thread_panel_scroll_playwright.py: app.html
is served from the shared static harness and the room-messages, search and
attachments fetches are stubbed in-page, so the messages come from the app's
own render path.
"""

import pytest

from playwright.sync_api import sync_playwright

from tests.test_reply_playwright import start_static_server

pytestmark = pytest.mark.integration


TEST_HTTP_PORT = 19115
BASE_URL = f"http://127.0.0.1:{TEST_HTTP_PORT}"

# Room history deep enough that the jump target needs a backfill page, and
# far enough away that a scroll spanning it is not instantaneous.
TOTAL_MESSAGES = 200
LOADED_MESSAGES = 20
TARGET_INDEX = 5

ARRIVAL_TIMEOUT_MS = 1500


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server(TEST_HTTP_PORT)
    yield BASE_URL
    http_server.shutdown()


SETUP_JS = """
    ({theme, total, loaded, targetIndex}) => {
        document.documentElement.setAttribute('data-theme', theme);
        credentials = {id: 'alice-id', secret: 's', ns: 'test-ns'};
        currentRoomId = 'room-test';
        roomMembers = {'bob-id': {display_name: 'Bob Vance'}};
        document.getElementById('room-chat-title').textContent = 'Shipping Deck';

        window.ALL = [];
        for (let i = 0; i < total; i++) {
            window.ALL.push({
                mid: '0192a000-0000-7000-8000-' + String(i).padStart(12, '0'),
                room_id: 'room-test',
                from_id: 'bob-id',
                body: 'Message number ' + i,
                content_type: 'text/plain',
                reference_mid: null,
                created_at: '2026-08-01T10:00:00Z',
                attachments: [],
            });
        }
        window.TARGET = window.ALL[targetIndex];
        window.TARGET.body = 'the deploy went out at 14:44';

        DeadropAPI.getRoomMessages = async (creds, roomId, opts = {}) => {
            const limit = opts.limit || 20;
            let msgs = window.ALL.slice();
            if (opts.beforeMid) msgs = msgs.filter(m => m.mid < opts.beforeMid).slice(-limit);
            else if (opts.afterMid) msgs = msgs.filter(m => m.mid > opts.afterMid).slice(0, limit);
            else msgs = msgs.slice(-limit);
            return {messages: msgs, room_id: roomId};
        };
        DeadropAPI.searchRoomMessages = async () => ({messages: [window.TARGET], has_more: false});
        DeadropAPI.listRoomAttachments = async () => ({
            attachments: [{
                id: 'att-0', filename: 'deploy.png', content_type: 'image/png',
                size: 2048, from_id: 'bob-id', message_mid: window.TARGET.mid,
                message_created_at: '2026-08-01T10:00:00Z',
            }],
            has_more: false,
        });
        DeadropAPI.getAttachment = async () => ({
            content_type: 'image/png',
            data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mN' +
                  'k+A8AAQUBAScY42YAAAAASUVORK5CYII=',
        });
        DeadropAPI.updateRoomReadCursor = async () => ({});

        roomMessages = window.ALL.slice(-loaded);
        roomHasOlderMessages = true;
        showView('roomChat');
        renderRoomMessages({skipReadCursor: true});

        // The room header sits above the list, so "revealed" means inside the
        // list's own box: a message tucked behind the header satisfies a
        // window-relative check while being invisible.
        window.geometry = (el) => {
            const box = document.getElementById('room-message-list').getBoundingClientRect();
            const r = el.getBoundingClientRect();
            return {
                mid: el.dataset.mid,
                offset: Math.round(r.top - box.top),
                inView: r.top >= box.top && r.bottom <= box.bottom,
            };
        };
        // animationstart bubbles, so one listener on the list samples the
        // target's geometry at the instant the highlight begins.
        window.FLASH_AT_START = null;
        document.getElementById('room-message-list').addEventListener('animationstart', (e) => {
            if (e.animationName !== 'reply-target-flash') return;
            window.FLASH_AT_START = window.geometry(e.target);
        });

        return !!document.querySelector(`[data-mid="${window.TARGET.mid}"]`);
    }
"""

OPEN_SEARCH_JS = """
    () => {
        openThreadPanel();
        showPanelTab('search');
        document.getElementById('panel-search-input').value = 'deploy';
        return runPanelSearch({reset: true});
    }
"""

TARGET_GEOMETRY_JS = """
    () => {
        const el = document.querySelector(`[data-mid="${window.TARGET.mid}"]`);
        return el ? window.geometry(el) : null;
    }
"""

FLASH_CLEARED_JS = """
    () => {
        const el = document.querySelector(`[data-mid="${window.TARGET.mid}"]`);
        return !!el && !el.classList.contains('reply-target-flash');
    }
"""

HIGHLIGHT_JS = """
    () => {
        const el = document.querySelector(`[data-mid="${window.TARGET.mid}"]`);
        const style = getComputedStyle(el);
        return {
            animationName: style.animationName,
            boxShadow: style.boxShadow,
            flashing: el.classList.contains('reply-target-flash'),
        };
    }
"""


def _setup(page, theme="light"):
    page.goto(f"{BASE_URL}/app")
    page.wait_for_function("() => typeof openThreadPanel === 'function'")
    target_in_dom = page.evaluate(
        SETUP_JS,
        {
            "theme": theme,
            "total": TOTAL_MESSAGES,
            "loaded": LOADED_MESSAGES,
            "targetIndex": TARGET_INDEX,
        },
    )
    # The premise: the jump target is outside the loaded page.
    assert target_in_dom is False


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_jump_from_search_reveals_target_while_highlighted(server, theme):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 390, "height": 750})
        try:
            _setup(page, theme)
            page.evaluate(OPEN_SEARCH_JS)
            page.wait_for_selector(".search-result")
            page.click(".search-result")

            page.wait_for_function("() => window.FLASH_AT_START", timeout=ARRIVAL_TIMEOUT_MS)
            at_start = page.evaluate("() => window.FLASH_AT_START")
            assert at_start["mid"] == page.evaluate("() => window.TARGET.mid")
            assert at_start["inView"], at_start

            highlight = page.evaluate(HIGHLIGHT_JS)
            assert highlight["animationName"] == "reply-target-flash"
            # An accent rule and a tint, both inset so neither reflows the row.
            assert highlight["boxShadow"].count("inset") == 2
            assert "rgba(0, 0, 0, 0)" not in highlight["boxShadow"]

            # The panel is gone and the room is back.
            assert page.locator("#view-thread-panel").is_hidden()
            assert page.locator("#view-room-chat").is_visible()

            # The highlight is transient, and the target does not drift out of
            # view while it runs.
            page.wait_for_function(FLASH_CLEARED_JS, timeout=3000)
            assert page.evaluate(TARGET_GEOMETRY_JS)["inView"]
        finally:
            browser.close()


def test_jump_from_attachments_reveals_target_while_highlighted(server):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 390, "height": 750})
        try:
            _setup(page)
            page.evaluate("() => openThreadPanel()")
            page.wait_for_selector(".attachment-tile .attachment-jump")
            page.click(".attachment-tile .attachment-jump")

            page.wait_for_function("() => window.FLASH_AT_START", timeout=ARRIVAL_TIMEOUT_MS)
            at_start = page.evaluate("() => window.FLASH_AT_START")
            assert at_start["mid"] == page.evaluate("() => window.TARGET.mid")
            assert at_start["inView"], at_start
            assert page.evaluate(HIGHLIGHT_JS)["animationName"] == "reply-target-flash"
            assert page.locator("#view-thread-panel").is_hidden()
        finally:
            browser.close()
