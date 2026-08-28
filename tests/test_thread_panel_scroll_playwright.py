"""
Playwright test for vertical scrolling in the thread panel.

``.view`` is ``height: 100vh; overflow: hidden``, so a tall tab body only
reaches its content by being its own scroll region. Verifies, against the real
client JS in a real browser, that a gallery taller than the viewport:

  1. leaves ``.panel-body`` scrollable (scrollHeight > clientHeight with an
     ``auto`` overflow), rather than overflowing into the clipped ``.view``;
  2. responds to a wheel gesture and reaches its own bottom;
  3. keeps the panel header and tab strip at full height while doing so;
  4. does the same on the search tab, which shares the class.

Test approach mirrors tests/test_command_palette_playwright.py: app.html is
served from the shared static harness and the attachments fetch is stubbed
in-page, so the tiles come from the app's own render path.
"""

import pytest

from playwright.sync_api import sync_playwright

from tests.test_reply_playwright import start_static_server

pytestmark = pytest.mark.integration


TEST_HTTP_PORT = 19114
BASE_URL = f"http://127.0.0.1:{TEST_HTTP_PORT}"

# Enough tiles and rows to exceed any test viewport.
TILE_COUNT = 48
SEARCH_HIT_COUNT = 30


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server(TEST_HTTP_PORT)
    yield BASE_URL
    http_server.shutdown()


SETUP_JS = """
    (tileCount) => {
        credentials = {id: 'alice-id', secret: 's', ns: 'test-ns'};
        currentRoomId = 'room-test';
        roomMembers = {'bob-id': {display_name: 'Bob Vance'}};
        document.getElementById('room-chat-title').textContent = 'Shipping Deck';
        showView('roomChat');

        const attachments = [];
        for (let i = 0; i < tileCount; i++) {
            attachments.push({
                id: 'att-' + i,
                filename: 'shot-' + i + '.png',
                content_type: 'image/png',
                size: 24576,
                from_id: 'bob-id',
                message_mid: '0192a000-0000-7000-8000-' + String(i).padStart(12, '0'),
                message_created_at: '2026-08-01T10:00:00Z',
            });
        }
        DeadropAPI.listRoomAttachments = async () => ({attachments, has_more: true});
        // A 1x1 transparent PNG, so thumbnail loading never hits the network.
        DeadropAPI.getAttachment = async () => ({
            content_type: 'image/png',
            data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mN' +
                  'k+A8AAQUBAScY42YAAAAASUVORK5CYII=',
        });

        openThreadPanel();
    }
"""

SEARCH_JS = """
    (hitCount) => {
        const results = [];
        for (let i = 0; i < hitCount; i++) {
            results.push({
                mid: '0192b000-0000-7000-8000-' + String(i).padStart(12, '0'),
                from_id: 'bob-id',
                body: 'the deploy went out at 14:44, hit number ' + i,
                created_at: '2026-08-01T10:00:00Z',
            });
        }
        DeadropAPI.searchRoomMessages = async () => ({messages: results, has_more: false});
        showPanelTab('search');
        document.getElementById('panel-search-input').value = 'deploy';
        return runPanelSearch({reset: true});
    }
"""

PROBE_JS = """
    (id) => {
        const el = document.getElementById(id);
        const style = getComputedStyle(el);
        return {
            overflowY: style.overflowY,
            scrollHeight: el.scrollHeight,
            clientHeight: el.clientHeight,
            scrollTop: el.scrollTop,
        };
    }
"""

CHROME_JS = """
    () => ({
        header: document.querySelector('#view-thread-panel .header').getBoundingClientRect().height,
        tabs: document.querySelector('#view-thread-panel .panel-tabs').getBoundingClientRect().height,
    })
"""


WHEEL_DELTA = 600


def _wheel_to_bottom(page, element_id, width, height):
    """Wheel over the panel far enough to reach the bottom. Returns its probe."""
    start = page.evaluate(PROBE_JS, element_id)
    distance = start["scrollHeight"] - start["clientHeight"]
    page.mouse.move(width // 2, height // 2)
    for _ in range(distance // WHEEL_DELTA + 3):
        page.mouse.wheel(0, WHEEL_DELTA)
        page.wait_for_timeout(30)
    page.wait_for_timeout(300)
    return page.evaluate(PROBE_JS, element_id)


@pytest.mark.parametrize("width,height", [(390, 750), (1100, 800)])
def test_thread_panel_tabs_scroll(server, width, height):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": height})
        try:
            page.goto(f"{server}/app")
            page.wait_for_function("() => typeof openThreadPanel === 'function'")
            page.evaluate(SETUP_JS, TILE_COUNT)
            page.wait_for_selector(f".attachment-tile:nth-child({TILE_COUNT})")

            chrome_before = page.evaluate(CHROME_JS)

            attachments = page.evaluate(PROBE_JS, "panel-body-attachments")
            assert attachments["overflowY"] == "auto"
            assert attachments["scrollHeight"] > attachments["clientHeight"]
            assert attachments["clientHeight"] < height
            assert attachments["scrollTop"] == 0

            scrolled = _wheel_to_bottom(page, "panel-body-attachments", width, height)
            assert scrolled["scrollTop"] > 0
            assert scrolled["scrollTop"] == scrolled["scrollHeight"] - scrolled["clientHeight"]

            # The "Load more" control sits after the grid: unreachable unless
            # the body scrolls.
            more = page.locator("#attachments-more")
            assert more.is_visible()
            assert more.evaluate(
                "el => { const r = el.getBoundingClientRect();"
                " return r.top >= 0 && r.bottom <= window.innerHeight; }"
            )

            # Scrolling the body must not have squeezed the panel chrome.
            assert page.evaluate(CHROME_JS) == chrome_before

            page.evaluate(SEARCH_JS, SEARCH_HIT_COUNT)
            page.wait_for_selector(f".search-result:nth-child({SEARCH_HIT_COUNT})")
            search = _wheel_to_bottom(page, "panel-body-search", width, height)
            assert search["overflowY"] == "auto"
            assert search["scrollTop"] > 0
            assert search["scrollTop"] == search["scrollHeight"] - search["clientHeight"]
        finally:
            browser.close()
