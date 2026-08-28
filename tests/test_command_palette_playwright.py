"""
Playwright test for the command palette and keyboard shortcuts.

Verifies, against the real client JS in a real browser:
  1. Ctrl+K opens the palette; Escape closes it.
  2. Typing fuzzy-filters the action list down to a match.
  3. Enter runs the selected action (opening a room).
  4. ``?`` opens the shortcuts help overlay.
  5. Shortcuts are inert while a composer has focus — except the palette
     hotkey, which still works.
  6. j/k move the selection in the inbox list and Enter opens it.
  7. On a touch device (390x844, coarse pointer) every binding is inert.

Test approach mirrors tests/test_reply_playwright.py: the app.html template is
rendered with minimal Jinja2 substitution and served from a local HTTP server,
so the real client JS runs in a real browser with no FastAPI at runtime. The
three inbox API calls are stubbed in-page, so the palette's action list is
built from the same in-memory state the app itself renders from.
"""

import pytest

from playwright.sync_api import sync_playwright

from tests.test_reply_playwright import start_static_server

pytestmark = pytest.mark.integration


# A port of its own: test_reply_playwright's module-scoped server may still be
# bound to 19112 when this module runs.
TEST_HTTP_PORT = 19113
BASE_URL = f"http://127.0.0.1:{TEST_HTTP_PORT}"


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server(TEST_HTTP_PORT)
    yield BASE_URL
    http_server.shutdown()


# Seed the inbox view through the app's own render path: stub the three API
# calls loadUnifiedInbox() makes, then let it populate `rooms`/`peers` and the
# thread list. openRoom/openConversation are stubbed to record navigation.
SETUP_JS = """
    async () => {
        credentials = {id: 'alice-id', secret: 's', ns: 'test-ns', displayName: 'Alice'};
        currentSlug = 'test-ns';
        DeadropAPI.listPeers = async () => ([
            {id: 'bob-id', metadata: {display_name: 'Bob Vance'}},
            {id: 'carol-id', metadata: {display_name: 'Carol Danvers'}},
        ]);
        DeadropAPI.getInbox = async () => ({messages: [
            {mid: 'm1', from: 'bob-id', to: 'alice-id', body: 'hi',
             created_at: '2026-08-01T10:00:00Z', read_at: null},
        ]});
        DeadropAPI.listRooms = async () => ([
            {room_id: 'room-ship', display_name: 'Shipping Deck', member_count: 3,
             created_at: '2026-08-01T09:00:00Z'},
            {room_id: 'room-cats', display_name: 'Cat Pictures', member_count: 9,
             created_at: '2026-08-01T08:00:00Z'},
        ]);
        window.__nav = [];
        window.openRoom = (id) => { window.__nav.push('room:' + id); };
        window.openConversation = (id) => { window.__nav.push('peer:' + id); };
        showView('inbox');
        await loadUnifiedInbox();
    }
"""


def _new_page(browser, **context_kwargs):
    context = browser.new_context(**context_kwargs)
    page = context.new_page()
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")
    page.wait_for_function("typeof DeadropPalette !== 'undefined'", timeout=10000)
    page.evaluate(SETUP_JS)
    return page


@pytest.fixture
def page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield _new_page(browser, viewport={"width": 1280, "height": 800})
        browser.close()


@pytest.fixture
def mobile_page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield _new_page(
            browser,
            viewport={"width": 390, "height": 844},
            has_touch=True,
            is_mobile=True,
        )
        browser.close()


def _labels(page):
    return page.eval_on_selector_all(
        "#palette-results .palette-item .palette-label", "els => els.map(e => e.innerText)"
    )


class TestCommandPalette:
    def test_ctrl_k_opens_and_escape_closes(self, page):
        """The palette opens on the hotkey, focused and populated."""
        assert page.locator("#command-palette.hidden").count() == 1

        page.keyboard.press("Control+k")
        assert page.locator("#command-palette.hidden").count() == 0
        assert page.evaluate("document.activeElement.id") == "palette-input"

        # Rooms and people come from the state the inbox already loaded.
        labels = _labels(page)
        assert "Shipping Deck" in labels
        assert "Bob Vance" in labels
        assert "Toggle theme" in labels

        page.keyboard.press("Escape")
        assert page.locator("#command-palette.hidden").count() == 1

    def test_typing_fuzzy_filters(self, page):
        """A non-contiguous query narrows the list to its subsequence matches."""
        page.keyboard.press("Control+k")
        before = len(_labels(page))
        page.fill("#palette-input", "shpdk")
        page.wait_for_timeout(100)

        labels = _labels(page)
        assert labels[0] == "Shipping Deck"
        assert len(labels) < before
        assert "Cat Pictures" not in labels

        # Matched characters are marked for the reader.
        assert page.locator("#palette-results .palette-item mark").count() >= 5

    def test_enter_opens_selected_room(self, page):
        """Enter runs the highlighted action and closes the palette."""
        page.keyboard.press("Control+k")
        page.fill("#palette-input", "cat pic")
        page.wait_for_timeout(100)
        page.keyboard.press("Enter")

        assert page.evaluate("window.__nav") == ["room:room-cats"]
        assert page.locator("#command-palette.hidden").count() == 1

    def test_arrows_move_the_palette_cursor(self, page):
        """ArrowDown advances the selection; Enter takes the new one."""
        page.keyboard.press("Control+k")
        page.fill("#palette-input", "a")
        page.wait_for_timeout(100)
        second = _labels(page)[1]
        page.keyboard.press("ArrowDown")
        assert (
            page.locator("#palette-results .palette-item.selected .palette-label").inner_text()
            == second
        )

    def test_no_match_shows_empty_state(self, page):
        page.keyboard.press("Control+k")
        page.fill("#palette-input", "zzzzzz")
        page.wait_for_timeout(100)
        assert page.locator("#palette-results .palette-empty").count() == 1


class TestShortcuts:
    def test_question_mark_opens_help(self, page):
        assert page.locator("#shortcuts-help.hidden").count() == 1
        page.keyboard.press("?")
        assert page.locator("#shortcuts-help.hidden").count() == 0
        assert "Command palette" in page.locator("#shortcuts-help").inner_text()
        page.keyboard.press("Escape")
        assert page.locator("#shortcuts-help.hidden").count() == 1

    def test_j_k_move_selection_and_enter_opens(self, page):
        """List navigation walks the rendered thread items."""
        assert page.locator("#thread-list .thread-item").count() == 3

        page.keyboard.press("j")
        assert page.locator("#thread-list .thread-item.kbd-selected").count() == 1
        first = page.locator("#thread-list .thread-item.kbd-selected .thread-name").inner_text()

        page.keyboard.press("j")
        second = page.locator("#thread-list .thread-item.kbd-selected .thread-name").inner_text()
        assert second != first

        page.keyboard.press("k")
        assert (
            page.locator("#thread-list .thread-item.kbd-selected .thread-name").inner_text()
            == first
        )

        page.keyboard.press("Enter")
        assert len(page.evaluate("window.__nav")) == 1

    def test_shortcuts_inert_while_composer_focused(self, page):
        """Typing '?' or 'j' in a composer types, and never triggers a shortcut."""
        page.evaluate("showView('roomChat')")
        page.focus("#room-message-input")
        page.keyboard.type("?jkc")

        assert page.locator("#shortcuts-help.hidden").count() == 1
        assert page.locator("#compose-modal.hidden").count() == 1
        assert page.input_value("#room-message-input") == "?jkc"

        # The palette hotkey is the deliberate exception.
        page.keyboard.press("Control+k")
        assert page.locator("#command-palette.hidden").count() == 0
        assert page.input_value("#room-message-input") == "?jkc"

    def test_escape_leaves_the_composer(self, page):
        page.evaluate("showView('roomChat')")
        page.focus("#room-message-input")
        page.keyboard.press("Escape")
        assert page.evaluate("document.activeElement.id") != "room-message-input"

    def test_g_then_i_is_a_sequence_not_two_keys(self, page):
        """'g' alone does nothing; 'g' then 'i' navigates."""
        page.evaluate("""() => {
            window.__ns = [];
            window.openNamespace = function (slug) { window.__ns.push(slug); };
        }""")
        page.keyboard.press("g")
        assert page.evaluate("window.__ns") == []
        page.keyboard.press("i")
        assert page.evaluate("window.__ns") == ["test-ns"]


class TestMobileUnaffected:
    def test_touch_device_gets_no_palette_and_no_shortcuts(self, mobile_page):
        """A coarse-pointer device sees none of it."""
        page = mobile_page
        assert page.evaluate("DeadropPalette.isDesktopInput()") is False

        page.keyboard.press("Control+k")
        assert page.locator("#command-palette.hidden").count() == 1

        page.keyboard.press("?")
        assert page.locator("#shortcuts-help.hidden").count() == 1

        page.keyboard.press("j")
        assert page.locator("#thread-list .thread-item.kbd-selected").count() == 0

    def test_touch_device_still_opens_threads_by_tap(self, mobile_page):
        """The gating changes nothing about the normal touch path."""
        mobile_page.locator("#thread-list .thread-item").first.click()
        assert len(mobile_page.evaluate("window.__nav")) == 1
