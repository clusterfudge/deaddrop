"""
Playwright test for external-link handling in rendered message bodies.

Verifies, against the real client JS in a real browser (marked + DOMPurify
loaded exactly as the app loads them):

  1. An external http(s) link — markdown syntax or GFM autolink — renders with
     ``target="_blank" rel="noopener noreferrer"``, and both attributes survive
     DOMPurify.
  2. In-app destinations (relative routes, same-origin absolute URLs) and
     non-http schemes render without ``target``.
  3. In a browser tab no click handling is added — the anchor's own target
     carries the behavior.
  4. In an installed iOS web app an external link click is intercepted, and
     falls back to ``window.open`` when the Safari scheme goes unhandled.
  5. In an installed iOS web app an in-app link click is not intercepted.

Test approach mirrors tests/test_reply_playwright.py: app.html is rendered with
minimal Jinja2 substitution and served from a local HTTP server, so the real
client JS runs in a real browser with no FastAPI at runtime.
"""

import pytest

from playwright.sync_api import sync_playwright

from tests.test_reply_playwright import start_static_server

pytestmark = pytest.mark.integration

TEST_HTTP_PORT = 19116
BASE_URL = f"http://127.0.0.1:{TEST_HTTP_PORT}"

GMAIL_URL = "https://mail.google.com/mail/u/0/#inbox"


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server(TEST_HTTP_PORT)
    yield BASE_URL
    http_server.shutdown()


@pytest.fixture
def page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        pg = browser.new_page()
        pg.goto(f"{server}/app")
        pg.wait_for_function(
            "typeof renderMessageBody === 'function' && typeof DOMPurify !== 'undefined'"
        )
        yield pg
        browser.close()


def _render(pg, body):
    return pg.evaluate("(body) => renderMessageBody(body, 'text/markdown')", body)


def test_external_link_targets_blank_and_survives_sanitizer(page):
    html = _render(page, f"Check [Gmail]({GMAIL_URL})")
    assert 'target="_blank"' in html
    assert 'rel="noopener noreferrer"' in html
    assert GMAIL_URL in html


def test_autolinked_external_url_targets_blank(page):
    html = _render(page, f"raw {GMAIL_URL}")
    assert 'target="_blank"' in html
    assert 'rel="noopener noreferrer"' in html


def test_in_app_links_have_no_target(page):
    relative = _render(page, "[room](/app/fritz/rooms/abc)")
    assert "<a " in relative
    assert "target=" not in relative

    same_origin = _render(page, f"[abs]({BASE_URL}/app/fritz)")
    assert "<a " in same_origin
    assert "target=" not in same_origin

    mailto = _render(page, "[mail](mailto:sean@example.com)")
    assert "target=" not in mailto


SETUP_JS = """(args) => {
    window.__opened = [];
    window.open = (url, target, features) => {
        window.__opened.push([url, target, features]);
        return null;
    };
    DeadropPush.standalone = () => args.standalone;
    DeadropPush.isIOS = () => args.ios;
    const host = document.createElement('div');
    host.className = 'markdown-body';
    host.id = 'test-body';
    host.innerHTML = args.html;
    host.addEventListener('click', (e) => e.preventDefault());
    document.body.appendChild(host);
}"""


def _mount(pg, body, standalone, ios):
    pg.evaluate(
        SETUP_JS,
        {"html": _render(pg, body), "standalone": standalone, "ios": ios},
    )


def test_browser_tab_click_not_intercepted(page):
    _mount(page, f"Check [Gmail]({GMAIL_URL})", standalone=False, ios=True)
    page.click("#test-body a")
    assert page.evaluate("() => window.__opened") == []
    assert page.url == f"{BASE_URL}/app"


def test_ios_standalone_external_click_falls_back_to_window_open(page):
    _mount(page, f"Check [Gmail]({GMAIL_URL})", standalone=True, ios=True)
    page.click("#test-body a")
    page.wait_for_function("() => window.__opened.length === 1", timeout=5000)
    opened = page.evaluate("() => window.__opened")[0]
    assert opened[0] == GMAIL_URL
    assert opened[1] == "_blank"
    assert "noopener" in opened[2]
    # The app frame did not navigate.
    assert page.url == f"{BASE_URL}/app"


def test_ios_standalone_in_app_click_not_intercepted(page):
    _mount(page, "[room](/app/fritz/rooms/abc)", standalone=True, ios=True)
    page.click("#test-body a")
    assert page.evaluate("() => window.__opened") == []
