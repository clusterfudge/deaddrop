"""
Playwright test for handing Gmail message links to the native Gmail app.

Verifies, against the real client JS in a real browser:
  1. ``nativeAppUrl()`` maps an https ``mail.google.com`` URL to
     ``googlegmail://`` in an installed iOS web app, and to null for every
     other URL and every other platform.
  2. In an installed iOS web app a Gmail link click is intercepted, the app
     frame stays on ``/app``, and the rendered anchor keeps its https href.
  3. Non-Gmail links on iOS, and Gmail links on other platforms, are not
     intercepted.

The OS hand-off to the Gmail app itself cannot run in Chromium; that needs a
device.

Test approach mirrors tests/test_reply_playwright.py: app.html is rendered
with minimal Jinja2 substitution and served from a local HTTP server, so the
real client JS runs in a real browser with no FastAPI at runtime.
"""

import pytest

from playwright.sync_api import sync_playwright

from tests.test_reply_playwright import start_static_server

pytestmark = pytest.mark.integration

TEST_HTTP_PORT = 19122
BASE_URL = f"http://127.0.0.1:{TEST_HTTP_PORT}"

GMAIL_INBOX = "https://mail.google.com/mail/u/0/#inbox/19a8f2c3d4e5f607"

URLS = {
    "inbox": GMAIL_INBOX,
    "all": "https://mail.google.com/mail/u/0/#all/19a8f2c3d4e5f607",
    "search": "https://mail.google.com/mail/u/0/#search/from%3Abob+subject%3A%22Q3%22",
    "label": "https://mail.google.com/mail/u/0/#label/Receipts%2F2026/19a8f2c3d4e5f607",
    "sent": "https://mail.google.com/mail/u/0/#sent/19a8f2c3d4e5f607",
    "thread": "https://mail.google.com/mail/u/1/#thread/19a8f2c3d4e5f607",
    "special_fragment": (
        "https://mail.google.com/mail/u/0/"
        "#search/rfc822msgid%3A%3CCAB%2Bx%3D1%40mail.gmail.com%3E/19a8f2c3d4e5f607"
    ),
    "lookalike_host": "https://mail.google.com.example.net/mail/u/0/#inbox/1",
    "non_gmail": "https://github.com/clusterfudge/deaddrop/pull/103",
    "mailto": "mailto:sean@example.com",
    "relative": "/app/fritz/rooms/abc",
}

GMAIL_KEYS = {"inbox", "all", "search", "label", "sent", "thread", "special_fragment"}

PLATFORMS = {
    "ios_standalone": {"ios": True, "standalone": True},
    "ios_tab": {"ios": True, "standalone": False},
    "android_standalone": {"ios": False, "standalone": True},
    "android_tab": {"ios": False, "standalone": False},
}


def _expected(platform, key):
    if platform == "ios_standalone" and key in GMAIL_KEYS:
        return "googlegmail://"
    return None


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
            "typeof nativeAppUrl === 'function' && typeof renderMessageBody === 'function'"
        )
        yield pg
        browser.close()


def test_native_app_url_table(page):
    actual = page.evaluate(
        """({urls, platforms}) => {
            const out = {};
            for (const [p, flags] of Object.entries(platforms)) {
                out[p] = {};
                for (const [k, href] of Object.entries(urls)) {
                    out[p][k] = nativeAppUrl(href, flags);
                }
            }
            return out;
        }""",
        {"urls": URLS, "platforms": PLATFORMS},
    )
    expected = {p: {k: _expected(p, k) for k in URLS} for p in PLATFORMS}
    assert actual == expected


SETUP_JS = """(args) => {
    DeadropPush.isIOS = () => args.ios;
    DeadropPush.standalone = () => args.standalone;
    const host = document.createElement('div');
    host.className = 'markdown-body';
    host.id = 'test-body';
    host.innerHTML = renderMessageBody(args.body, 'text/markdown');
    document.body.appendChild(host);
    window.__clicks = [];
    window.addEventListener('click', (e) => {
        window.__clicks.push(e.defaultPrevented);
        e.preventDefault();
    });
}"""


def _click(pg, body, ios, standalone):
    pg.evaluate(SETUP_JS, {"body": body, "ios": ios, "standalone": standalone})
    pg.click("#test-body a")
    return pg.evaluate("() => window.__clicks")


def test_ios_standalone_gmail_click_is_handed_off(page):
    assert _click(page, f"[Q3 receipt]({GMAIL_INBOX})", ios=True, standalone=True) == [True]
    assert page.url == f"{BASE_URL}/app"
    assert page.get_attribute("#test-body a", "href") == GMAIL_INBOX


@pytest.mark.parametrize(
    ("href", "ios", "standalone"),
    [
        (URLS["non_gmail"], True, True),
        (GMAIL_INBOX, True, False),
        (GMAIL_INBOX, False, True),
    ],
    ids=["ios-standalone-non-gmail", "ios-tab-gmail", "android-standalone-gmail"],
)
def test_other_clicks_not_intercepted(page, href, ios, standalone):
    assert _click(page, f"[link]({href})", ios=ios, standalone=standalone) == [False]
