"""
Playwright test for strikethrough delimiter handling in renderMessageBody().

Verifies, against the real client JS in a real browser:
  1. Single tildes never produce a <del> span — approximation tildes
     ("~1 GB/s … (~4h"), adjacent tildes ("~10~20") and home paths ("~/a")
     render literally.
  2. Paired ``~~text~~`` still renders as <del>, including with nested inline
     markup and multiple spans in one message.

Test approach mirrors tests/test_reply_playwright.py: the app.html template is
rendered with minimal Jinja2 substitution and served from a local HTTP server,
so the real marked configuration runs in a real browser with no FastAPI at
runtime.
"""

import pytest

from playwright.sync_api import sync_playwright

from tests.test_reply_playwright import start_static_server

pytestmark = pytest.mark.integration


TEST_HTTP_PORT = 19116
BASE_URL = f"http://127.0.0.1:{TEST_HTTP_PORT}"

# Verbatim body of a message that rendered with a stray <del> span spanning
# three sentences.
REPRO_BODY = (
    "Running \u2014 guards passed, `rm -rf` is freeing ~1 GB/s "
    "(292G \u2192 345G free in the first minute), tmux `scarif-drop` on r2d2. "
    "When the delete finishes it chains straight into `scarif-sync.sh all` "
    "for the remaining ~1.15T of TV + INBOUND + BitTorrent (~4h at wire speed)."
)

NO_STRIKETHROUGH = [
    REPRO_BODY,
    "Backup ~1 GB/s, ~4h remaining, ~18T total",
    "roughly ~10~20 items",
    "see ~/a/b and ~/c/d",
    "a ~~b c",
]

STRIKETHROUGH = [
    "this is ~~struck~~ text",
    "this is ~~*struck*~~ text",
    "~~one~~ and ~~two~~",
]


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server(TEST_HTTP_PORT)
    yield BASE_URL
    http_server.shutdown()


class TestMarkdownStrikethrough:
    def test_single_tilde_is_literal_and_double_tilde_strikes(self, server):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_context().new_page()

            page.goto(server)
            page.wait_for_load_state("networkidle")
            page.wait_for_function("typeof renderMessageBody === 'function'", timeout=10000)

            for body in NO_STRIKETHROUGH:
                html = page.evaluate("(b) => renderMessageBody(b, 'text/markdown')", body)
                assert "<del>" not in html, f"unexpected strikethrough for {body!r}: {html}"

            for body in STRIKETHROUGH:
                html = page.evaluate("(b) => renderMessageBody(b, 'text/markdown')", body)
                assert "<del>" in html, f"missing strikethrough for {body!r}: {html}"

            # The repro's tildes survive as literal text, not swallowed by a span.
            html = page.evaluate("(b) => renderMessageBody(b, 'text/markdown')", REPRO_BODY)
            assert "~1 GB/s" in html
            assert "~1.15T" in html
            assert "(~4h" in html

            browser.close()
