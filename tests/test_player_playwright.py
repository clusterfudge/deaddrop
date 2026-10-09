"""Playwright tests for media player cards in the room view.

Verifies, against the real client JS in a real browser:
  1. An ``application/x-player`` message renders a card with an <audio>
     element, the playlist, and the first track selected.
  2. Selecting a track (tap, Prev/Next) switches the <audio> source and plays;
     a track that ends advances to the next one.
  3. Playback survives a room re-render, and only one card plays at a time.
  4. Attachment tracks resolve to blob URLs through the attachment cache, and
     their files are not drawn again as chips.
  5. A malformed payload degrades to the title plus one line per track, with
     links only for http(s) URLs; payload strings are never injected as HTML.

The page is served by the static harness in tests/test_question_playwright.py.
Audio is a generated WAV, served by ``page.route`` for URL tracks and by a
stubbed ``DeadropAPI.downloadAttachment`` for attachment tracks.
"""

import base64
import io
import json
import wave

import pytest
from playwright.sync_api import sync_playwright

from tests.test_question_playwright import start_static_server

pytestmark = pytest.mark.integration

TEST_HTTP_PORT = 19131

PLAYER_MID = "0192b000-0000-7000-8000-000000000001"
SECOND_MID = "0192b000-0000-7000-8000-000000000002"
ATTACH_MID = "0192b000-0000-7000-8000-000000000003"
BROKEN_MID = "0192b000-0000-7000-8000-000000000004"
MISSING_MID = "0192b000-0000-7000-8000-000000000005"

MEDIA = "https://media.test"


def _wav(seconds: float) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(b"\x00\x00" * int(8000 * seconds))
    return buf.getvalue()


SHORT_WAV = _wav(0.4)
LONG_WAV = _wav(6.0)

PLAYER = {
    "title": "Doof samples",
    "tracks": [
        {"title": "Curse", "subtitle": "plain", "src": f"{MEDIA}/short.wav"},
        {"title": "Scheme", "subtitle": "converted", "src": f"{MEDIA}/long.wav", "duration": 6},
        {"title": "Nouns", "src": f"{MEDIA}/long2.wav"},
    ],
}
SECOND = {"title": "Other", "tracks": [{"title": "Solo", "src": f"{MEDIA}/long3.wav"}]}
ATTACHED = {
    "title": "Attached",
    "tracks": [{"attachment": "one.wav"}, {"attachment": "att-2", "title": "Two"}],
}
BROKEN = {
    "title": "Broken list",
    "tracks": [
        {"title": "Fine", "src": f"{MEDIA}/short.wav"},
        {"title": "Evil", "src": "javascript:alert(1)"},
    ],
}
MISSING = {"title": "Missing file", "tracks": [{"attachment": "nope.wav"}]}

SETUP_ROOM_JS = """
    ({player, second, attached, broken, missing, wavB64}) => {
        credentials = {id: 'alice-id', secret: 'alice-secret', ns: 'test-ns'};
        currentRoomId = 'room-test';
        roomMembers = {
            'alice-id': {display_name: 'Alice'},
            'bob-id': {display_name: 'Bob'},
        };
        roomHasOlderMessages = false;
        const wav = Uint8Array.from(atob(wavB64), c => c.charCodeAt(0));
        window.__downloads = [];
        DeadropAPI.downloadAttachment = async (creds, id) => {
            window.__downloads.push(id);
            return {blob: new Blob([wav], {type: 'audio/wav'}), filename: null};
        };
        const msg = (mid, body, extra = {}) => ({
            mid, room_id: 'room-test', from_id: 'bob-id', body: JSON.stringify(body),
            content_type: 'application/x-player', created_at: '2026-10-09T10:00:00Z', ...extra,
        });
        roomMessages = [
            msg('0192b000-0000-7000-8000-000000000001', player),
            msg('0192b000-0000-7000-8000-000000000002', second),
            msg('0192b000-0000-7000-8000-000000000003', attached, {attachments: [
                {id: 'att-1', message_mid: 'x', filename: 'one.wav',
                 content_type: 'audio/wav', size: 100, created_at: ''},
                {id: 'att-2', message_mid: 'x', filename: 'two.wav',
                 content_type: 'audio/wav', size: 100, created_at: ''},
                {id: 'att-3', message_mid: 'x', filename: 'notes.txt',
                 content_type: 'text/plain', size: 10, created_at: ''},
            ]}),
            msg('0192b000-0000-7000-8000-000000000004', broken),
            msg('0192b000-0000-7000-8000-000000000005', missing),
        ];
        document.getElementById('view-room-chat').classList.remove('hidden');
        renderRoomMessages({skipReadCursor: true});
    }
"""


@pytest.fixture(scope="module")
def server():
    http_server = start_static_server(TEST_HTTP_PORT)
    yield f"http://127.0.0.1:{TEST_HTTP_PORT}"
    http_server.shutdown()


def _serve_media(route):
    path = route.request.url.rsplit("/", 1)[-1]
    if path == "short.wav":
        body = SHORT_WAV
    elif path.startswith("long"):
        body = LONG_WAV
    else:
        route.fulfill(status=404, body="")
        return
    route.fulfill(status=200, content_type="audio/wav", body=body)


@pytest.fixture
def page(server):
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True, args=["--autoplay-policy=no-user-gesture-required"]
        )
        context = browser.new_context(viewport={"width": 390, "height": 844})
        pg = context.new_page()
        pg.route(f"{MEDIA}/**", _serve_media)
        pg.goto(server)
        pg.wait_for_load_state("networkidle")
        pg.wait_for_function("typeof renderPlayerCard === 'function'", timeout=10000)
        pg.evaluate(
            SETUP_ROOM_JS,
            {
                "player": PLAYER,
                "second": SECOND,
                "attached": ATTACHED,
                "broken": BROKEN,
                "missing": MISSING,
                "wavB64": base64.b64encode(LONG_WAV).decode(),
            },
        )
        yield pg
        browser.close()


def _card(page, mid):
    return page.locator(f'.room-message[data-mid="{mid}"] .player-card')


def _audio_js(mid):
    return f"document.querySelector('.room-message[data-mid=\"{mid}\"] .player-card audio')"


def _wait_playing(page, mid):
    page.wait_for_function(f"!{_audio_js(mid)}.paused && {_audio_js(mid)}.currentTime > 0")


class TestRendering:
    def test_card_has_audio_and_playlist(self, page):
        card = _card(page, PLAYER_MID)
        assert card.count() == 1
        assert card.locator(".player-title").inner_text() == "Doof samples"
        assert card.locator("audio.player-audio").count() == 1
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.controls") is True

        tracks = card.locator(".player-track")
        assert tracks.count() == 3
        assert tracks.nth(0).locator(".player-track-title").inner_text() == "Curse"
        assert tracks.nth(0).locator(".player-track-sub").inner_text() == "plain"
        assert tracks.nth(1).locator(".player-track-dur").inner_text() == "0:06"
        assert "current" in tracks.nth(0).get_attribute("class")
        assert tracks.nth(0).get_attribute("aria-current") == "true"
        assert card.locator(".player-now-title").inner_text() == "Curse"
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.getAttribute('src')") == (
            f"{MEDIA}/short.wav"
        )
        # Nothing plays until asked, and no JSON reaches the reader.
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.paused") is True
        assert "tracks" not in page.locator(f'.room-message[data-mid="{PLAYER_MID}"]').inner_text()

    def test_controls_are_at_least_44px_tall(self, page):
        heights = page.eval_on_selector_all(
            f'.room-message[data-mid="{PLAYER_MID}"] .player-card button',
            "els => els.map(e => e.getBoundingClientRect().height)",
        )
        assert len(heights) == 5 and all(h >= 44 for h in heights), heights

    def test_single_track_card_has_no_prev_next(self, page):
        assert _card(page, SECOND_MID).locator(".player-nav").count() == 0

    def test_payload_strings_are_escaped(self, page):
        page.evaluate("""() => {
            roomMessages[1].body = JSON.stringify({
                title: '<img src=x onerror="window.__pwned=1">list',
                tracks: [{title: '<b>bold</b>', subtitle: '<i>x</i>',
                          src: 'https://media.test/long.wav'}],
            });
            renderRoomMessages({skipReadCursor: true});
        }""")
        card = _card(page, SECOND_MID)
        assert "<img" in card.locator(".player-title").inner_text()
        assert card.locator(".player-track-title").inner_text() == "<b>bold</b>"
        assert card.locator("img, b, i").count() == 0
        assert page.evaluate("window.__pwned || 0") == 0


class TestPlayback:
    def test_tapping_a_track_switches_src_and_plays(self, page):
        card = _card(page, PLAYER_MID)
        card.locator(".player-track").nth(1).click()
        _wait_playing(page, PLAYER_MID)
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.getAttribute('src')") == (
            f"{MEDIA}/long.wav"
        )
        assert card.get_attribute("data-track") == "1"
        assert "current" in card.locator(".player-track").nth(1).get_attribute("class")
        assert "current" not in card.locator(".player-track").nth(0).get_attribute("class")
        assert card.locator(".player-now-title").inner_text() == "Scheme"

    def test_prev_and_next_step_through_the_list(self, page):
        card = _card(page, PLAYER_MID)
        prev, nxt = card.locator(".player-prev"), card.locator(".player-next")
        assert prev.is_disabled() and not nxt.is_disabled()
        nxt.click()
        nxt.click()
        assert card.get_attribute("data-track") == "2"
        assert nxt.is_disabled()
        prev.click()
        assert card.get_attribute("data-track") == "1"
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.getAttribute('src')") == (
            f"{MEDIA}/long.wav"
        )

    def test_a_finished_track_advances_to_the_next(self, page):
        card = _card(page, PLAYER_MID)
        card.locator(".player-track").nth(0).click()
        page.wait_for_function(
            f"""document.querySelector('.room-message[data-mid="{PLAYER_MID}"] .player-card')
                    .dataset.track === '1'""",
            timeout=5000,
        )
        _wait_playing(page, PLAYER_MID)
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.getAttribute('src')") == (
            f"{MEDIA}/long.wav"
        )

    def test_playback_survives_a_room_rerender(self, page):
        _card(page, PLAYER_MID).locator(".player-track").nth(1).click()
        _wait_playing(page, PLAYER_MID)
        page.evaluate(f"{_audio_js(PLAYER_MID)}.__marker = 'same-element'")
        page.evaluate("""() => {
            roomMessages.push({mid: '0192b000-0000-7000-8000-0000000000ff',
                room_id: 'room-test', from_id: 'bob-id', body: 'new message',
                content_type: 'text/markdown', created_at: '2026-10-09T10:05:00Z'});
            renderRoomMessages({skipReadCursor: true});
        }""")
        before = page.evaluate(f"{_audio_js(PLAYER_MID)}.currentTime")
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.__marker") == "same-element"
        page.wait_for_function(f"{_audio_js(PLAYER_MID)}.currentTime > {before} + 0.2")
        assert page.evaluate(f"{_audio_js(PLAYER_MID)}.paused") is False

    def test_starting_one_card_pauses_another(self, page):
        _card(page, PLAYER_MID).locator(".player-track").nth(1).click()
        _wait_playing(page, PLAYER_MID)
        _card(page, SECOND_MID).locator(".player-track").nth(0).click()
        _wait_playing(page, SECOND_MID)
        page.wait_for_function(f"{_audio_js(PLAYER_MID)}.paused")

    def test_a_track_that_fails_to_load_says_so(self, page):
        page.evaluate("""() => {
            roomMessages[1].body = JSON.stringify(
                {tracks: [{title: 'Gone', src: 'https://media.test/missing.wav'}]});
            renderRoomMessages({skipReadCursor: true});
        }""")
        card = _card(page, SECOND_MID)
        card.locator(".player-track").nth(0).click()
        page.wait_for_function(
            f"""document.querySelector('.room-message[data-mid="{SECOND_MID}"] .player-card')
                    .classList.contains('player-error')"""
        )
        assert card.locator(".player-now-sub").inner_text() == "Could not load this track"


class TestAttachmentTracks:
    def test_attachment_tracks_play_from_blob_urls(self, page):
        card = _card(page, ATTACH_MID)
        titles = card.locator(".player-track-title").all_inner_texts()
        assert titles == ["one.wav", "Two"]
        page.wait_for_function(
            f"({_audio_js(ATTACH_MID)}.getAttribute('src') || '').startsWith('blob:')"
        )
        # Only the selected track is fetched before anything plays.
        assert page.evaluate("window.__downloads") == ["att-1"]

        card.locator(".player-track").nth(1).click()
        _wait_playing(page, ATTACH_MID)
        assert "att-2" in page.evaluate("window.__downloads")
        assert card.get_attribute("data-track") == "1"

    def test_track_files_are_not_drawn_as_chips(self, page):
        msg = page.locator(f'.room-message[data-mid="{ATTACH_MID}"]')
        chips = msg.locator(".file-attachment")
        assert chips.count() == 1
        assert "notes.txt" in chips.inner_text()


class TestFallback:
    def test_a_bad_track_url_degrades_the_whole_card(self, page):
        msg = page.locator(f'.room-message[data-mid="{BROKEN_MID}"]')
        assert msg.locator(".player-card").count() == 0
        body = msg.locator(".message-body")
        text = body.inner_text()
        assert "Broken list" in text and "Fine" in text and "Evil" in text
        assert "{" not in text
        links = body.locator("a")
        assert links.count() == 1
        assert links.get_attribute("href") == f"{MEDIA}/short.wav"

    def test_a_missing_attachment_degrades_to_text(self, page):
        msg = page.locator(f'.room-message[data-mid="{MISSING_MID}"]')
        assert msg.locator(".player-card").count() == 0
        text = msg.locator(".message-body").inner_text()
        assert "Missing file" in text and "nope.wav" in text

    def test_fallback_html_links_only_http_urls(self, page):
        html = page.evaluate(
            "b => renderMessageBody(b, 'application/x-player')",
            json.dumps(
                {
                    "title": "T",
                    "tracks": [
                        {"title": "web", "src": "https://media.test/a.mp3"},
                        {"title": "data", "src": "data:audio/wav;base64,AAAA"},
                        {"attachment": "file.mp3"},
                    ],
                }
            ),
        )
        assert '<a href="https://media.test/a.mp3"' in html
        assert "data:audio" not in html
        assert "file.mp3" in html
        assert html.count("<a ") == 1

    def test_reply_quote_uses_the_title(self, page):
        snippet = page.evaluate(
            "b => replySnippet({content_type: 'application/x-player', body: b})",
            json.dumps(PLAYER),
        )
        assert snippet == "Doof samples"
