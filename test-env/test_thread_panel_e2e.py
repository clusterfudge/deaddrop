"""E2E: attachments panel, lightbox reuse, jump-to-message, and search.

Seeds a room with enough history that the jump target is NOT in the first
page, then drives the real browser through the panel. Also exercises the 1:1
panel (attachments empty state + client-side search + jump).

Screenshots land in test-env/screenshots/.
"""

import asyncio
import base64
import json
import os
import struct
import threading
import time
import zlib
from pathlib import Path

os.environ["DEADROP_ADMIN_TOKEN"] = "test-admin-token"
os.environ["DEADROP_DB"] = ":memory:"
os.environ.pop("HEARE_AUTH_URL", None)

from deadrop import db  # noqa: E402
from deadrop.api import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PORT = 18931
BASE = f"http://127.0.0.1:{PORT}"
SHOTS = Path(__file__).parent / "screenshots"
# History depth: the room page size is 50, so an attachment behind this many
# messages forces the jump path to page backwards.
FILLER_MESSAGES = 70


def _png_b64(r, g, b):
    """A 4x4 solid-colour PNG, so grid thumbnails are visually distinguishable."""

    def chunk(kind, data):
        c = kind + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    w = h = 4
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes([r, g, b]) * w for _ in range(h))
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    return base64.b64encode(png).decode()


def seed():
    db.init_db()
    c = TestClient(app)
    admin = {"X-Admin-Token": "test-admin-token"}

    ns_data = c.post("/admin/namespaces", json={"slug": "panel-e2e"}, headers=admin).json()
    ns, ns_secret = ns_data["ns"], ns_data["secret"]

    def identity(name):
        return c.post(
            f"/{ns}/identities",
            json={"metadata": {"display_name": name}},
            headers={"X-Namespace-Secret": ns_secret},
        ).json()

    alice = identity("Alice")
    bob = identity("Bob")

    room = c.post(
        f"/{ns}/rooms",
        json={"display_name": "Gallery Room"},
        headers={"X-Inbox-Secret": alice["secret"]},
    ).json()
    room_id = room["room_id"]
    c.post(
        f"/{ns}/rooms/{room_id}/members",
        json={"identity_id": bob["id"]},
        headers={"X-Inbox-Secret": alice["secret"]},
    )

    alice_h = {"X-Inbox-Secret": alice["secret"]}
    bob_h = {"X-Inbox-Secret": bob["secret"]}

    # The deep target: an attachment + a searchable phrase, buried in history.
    deep = c.post(
        f"/{ns}/rooms/{room_id}/messages",
        json={
            "body": "the ancient artifact photo, codeword marmalade",
            "attachments": [
                {
                    "filename": "artifact.png",
                    "content_type": "image/png",
                    "data": _png_b64(220, 40, 40),
                }
            ],
        },
        headers=alice_h,
    ).json()

    for i in range(FILLER_MESSAGES):
        c.post(
            f"/{ns}/rooms/{room_id}/messages",
            json={"body": f"filler chatter number {i}"},
            headers=(alice_h if i % 2 else bob_h),
        )

    # Recent attachments so the grid has more than one tile.
    for name, colour in (("blue.png", (40, 90, 220)), ("green.png", (40, 180, 90))):
        c.post(
            f"/{ns}/rooms/{room_id}/messages",
            json={
                "body": f"recent {name}",
                "attachments": [
                    {"filename": name, "content_type": "image/png", "data": _png_b64(*colour)}
                ],
            },
            headers=bob_h,
        )
    c.post(
        f"/{ns}/rooms/{room_id}/messages",
        json={
            "body": "notes attached",
            "attachments": [
                {
                    "filename": "notes.md",
                    "content_type": "text/markdown",
                    "data": base64.b64encode(b"# notes\nsome text\n").decode(),
                }
            ],
        },
        headers=alice_h,
    )

    # 1:1 thread, for the conversation-side panel.
    for body in ("dm hello there", "dm codeword marmalade in a direct message", "dm goodbye"):
        c.post(f"/{ns}/send", json={"to": alice["id"], "body": body}, headers=bob_h)

    return {
        "ns": ns,
        "room_id": room_id,
        "deep_mid": deep["mid"],
        "alice": alice,
        "bob": bob,
    }


def creds_blob(s):
    a = s["alice"]
    return json.dumps(
        {
            "version": 1,
            "namespaces": {
                "panel-e2e": {
                    "ns": s["ns"],
                    "slug": "panel-e2e",
                    "displayName": "Panel E2E",
                    "ttlHours": 0,
                    "identities": {
                        a["id"]: {
                            "id": a["id"],
                            "secret": a["secret"],
                            "displayName": "Alice",
                            "addedAt": "2026-08-28T00:00:00Z",
                        }
                    },
                    "activeIdentity": a["id"],
                }
            },
        }
    )


async def run():
    from playwright.async_api import async_playwright

    s = seed()
    SHOTS.mkdir(exist_ok=True)

    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    import httpx

    for _ in range(40):
        try:
            httpx.get(f"{BASE}/health", timeout=1)
            break
        except Exception:
            time.sleep(0.25)

    results = {}

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            # Mobile aspect ratio — this is the review surface.
            page = await browser.new_page(viewport={"width": 390, "height": 844})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on(
                "console",
                lambda m: errors.append(f"console.error: {m.text}") if m.type == "error" else None,
            )

            await page.goto(f"{BASE}/app")
            await page.evaluate(f"localStorage.setItem('deadrop_credentials', {creds_blob(s)!r})")

            # ---------- Room panel ----------
            await page.goto(f"{BASE}/app/panel-e2e/room/{s['room_id']}")
            await page.wait_for_selector("#room-message-input", state="visible", timeout=20000)
            await page.wait_for_timeout(1200)

            await page.click("#room-panel-btn")
            await page.wait_for_selector("#view-thread-panel:not(.hidden)", timeout=5000)
            await page.wait_for_timeout(1500)

            tiles = await page.eval_on_selector_all(".attachment-tile", "els => els.length")
            rows = await page.eval_on_selector_all(".attachment-row", "els => els.length")
            loaded = await page.eval_on_selector_all(
                ".attachment-thumb[data-loaded='true']", "els => els.length"
            )
            results["room_tiles"] = tiles
            results["room_file_rows"] = rows
            results["room_thumbs_loaded"] = loaded

            for theme in ("light", "dark"):
                await page.evaluate(f"applyTheme('{theme}')")
                await page.wait_for_timeout(350)
                await page.screenshot(path=str(SHOTS / f"panel-attachments-mobile-{theme}.png"))

            # ---------- Lightbox reuse ----------
            await page.click(".attachment-thumb[data-loaded='true']")
            await page.wait_for_selector("#image-lightbox:not(.hidden)", timeout=5000)
            results["lightbox_src_is_data_uri"] = await page.evaluate(
                "document.getElementById('lightbox-img').src.startsWith('data:image/')"
            )
            await page.screenshot(path=str(SHOTS / "panel-lightbox-mobile-dark.png"))
            await page.evaluate("closeLightbox()")

            # ---------- Search (server-side, room) ----------
            await page.click("#panel-tab-search")
            await page.fill("#panel-search-input", "marmalade")
            await page.wait_for_timeout(900)
            results["room_search_hits"] = await page.eval_on_selector_all(
                ".search-result", "els => els.length"
            )
            results["room_search_marks"] = await page.eval_on_selector_all(
                ".search-result-body mark", "els => els.length"
            )
            for theme in ("light", "dark"):
                await page.evaluate(f"applyTheme('{theme}')")
                await page.wait_for_timeout(350)
                await page.screenshot(path=str(SHOTS / f"panel-search-mobile-{theme}.png"))

            # ---------- Jump from a search hit into deep history ----------
            loaded_before = await page.evaluate("roomMessages.length")
            await page.click(".search-result")
            await page.wait_for_selector("#view-room-chat:not(.hidden)", timeout=5000)
            await page.wait_for_timeout(2500)
            results["msgs_loaded_before_jump"] = loaded_before
            results["msgs_loaded_after_jump"] = await page.evaluate("roomMessages.length")
            results["jump_target_in_dom"] = await page.evaluate(
                f"!!document.querySelector('[data-mid=\"{s['deep_mid']}\"]')"
            )
            results["jump_target_flashed"] = await page.evaluate(
                f"""(() => {{
                    const el = document.querySelector('[data-mid="{s["deep_mid"]}"]');
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    return r.top < window.innerHeight && r.bottom > 0;
                }})()"""
            )
            await page.screenshot(path=str(SHOTS / "panel-jump-target-mobile-dark.png"))

            # ---------- Back gesture closes the panel, not the room ----------
            await page.click("#room-panel-btn")
            await page.wait_for_selector("#view-thread-panel:not(.hidden)", timeout=5000)
            await page.go_back()
            await page.wait_for_timeout(600)
            results["back_returns_to_room"] = await page.evaluate(
                "!document.getElementById('view-room-chat').classList.contains('hidden')"
            )

            # ---------- 1:1 conversation panel ----------
            await page.goto(f"{BASE}/app/panel-e2e/{s['bob']['id']}")
            await page.wait_for_selector("#view-conversation:not(.hidden)", timeout=20000)
            await page.wait_for_timeout(800)
            await page.click("#conversation-panel-btn")
            await page.wait_for_selector("#view-thread-panel:not(.hidden)", timeout=5000)
            await page.wait_for_timeout(400)
            results["dm_attachments_empty_state"] = await page.evaluate(
                "!document.getElementById('attachments-empty').classList.contains('hidden')"
            )
            await page.screenshot(path=str(SHOTS / "panel-dm-attachments-mobile-dark.png"))

            await page.click("#panel-tab-search")
            await page.fill("#panel-search-input", "marmalade")
            await page.wait_for_timeout(700)
            results["dm_search_hits"] = await page.eval_on_selector_all(
                ".search-result", "els => els.length"
            )
            await page.click(".search-result")
            await page.wait_for_selector("#view-conversation:not(.hidden)", timeout=5000)
            await page.wait_for_timeout(700)
            results["dm_jump_flashed"] = await page.evaluate(
                "!!document.querySelector('#message-list .message.reply-target-flash')"
                " || !!document.querySelector('#message-list .message[data-mid]')"
            )

            # ---------- Desktop screenshots ----------
            await page.set_viewport_size({"width": 1280, "height": 900})
            await page.goto(f"{BASE}/app/panel-e2e/room/{s['room_id']}")
            await page.wait_for_selector("#room-message-input", state="visible", timeout=20000)
            await page.wait_for_timeout(1000)
            await page.click("#room-panel-btn")
            await page.wait_for_timeout(1500)
            for theme in ("light", "dark"):
                await page.evaluate(f"applyTheme('{theme}')")
                await page.wait_for_timeout(350)
                await page.screenshot(path=str(SHOTS / f"panel-attachments-desktop-{theme}.png"))

            results["page_errors"] = errors
            await browser.close()
    finally:
        server.should_exit = True

    return results


if __name__ == "__main__":
    out = asyncio.run(run())
    print(json.dumps(out, indent=2))

    checks = {
        "3 image tiles": out.get("room_tiles") == 3,
        "1 file row": out.get("room_file_rows") == 1,
        "thumbs loaded": out.get("room_thumbs_loaded", 0) >= 1,
        "lightbox reused": out.get("lightbox_src_is_data_uri") is True,
        "room search hit": out.get("room_search_hits", 0) >= 1,
        "search highlighted": out.get("room_search_marks", 0) >= 1,
        "jump backfilled history": out.get("msgs_loaded_after_jump", 0)
        > out.get("msgs_loaded_before_jump", 0),
        "jump target in DOM": out.get("jump_target_in_dom") is True,
        "jump target on screen": out.get("jump_target_flashed") is True,
        "back closes panel": out.get("back_returns_to_room") is True,
        "dm empty state": out.get("dm_attachments_empty_state") is True,
        "dm search hit": out.get("dm_search_hits", 0) >= 1,
        "no page errors": not out.get("page_errors"),
    }
    print()
    for name, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"\nRESULT: {'PASS' if all(checks.values()) else 'FAIL'}")
