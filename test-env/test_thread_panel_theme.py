"""Theme audit: every new panel surface must resolve from theme variables.

Renders the panel in light and dark and reads computed styles. A surface whose
colour is identical across themes is either transparent-by-design or a
hardcoded value; the assertions below name which is which.
"""

import asyncio
import json
import threading
import time

from test_thread_panel_e2e import BASE, PORT, creds_blob, seed  # noqa: E402

# Selector -> CSS properties that must differ between light and dark.
THEMED = {
    ".panel-tabs": ["background-color", "border-bottom-color"],
    ".panel-tab.active": ["color", "border-bottom-color"],
    ".attachment-thumb": ["background-color", "border-color"],
    ".attachment-tile-by": ["color"],
    ".attachment-jump": ["color", "border-color"],
    ".attachment-row": ["background-color", "border-color"],
    ".attachment-row-sub": ["color"],
    ".search-result": ["background-color", "border-color"],
    ".search-result-author": ["color"],
    ".search-result-body mark": ["background-color"],
    "#attachments-empty .empty-state-title": ["color"],
}


async def collect(page, selectors):
    out = {}
    for sel, props in selectors.items():
        out[sel] = await page.evaluate(
            """([sel, props]) => {
                const el = document.querySelector(sel);
                if (!el) return null;
                const cs = getComputedStyle(el);
                const r = {};
                for (const p of props) r[p] = cs.getPropertyValue(p);
                return r;
            }""",
            [sel, props],
        )
    return out


async def run():
    from playwright.async_api import async_playwright

    import uvicorn

    from deadrop.api import app

    s = seed()
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

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": 390, "height": 844})
            await page.goto(f"{BASE}/app")
            await page.evaluate(f"localStorage.setItem('deadrop_credentials', {creds_blob(s)!r})")
            await page.goto(f"{BASE}/app/panel-e2e/room/{s['room_id']}")
            await page.wait_for_selector("#room-message-input", state="visible", timeout=20000)
            await page.wait_for_timeout(1000)
            await page.click("#room-panel-btn")
            await page.wait_for_timeout(1500)
            # Populate the search tab too, so its surfaces exist in the DOM.
            await page.click("#panel-tab-search")
            await page.fill("#panel-search-input", "marmalade")
            await page.wait_for_timeout(900)
            await page.click("#panel-tab-attachments")

            snapshots = {}
            for theme in ("light", "dark"):
                await page.evaluate(f"applyTheme('{theme}')")
                await page.wait_for_timeout(300)
                snapshots[theme] = await collect(page, THEMED)

            await browser.close()
    finally:
        server.should_exit = True

    return snapshots


if __name__ == "__main__":
    snaps = asyncio.run(run())
    light, dark = snaps["light"], snaps["dark"]

    print(json.dumps(snaps, indent=2))
    print()

    ok = True
    for sel, props in THEMED.items():
        if light.get(sel) is None:
            print(f"FAIL  {sel}: not in DOM")
            ok = False
            continue
        for prop in props:
            lv, dv = light[sel][prop], dark[sel][prop]
            same = lv == dv
            if same:
                ok = False
            print(f"{'FAIL' if same else 'PASS'}  {sel} {prop}: {lv} -> {dv}")

    print(f"\nRESULT: {'PASS' if ok else 'FAIL'}")
