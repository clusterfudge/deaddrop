"""E2E test: verify web UI sends attachments correctly."""

import asyncio
import base64
import json
import os
import tempfile
import threading
import time

os.environ["DEADROP_ADMIN_TOKEN"] = "test-admin-token"
os.environ["DEADROP_DB"] = ":memory:"
os.environ.pop("HEARE_AUTH_URL", None)

from deadrop import db
from deadrop.api import app
from fastapi.testclient import TestClient


def create_test_image():
    png_data = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAEklEQVQI12P4z8BQDwAEAQH/7e8g7gAAAABJRU5ErkJggg=="
    )
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    tmp.write(png_data)
    tmp.close()
    return tmp.name


async def run_test():
    from playwright.async_api import async_playwright

    db.init_db()
    c = TestClient(app)

    r = c.post(
        "/admin/namespaces",
        json={"slug": "test-e2e"},
        headers={"X-Admin-Token": "test-admin-token"},
    )
    ns_data = r.json()
    ns = ns_data["ns"]
    ns_secret = ns_data["secret"]

    r = c.post(
        f"/{ns}/identities",
        json={"display_name": "TestUser"},
        headers={"X-Namespace-Secret": ns_secret},
    )
    user = r.json()

    r = c.post(
        f"/{ns}/rooms", json={"name": "Test Room"}, headers={"X-Inbox-Secret": user["secret"]}
    )
    room = r.json()
    room_id = room["room_id"]

    print(f"Setup: ns={ns[:8]} user={user['id'][:8]} room={room_id[:8]}")

    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=18926, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    import httpx

    for _ in range(30):
        try:
            httpx.get("http://127.0.0.1:18926/", timeout=1)
            break
        except:
            time.sleep(0.25)

    base_url = "http://127.0.0.1:18926"
    test_image = create_test_image()

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # Navigate to app base first
            await page.goto(f"{base_url}/app")
            await page.wait_for_load_state("domcontentloaded")

            # Inject credentials using the exact CredentialStore format
            cred_data = json.dumps(
                {
                    "version": 1,
                    "namespaces": {
                        "test-e2e": {
                            "ns": ns,
                            "slug": "test-e2e",
                            "displayName": "Test E2E",
                            "ttlHours": 0,
                            "identities": {
                                user["id"]: {
                                    "id": user["id"],
                                    "secret": user["secret"],
                                    "displayName": "TestUser",
                                    "addedAt": "2026-04-16T00:00:00Z",
                                }
                            },
                            "activeIdentity": user["id"],
                        }
                    },
                }
            )
            await page.evaluate(f"localStorage.setItem('deadrop_credentials', '{cred_data}')")

            # Now navigate to the room
            await page.goto(f"{base_url}/app/test-e2e/room/{room_id}")
            await page.wait_for_load_state("networkidle")

            try:
                await page.wait_for_selector("#room-message-input", state="visible", timeout=15000)
                print("✅ Room loaded")
            except Exception as e:
                print(f"❌ Room didn't load: {e}")
                body = await page.evaluate("document.body.innerText")
                print(f"Page: {body[:300]}")
                await browser.close()
                return False

            # Select file
            file_input = await page.query_selector("#room-file-input")
            await file_input.set_input_files(test_image)
            await page.wait_for_timeout(1000)

            pending = await page.evaluate("pendingAttachments.length")
            print(f"pendingAttachments after file select: {pending}")

            if pending > 0:
                info = await page.evaluate(
                    "pendingAttachments.map(a => ({fn: a.filename, ct: a.content_type, dataLen: (a.data||'').length}))"
                )
                print(f"  Details: {json.dumps(info)}")
            else:
                print("  ❌ pendingAttachments is empty!")
                # Debug FileReader
                fr_result = await page.evaluate("""
                    new Promise(resolve => {
                        const input = document.getElementById('room-file-input');
                        if (input.files.length > 0) {
                            resolve('has files: ' + input.files[0].name);
                        } else {
                            resolve('no files');
                        }
                    })
                """)
                print(f"  File input state: {fr_result}")

            # Type message and send
            await page.fill("#room-message-input", "E2E test with attachment")

            captured = {"payload": None}

            async def intercept(route):
                req = route.request
                if "/messages" in req.url and req.method == "POST":
                    body = req.post_data
                    captured["payload"] = json.loads(body) if body else None
                await route.continue_()

            await page.route("**/**/messages", intercept)
            await page.click("#room-send-btn")
            await page.wait_for_timeout(3000)

            payload = captured.get("payload")
            if not payload:
                print("\n❌ No POST captured")
                await browser.close()
                return False

            print(f"\nPOST payload keys: {list(payload.keys())}")
            has_att = "attachments" in payload
            if has_att:
                atts = payload["attachments"]
                print(f"✅ PASS: {len(atts)} attachment(s) sent")
                for a in atts:
                    print(f"  - {a.get('filename')} ({a.get('content_type')})")
            else:
                print("❌ FAIL: no attachments key")
                print(
                    f"Payload: {json.dumps({k: str(v)[:80] for k, v in payload.items()}, indent=2)}"
                )

            await browser.close()
            return has_att
    finally:
        os.unlink(test_image)
        server.should_exit = True


if __name__ == "__main__":
    result = asyncio.run(run_test())
    print(f"\n{'=' * 40}\nRESULT: {'PASS ✅' if result else 'FAIL ❌'}")
