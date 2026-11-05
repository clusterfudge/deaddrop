"""Headless Chromium driving the real join.html and app.html (playwright sync API)."""

import json
import time

from fleet_lib import VAULT, log, thermal_wait


class BrowserFleet:
    def __init__(self, url, ns, slug, room):
        from playwright.sync_api import sync_playwright

        thermal_wait()
        self.url, self.ns, self.slug, self.room = url, ns, slug, room
        self.pw = sync_playwright().start()
        self.browser = self.pw.chromium.launch()
        self.pages = {}

    def context(self, name, identity=None, secret=None):
        state = None
        if identity:
            creds = {
                "version": 1,
                "namespaces": {
                    self.slug: {
                        "ns": self.ns,
                        "slug": self.slug,
                        "displayName": "dd-fleet",
                        "ttlHours": 24,
                        "identities": {
                            identity: {
                                "id": identity,
                                "secret": secret,
                                "displayName": "ddfleet-browser",
                                "addedAt": "2026-01-01T00:00:00.000Z",
                            }
                        },
                        "activeIdentity": identity,
                    }
                },
            }
            state = {
                "cookies": [],
                "origins": [
                    {
                        "origin": self.url,
                        "localStorage": [
                            {"name": "deadrop_credentials", "value": json.dumps(creds)}
                        ],
                    }
                ],
            }
        ctx = self.browser.new_context(service_workers="block", storage_state=state)
        return self._page(name, ctx)

    def _page(self, name, ctx):
        """A fresh tab in ctx (localStorage is per context, so creds carry over)."""
        old = self.pages.get(name)
        page = ctx.new_page()
        page.alerts = []

        def on_dialog(d):
            page.alerts.append(d.message)
            try:
                d.dismiss()
            except Exception:  # noqa: BLE001 -- tab already navigating away
                pass

        page.on("dialog", on_dialog)
        self.pages[name] = page
        if old is not None:
            old.close()
        return page

    def claim(self, name, invite_url, pin):
        """Open the recovery link on join.html, type the PIN, accept."""
        page = self._page(name, self.pages[name].context)
        try:
            page.goto(invite_url)
            page.wait_for_selector("#pin-row:not(.hidden)", timeout=15000)
            page.fill("#pin-input", pin)
            page.click("#accept-btn")
            page.wait_for_url("**/app/**", timeout=15000)
            raw = page.evaluate("localStorage.getItem('deadrop_credentials')")
            ident = json.loads(raw)["namespaces"][self.slug]["identities"]
            for v in ident.values():
                VAULT.add("browser-secret", v["secret"])
            return True
        except Exception as e:  # noqa: BLE001
            log(f"browser claim failed: {type(e).__name__}: {str(e)[:200]}")
            return False

    def post(self, name, body, expect_seen=None):
        """Send from the app's room composer; report the POST status and any alert()."""
        page = self._page(name, self.pages[name].context)
        res = {"ok": False}
        try:
            page.goto(f"{self.url}/app/{self.slug}/room/{self.room}")
            page.wait_for_selector("#room-message-input", timeout=15000)
            if expect_seen:
                try:
                    page.wait_for_selector(f".room-message:has-text('{expect_seen}')", timeout=8000)
                    res["read_ok"] = True
                except Exception:  # noqa: BLE001
                    res["read_ok"] = False
            page.fill("#room-message-input", body)
            with page.expect_response(
                lambda r: r.request.method == "POST"
                and r.url.endswith(f"/rooms/{self.room}/messages"),
                timeout=15000,
            ) as info:
                page.click("#room-send-btn")
            resp = info.value
            res["status"] = resp.status
            if resp.status >= 400:
                detail = str(resp.json().get("detail", ""))
                res["retired"] = detail.startswith("credential_retired")
                deadline = time.time() + 8
                while not page.alerts and time.time() < deadline:
                    page.wait_for_timeout(200)
                res["alert_retired"] = any("credential was retired" in a for a in page.alerts)
            else:
                page.wait_for_selector(f".room-message:has-text('{body}')", timeout=10000)
                res["ok"] = True
        except Exception as e:  # noqa: BLE001
            res["error"] = VAULT.redact(f"{type(e).__name__}: {str(e)[:160]}")
        return res

    def try_push_subscribe(self, vapid_public):
        """Can headless Chromium mint a real push subscription? (needs a push service)"""
        ctx = self.browser.new_context(permissions=["notifications"])
        page = ctx.new_page()
        try:
            page.goto(f"{self.url}/app")
            out = page.evaluate(
                """async (key) => {
              try {
                const reg = await navigator.serviceWorker.register('/sw.js');
                await navigator.serviceWorker.ready;
                const pad = '='.repeat((4 - key.length % 4) % 4);
                const raw = atob((key + pad).replace(/-/g, '+').replace(/_/g, '/'));
                const k = Uint8Array.from(raw, c => c.charCodeAt(0));
                const sub = await reg.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: k});
                return {ok: true, host: new URL(sub.endpoint).host};
              } catch (e) { return {ok: false, error: String(e).slice(0, 160)}; }
            }""",
                vapid_public,
            )
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"}
        ctx.close()
        return out

    def close(self):
        try:
            self.browser.close()
        finally:
            self.pw.stop()
