"""
Playwright test: room images load lazily and repeat loads come from the
service worker's attachment cache.

Drives a real uvicorn server with a real database and a real service worker:

1. Opening a room with more images than fit on screen fetches only the images
   near the viewport, as raw bytes, never as base64 JSON.
2. Once the service worker controls the page, a reload serves every image from
   its cache without a network fetch.
3. Removing the credentials deletes the cache.
"""

import base64
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zlib

import pytest

from playwright.sync_api import sync_playwright

pytestmark = pytest.mark.integration

REPO_ROOT = pathlib.Path(__file__).parent.parent
ADMIN_TOKEN = "test-admin-token"
IMAGE_COUNT = 20
ATTACHMENT_CACHE = "deadrop-attachments-v1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(url: str, body: dict, headers: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def _png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    rows = b"".join(b"\x00" + b"\x80\x40\x20" * width for _ in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


@pytest.fixture(scope="module")
def live_server():
    port = _free_port()
    db_path = f"/tmp/deadrop-attachment-cache-{port}.db"
    if os.path.exists(db_path):
        os.unlink(db_path)
    env = {**os.environ, "DEADROP_DB": db_path, "DEADROP_ADMIN_TOKEN": ADMIN_TOKEN}
    env.pop("HEARE_AUTH_URL", None)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "deadrop.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(proc.stdout.read().decode(errors="replace"))
        try:
            with urllib.request.urlopen(f"{base}/health", timeout=1):
                break
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("server did not become healthy")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def image_room(live_server):
    """A room whose newest IMAGE_COUNT messages each carry a tall image."""
    admin = {"X-Admin-Token": ADMIN_TOKEN}
    slug = f"cache-{uuid.uuid4().hex[:8]}"
    ns = _post(f"{live_server}/admin/namespaces", {"slug": slug, "ttl_hours": 24}, admin)
    viewer = _post(f"{live_server}/admin/{ns['ns']}/identities", {"metadata": {}}, admin)
    sender = _post(f"{live_server}/admin/{ns['ns']}/identities", {"metadata": {}}, admin)
    room = _post(f"{live_server}/{ns['ns']}/rooms", {}, {"X-Inbox-Secret": viewer["secret"]})
    _post(
        f"{live_server}/{ns['ns']}/rooms/{room['room_id']}/members",
        {"identity_id": sender["id"]},
        {"X-Inbox-Secret": viewer["secret"]},
    )
    data = base64.b64encode(_png(300, 600)).decode()
    for i in range(IMAGE_COUNT):
        _post(
            f"{live_server}/{ns['ns']}/rooms/{room['room_id']}/messages",
            {
                "body": f"image {i}",
                "attachments": [
                    {"filename": f"img-{i}.png", "content_type": "image/png", "data": data}
                ],
            },
            {"X-Inbox-Secret": sender["secret"]},
        )
    credentials = {
        "version": 1,
        "namespaces": {
            slug: {
                "ns": ns["ns"],
                "slug": slug,
                "displayName": "Cache",
                "ttlHours": 24,
                "identities": {
                    viewer["id"]: {
                        "id": viewer["id"],
                        "secret": viewer["secret"],
                        "displayName": "Viewer",
                        "addedAt": "2026-01-01T00:00:00.000Z",
                    }
                },
                "activeIdentity": viewer["id"],
            }
        },
    }
    return {"path": f"/app/{slug}/room/{room['room_id']}", "credentials": credentials}


def _settle(page, ms: int = 1500) -> None:
    page.wait_for_selector("#room-message-list .room-message")
    page.wait_for_timeout(ms)


def test_room_images_load_lazily_then_from_cache(live_server, image_room):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            viewport={"width": 390, "height": 844},
            storage_state={
                "cookies": [],
                "origins": [
                    {
                        "origin": live_server,
                        "localStorage": [
                            {
                                "name": "deadrop_credentials",
                                "value": json.dumps(image_room["credentials"]),
                            }
                        ],
                    }
                ],
            },
        )
        page = context.new_page()
        page_requests: list = []
        sw_requests: list = []
        page.on("request", lambda r: page_requests.append(r))
        context.on(
            "request", lambda r: sw_requests.append(r) if r.service_worker is not None else None
        )

        page.goto(f"{live_server}{image_room['path']}")
        _settle(page)

        attachment_urls = [r.url for r in page_requests if "/attachments/" in r.url]
        assert attachment_urls, "no image was fetched"
        assert all(u.endswith("/download") for u in attachment_urls), attachment_urls
        assert len(set(attachment_urls)) < IMAGE_COUNT, "every image was fetched up front"

        page.wait_for_function("navigator.serviceWorker.controller !== null")
        # Warm the cache through the controlling worker, then measure a reload.
        page.reload()
        _settle(page)
        page_requests.clear()
        sw_requests.clear()
        page.reload()
        _settle(page)

        downloads = [r for r in page_requests if r.url.endswith("/download")]
        assert downloads, "no image was requested on reload"
        for r in downloads:
            assert r.response().from_service_worker, r.url
        assert not [r for r in sw_requests if r.url.endswith("/download")], (
            "the service worker went to the network for a cached image"
        )
        cached = page.evaluate(
            f"caches.open('{ATTACHMENT_CACHE}').then(c => c.keys()).then(k => k.length)"
        )
        assert cached >= len({r.url for r in downloads})

        page.evaluate("CredentialStore.clear()")
        page.wait_for_function(f"caches.has('{ATTACHMENT_CACHE}').then(h => !h)")
        browser.close()
