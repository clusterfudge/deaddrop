#!/usr/bin/env python3
"""Integration test: send and receive image attachments.

Starts a local deaddrop server, creates a namespace/room, sends a message
with an image attachment, fetches it back, and verifies the round-trip.
"""

import base64
import os
import struct
import sys
import threading
import time
import zlib

import httpx
import uvicorn

# Ensure we use the local source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

os.environ["DEADROP_ADMIN_TOKEN"] = "test-admin-token"
os.environ["DEADROP_DB"] = ":memory:"


def make_test_png() -> bytes:
    """Create a 2x2 red/blue PNG for testing."""

    def chunk(ctype, data):
        c = ctype + data
        crc = struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        return struct.pack(">I", len(data)) + c + crc

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    # 2x2 RGB: red, green, blue, white (with filter bytes)
    scanlines = b"\x00\xff\x00\x00\x00\xff\x00" + b"\x00\x00\x00\xff\xff\xff\xff"
    idat = zlib.compress(scanlines)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def main():
    from deadrop.api import app

    # Start server in background thread
    config = uvicorn.Config(app, host="127.0.0.1", port=18999, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to be ready
    base = "http://127.0.0.1:18999"
    for _ in range(50):
        try:
            httpx.get(f"{base}/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        print("FAIL: Server didn't start")
        sys.exit(1)

    client = httpx.Client(base_url=base, timeout=10)
    admin = {"X-Admin-Token": "test-admin-token"}

    # 1. Create namespace
    ns_resp = client.post("/admin/namespaces", headers=admin).json()
    ns = ns_resp["ns"]
    ns_secret = ns_resp["secret"]
    print(f"✓ Namespace: {ns}")

    # 2. Create identity
    alice = client.post(
        f"/{ns}/identities",
        headers={"X-Namespace-Secret": ns_secret},
        json={"metadata": {"display_name": "Alice"}},
    ).json()
    alice_headers = {"X-Inbox-Secret": alice["secret"]}
    print(f"✓ Identity: {alice['id'][:8]}")

    # 3. Create room
    room = client.post(
        f"/{ns}/rooms",
        headers=alice_headers,
        json={"display_name": "Image Test Room"},
    ).json()
    room_id = room["room_id"]
    print(f"✓ Room: {room_id[:8]}")

    # 4. Send message with image attachment
    png_bytes = make_test_png()
    png_b64 = base64.b64encode(png_bytes).decode()

    send_resp = client.post(
        f"/{ns}/rooms/{room_id}/messages",
        headers=alice_headers,
        json={
            "body": "Check out this test image!",
            "content_type": "text/markdown",
            "attachments": [
                {
                    "filename": "test.png",
                    "content_type": "image/png",
                    "data": png_b64,
                }
            ],
        },
    )
    assert send_resp.status_code == 200, f"Send failed: {send_resp.text}"
    msg = send_resp.json()
    assert msg["attachments"] is not None
    assert len(msg["attachments"]) == 1
    att_info = msg["attachments"][0]
    att_id = att_info["id"]
    print(f"✓ Sent message with attachment: {att_id[:8]}")
    print(
        f"  filename={att_info['filename']}, type={att_info['content_type']}, size={att_info['size']}"
    )

    # 5. List messages — should include attachment metadata
    list_resp = client.get(f"/{ns}/rooms/{room_id}/messages", headers=alice_headers)
    assert list_resp.status_code == 200
    messages = list_resp.json()["messages"]
    assert len(messages) == 1
    assert messages[0]["attachments"] is not None
    assert len(messages[0]["attachments"]) == 1
    assert "data" not in messages[0]["attachments"][0]  # No data in list!
    print("✓ Listed messages — attachment metadata present, data omitted")

    # 6. Fetch full attachment with data
    fetch_resp = client.get(f"/{ns}/attachments/{att_id}", headers=alice_headers)
    assert fetch_resp.status_code == 200
    att_data = fetch_resp.json()
    assert att_data["data"] == png_b64
    assert att_data["content_type"] == "image/png"
    assert att_data["filename"] == "test.png"
    round_trip_bytes = base64.b64decode(att_data["data"])
    assert round_trip_bytes == png_bytes
    print(f"✓ Fetched attachment — data round-trips perfectly ({len(round_trip_bytes)} bytes)")

    # 7. Send message with multiple attachments
    jpeg_b64 = base64.b64encode(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9").decode()
    multi_resp = client.post(
        f"/{ns}/rooms/{room_id}/messages",
        headers=alice_headers,
        json={
            "body": "Multiple files",
            "attachments": [
                {"filename": "photo.png", "content_type": "image/png", "data": png_b64},
                {"filename": "thumb.jpg", "content_type": "image/jpeg", "data": jpeg_b64},
            ],
        },
    )
    assert multi_resp.status_code == 200
    assert len(multi_resp.json()["attachments"]) == 2
    print(f"✓ Multiple attachments work ({len(multi_resp.json()['attachments'])})")

    # 8. Verify Anthropic-compatible shape
    # This is what harness1 would construct from the attachment
    anthropic_image_block = {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": att_data["content_type"],
            "data": att_data["data"],
        },
    }
    assert anthropic_image_block["source"]["media_type"] == "image/png"
    assert len(anthropic_image_block["source"]["data"]) > 0
    print("✓ Anthropic image block shape validated")

    print("\n🎉 All integration tests passed!")
    server.should_exit = True


if __name__ == "__main__":
    main()
