"""One (re)start of a store-driven agent using the real deadrop python client.

Reads its bundle from the throwaway credential store on every start, then
posts one message and reads the room back. Prints one JSON line, no secrets.

usage: pyclient_op.py <credential-name> <body>
"""

import json
import os
import sys
import urllib.request

from deadrop.backends import AuthenticationError, DeaddropAPIError
from deadrop.client import Deaddrop

store = os.environ["DDFLEET_CREDSTORE"].rstrip("/")
cred, body = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(f"{store}/api/credentials/{cred}", timeout=5) as r:
    bundle = json.loads(r.read())["data"]

out = {"ok": False}
try:
    with Deaddrop.remote(url=bundle["url"]) as dd:
        sent = dd.send_room_message(bundle["namespace"], bundle["room_id"], bundle["secret"], body)
        msgs = dd.get_room_messages(
            bundle["namespace"], bundle["room_id"], bundle["secret"], limit=500
        )
    out = {
        "ok": True,
        "mid": sent["mid"],
        "mids": [m["mid"] for m in msgs],
        "seen_body": any(m["body"] == body for m in msgs),
    }
except AuthenticationError as e:
    out = {"ok": False, "status": e.status_code, "retired": "credential_retired" in str(e)}
except DeaddropAPIError as e:
    out = {"ok": False, "status": e.status_code, "error": type(e).__name__}
print(json.dumps(out))
