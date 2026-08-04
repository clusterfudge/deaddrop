# Web Push

Deaddrop can deliver notifications to an installed PWA (iOS/iPadOS ≥ 16.4)
and to desktop browsers using standards-based Web Push. There is no Apple
Developer Program membership involved and no third-party notification
service: the server signs and encrypts the payload itself and POSTs it to
the endpoint the browser handed out.

The feature is **off by default**. Nothing below runs until
`DEADROP_PUSH_ENABLED` is set and a VAPID keypair is present.

---

## When a push is sent

A room message notifies each recipient **immediately**, then opens a
**two-minute cooldown** for that recipient. Messages arriving inside the
window are folded into a single follow-up push delivered when the window
expires — its body reads `latest message (+N more)` — and that follow-up
opens the next window. A window that ends quiet sends nothing and closes
the throttle, so the next message is again immediate.

Before each delivery the server re-reads that recipient's read cursor:

| Cursor state | Result |
|---|---|
| absent | unread → push |
| valid UUIDv7, older than the message | unread → push |
| valid UUIDv7, at or past the message | caught up → silent |
| present but not a UUIDv7 | unknowable → silent |

The last row is deliberate. A non-v7 cursor cannot be ordered against a v7
message id, so treating it as "never seen" would leave the room
permanently unread and push on every message forever.

Two further reasons not to send, checked at each delivery:

* **Switched off.** The identity set `enabled: false` via
  `PUT /{ns}/push/prefs`.
* **No devices.** The identity holds no subscriptions.

The read cursor is the only staleness signal. An open connection on
`/{ns}/subscribe` does not suppress anything — an identity routinely holds
several idle browser tabs, and none of them imply the message was seen. A
client that actually renders the message advances its cursor, and that
drops the coalesced follow-up.

Reactions never notify, and a sender is never notified about its own
message. A reaction is dropped before the throttle sees it, so it neither
fires a push nor counts toward the `(+N more)` on a follow-up. The badge
number is the exception: it comes from the same unread query the room list
uses, which counts reactions.

The windows are in-process (the deployment runs a single uvicorn worker).
**A restart loses whatever follow-up was pending**; those messages stay unread and the next message in the room
notifies immediately.

---

## Generating a VAPID keypair

```bash
uv run python -m deadrop.push
```

Output:

```
DEADROP_VAPID_PUBLIC_KEY=BB1c…
DEADROP_VAPID_PRIVATE_KEY=k9F…
DEADROP_VAPID_SUBJECT=mailto:you@example.com
```

Set the subject to a real `mailto:` or `https://` URL you control. Apple's
push service rejects a JWT whose `sub` claim is missing or is not a URL
with `403 BadJwtToken`, and that is the single most common failure when
bringing Web Push up.

**Rotating the keypair invalidates every existing subscription.** Every
device has to re-subscribe. Treat the keys as permanent and store them
like any other secret.

Deploy them:

```bash
ssh dokku@h1.dokku.heare.io config:set deaddrop \
  DEADROP_PUSH_ENABLED=1 \
  DEADROP_VAPID_PUBLIC_KEY=… \
  DEADROP_VAPID_PRIVATE_KEY=… \
  DEADROP_VAPID_SUBJECT=mailto:you@example.com
```

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DEADROP_PUSH_ENABLED` | unset (off) | Master switch. |
| `DEADROP_VAPID_PUBLIC_KEY` | — | base64url of the uncompressed P-256 point (65 bytes). |
| `DEADROP_VAPID_PRIVATE_KEY` | — | base64url of the raw P-256 scalar (32 bytes). |
| `DEADROP_VAPID_SUBJECT` | — | `mailto:` or `https://` URL. |
| `DEADROP_PUSH_DEBOUNCE_SECONDS` | `120` | Cooldown window — how long after a push messages coalesce before the next one goes out. |
| `DEADROP_PUSH_TTL_SECONDS` | `3600` | `TTL` header — how long the push service may hold an undelivered message. |

All three keys plus the subject must be present; with any one missing the
server logs a warning at startup and stays off.

Egress to `*.push.apple.com`, `*.push.services.mozilla.com` and
`fcm.googleapis.com` must be allowed.

---

## Subscribing from a device

Web Push is only exposed to an **installed** web app on iOS — in a Safari
tab `window.PushManager` does not exist. The toggle in the namespace
header is therefore hidden on iOS until the app is on the Home Screen.

1. Open the site in Safari, Share → **Add to Home Screen**.
2. Launch from the Home Screen icon.
3. Open a namespace and tap 🔕 in the header.
4. Accept the permission prompt.

Verify without waiting for real traffic:

```bash
curl -X POST -H "X-Inbox-Secret: $SECRET" \
  https://deaddrop.dokku.heare.io/$NS/push/test
```

---

## API

| Route | Auth | Purpose |
|---|---|---|
| `GET /push/vapid-public-key` | none | Feature flag + `applicationServerKey`. |
| `POST /{ns}/push/subscriptions` | `X-Inbox-Secret` | Register a device. |
| `GET /{ns}/push/subscriptions` | `X-Inbox-Secret` | List your devices (no key material). |
| `DELETE /{ns}/push/subscriptions?endpoint=…` | `X-Inbox-Secret` | Remove one device. |
| `GET /{ns}/push/prefs` | `X-Inbox-Secret` | Read the identity switch and the badge count. |
| `PUT /{ns}/push/prefs` | `X-Inbox-Secret` | Turn push on/off for this identity everywhere. |
| `POST /{ns}/push/test` | `X-Inbox-Secret` | Send a test notification to all your devices. |

Subscriptions are keyed on the endpoint URL, so one identity may hold
several — a laptop, a phone, and a second install of the same PWA are
three rows. A `404` or `410` from the push service deletes the row.

---

## Payload shape

The server always emits a Declarative Web Push envelope:

```json
{
  "web_push": 8030,
  "notification": {
    "title": "sean in twin",
    "body": "PR #78 is green, merging",
    "navigate": "https://deaddrop.dokku.heare.io/app/twin/room/0698e39d-…",
    "tag": "room:0698e39d-…",
    "app_badge": 3
  }
}
```

iOS ≥ 18.4 renders this with no service worker involvement; iOS 16.4–18.3
and other browsers dispatch it to the `push` handler in `sw.js`, which
reads the same fields. One payload serves both.

`userVisibleOnly` is mandatory — iOS revokes a subscription that receives
a push without showing a notification. There is no silent push.

---

## Preferences and the badge

The switch is **one boolean per identity** (`push_prefs`), not per room and
not per device. Turning it off leaves the subscription rows in place, so
turning it back on does not require the permission gesture again. An
identity with no row is enabled — registering a device is the opt-in.

`app_badge` is a single integer: every unread room message for that
identity, across every room, defined once in
`db.count_unread_for_identity` and reused by both the push payload and
`GET /{ns}/push/prefs`. The client mirrors it onto the app icon with
`setAppBadge()` after a read-cursor update, and the service worker applies
it on iOS 16.4–18.3 where the OS does not.

A subscription endpoint belongs to one (namespace, identity) pair, so a
device signed into two namespaces badges the one it subscribed with. That
is the multi-namespace caveat the badge's one-integer shape forces.

---

## What this does not do

* **1:1 messages.** Only room messages notify. Direct messages track
  read state with `read_at` rather than a cursor and are not wired up.
* **Per-room mute / quiet hours.** The switch is global per identity.
* **Durable throttling.** Pending follow-ups live in the worker process.
