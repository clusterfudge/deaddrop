// Deadrop service worker — minimal, offline-tolerant shell caching.
//
// Strategy:
//   - Cache the app shell (HTML templates + static JS/CSS) on install.
//   - Network-first for same-origin GET requests; fall back to cache.
//   - Skip all API/dynamic routes — those must always hit the network
//     (fresh state + auth). See NO_CACHE_PATTERNS below.
//   - Don't cache POST/PUT/DELETE or cross-origin requests.
//
// Cache version: bump CACHE_NAME when shell assets change to force update.

const CACHE_NAME = 'deadrop-shell-v4';
const APP_SHELL = [
  '/app',
  '/static/css/style.css',
  '/static/js/api.js',
  '/static/js/crypto.js',
  '/static/js/credentials.js',
  '/manifest.webmanifest',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) =>
        // Add each URL individually so one 404 doesn't poison the whole install.
        Promise.all(
          APP_SHELL.map((url) =>
            cache.add(url).catch((err) => {
              console.warn('[sw] precache miss:', url, err.message);
            }),
          ),
        ),
      )
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Paths that should always bypass cache (API + dynamic data).
//
// Deaddrop API route map (GET endpoints that must be fresh):
//   /admin/**                      — admin API
//   /api/invites/**                — invite lookup (dynamic)
//   /{ns}/inbox/**                 — message inbox (dynamic)
//   /{ns}/identities/**            — identity directory (dynamic)
//   /{ns}/invites/**               — invite list (dynamic)
//   /{ns}/rooms/**                 — room list + messages + unread (dynamic)
//   /{ns}/attachments/**           — binary attachment data (dynamic)
//   /{ns}/push/**, /push/**        — push subscription state + VAPID key
//   /health, /metrics              — ops endpoints
//
// HTML shell routes (/app/**, /, /join/**) are intentionally cacheable
// because they're the server-rendered shell, not live data.
const NO_CACHE_PATTERNS = [
  /^\/admin(\/|$)/,
  /^\/api\//,
  /^\/[^/]+\/send$/,
  /^\/[^/]+\/inbox(\/|$)/,
  /^\/[^/]+\/identities(\/|$)/,
  /^\/[^/]+\/invites(\/|$)/,
  /^\/[^/]+\/rooms(\/|$)/,
  /^\/[^/]+\/attachments(\/|$)/,
  /^\/[^/]+\/push(\/|$)/,
  /^\/push(\/|$)/,
  /^\/health$/,
  /^\/metrics$/,
];

function shouldBypass(path) {
  return NO_CACHE_PATTERNS.some((re) => re.test(path));
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (shouldBypass(url.pathname)) return;

  event.respondWith(
    fetch(request)
      .then((response) => {
        // Only cache successful, non-opaque responses.
        if (response.ok && response.type === 'basic') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
        }
        return response;
      })
      .catch(() =>
        caches.match(request).then((cached) => {
          if (cached) return cached;
          // Offline navigation fallback → serve /app shell if available.
          if (request.mode === 'navigate') {
            return caches.match('/app');
          }
          return new Response('offline', { status: 503, statusText: 'offline' });
        }),
      ),
  );
});

// Notify open clients when a new SW version is waiting to activate.
// The UI can listen for this and show a "Reload to update" banner.
self.addEventListener('message', (event) => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }
});

// --- Web Push ---
//
// The server sends a Declarative Web Push envelope:
//
//   { "web_push": 8030,
//     "notification": { "title", "body", "navigate", "tag", "app_badge" } }
//
// iOS >= 18.4 and Safari 18.4 render that envelope themselves and never
// run this handler. Everything older (including iOS 16.4-18.3, the floor
// for Web Push in an installed web app) dispatches it here, so both
// generations are served by one payload shape.

self.addEventListener('push', (event) => {
  let envelope = {};
  try {
    envelope = event.data ? event.data.json() : {};
  } catch (err) {
    envelope = { notification: { body: event.data ? event.data.text() : '' } };
  }

  const n = envelope.notification || envelope || {};
  const navigateTo = n.navigate || '/app';

  // userVisibleOnly is mandatory on iOS: failing to show a notification
  // for a delivered push revokes the subscription.
  event.waitUntil(
    (async () => {
      await self.registration.showNotification(n.title || 'Deadrop', {
        body: n.body || '',
        tag: n.tag || 'deadrop',
        icon: '/static/icons/icon-192.png',
        badge: '/static/icons/icon-192.png',
        data: { navigate: navigateTo },
      });

      // app_badge is applied by the OS on iOS >= 18.4, which never reaches
      // this handler; here it has to be applied explicitly.
      if (n.app_badge !== undefined && n.app_badge !== null && 'setAppBadge' in navigator) {
        const count = Number(n.app_badge);
        if (count > 0) {
          await navigator.setAppBadge(count);
        } else {
          await navigator.clearAppBadge();
        }
      }
    })(),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const target = new URL(
    (event.notification.data && event.notification.data.navigate) || '/app',
    self.location.origin,
  );

  // Focus an existing window when one is open — on iOS that is the
  // installed web app, which is the whole point of owning the
  // notification instead of routing through a third-party app.
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const client of windows) {
        if (new URL(client.url).origin !== target.origin) continue;
        await client.focus();
        if ('navigate' in client) {
          try {
            await client.navigate(target.href);
          } catch (err) {
            client.postMessage({ type: 'navigate', url: target.href });
          }
        } else {
          client.postMessage({ type: 'navigate', url: target.href });
        }
        return;
      }
      await self.clients.openWindow(target.href);
    })(),
  );
});
