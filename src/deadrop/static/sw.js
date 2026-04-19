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

const CACHE_NAME = 'deadrop-shell-v2';
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
