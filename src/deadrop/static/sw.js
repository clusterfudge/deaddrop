// Deadrop service worker — minimal, offline-tolerant shell caching.
//
// Strategy:
//   - Cache the app shell (HTML templates + static JS/CSS) on install.
//   - Network-first for same-origin GET requests; fall back to cache.
//   - Skip API requests (anything under /{ns}/send, /inbox, /admin) — those
//     must always hit the network (fresh state + auth).
//   - Don't cache POST/PUT/DELETE or cross-origin requests.

const CACHE_NAME = 'deadrop-shell-v1';
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
const NO_CACHE_PATTERNS = [
  /^\/admin(\/|$)/,
  /^\/[^/]+\/send$/,
  /^\/[^/]+\/inbox/,
  /^\/[^/]+\/identities/,
  /^\/[^/]+\/archive$/,
  /^\/events/,
  /^\/health$/,
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
