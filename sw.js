/**
 * sw.js â€” Online Vault Service Worker
 *
 * Routing strategy:
 *  â€¢ Backend API calls        â†’ Always network-only (auth-bearing, never cached)
 *  â€¢ AI / chat endpoints      â†’ Network-only (never cachede)
 *  â€¢ Vault /docs/* blobs      â†’ Network-only; offline fallback via page IndexedDB
 *                               (features.js â†’ fetchVaultDocWithOfflineFallback)
 *  â€¢ Navigation (HTML pages)  â†’ Network-first, fall back to cached /index.html
 *  â€¢ Same-origin shell assets â†’ Cache-first, populate on first fetch
 *  â€¢ External CDN assets      â†’ Network-first, cache fallback
 *
 * Encrypted vault blobs are cached in IndexedDB by features.js.
 * The SW never tries to cache them to avoid auth/CORS complexity.
 *
 * Login-after-logout fix:
 *  The page sends CLEAR_SESSION via postMessage on logout.
 *  The SW purges the entire cache so the next page load is a clean
 *  network fetch â€” no stale authenticated shell is served.
 */

const CACHE = "online-vault-v33";   // bump this string to force a full cache refresh

const BACKEND_HOST = "backend.shinumaths989.workers.dev";

// Assets pre-cached at install time (app shell) â€” only files that exist on origin
const PRECACHE_URLS = [
  "/",
  "/index.html",
  "/auth.js",
  "/offline-auth.js",
  "/offline-ai.js",
  "/features.js",
  "/session.js",
  "/startup.js",
  "/vault-data.js",
  "/viewer.js",
  "/vault-ui.js"
];

// URL path fragments that must NEVER be cached (AI chat, streaming, live data)
const NEVER_CACHE_PATTERNS = [
  "/ai-chat",
  "/chat",
  "/openai",
  "/gemini",
  "/anthropic",
  "/stream"
];

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Install â€” pre-cache app shell assets
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
self.addEventListener("install", function(event) {
  event.waitUntil(
    caches.open(CACHE).then(function(cache) {
      // Use individual add() with per-item catches so a single missing
      // asset (e.g. /profile.png missing in dev) does not abort the whole install.
      return Promise.allSettled(
        PRECACHE_URLS.map(function(url) {
          return cache.add(url).catch(function(err) {
            console.warn("[SW] Precache miss:", url, err);
          });
        })
      );
    })
  );
  self.skipWaiting();
});

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Activate â€” purge any old caches, claim clients immediately
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
self.addEventListener("activate", function(event) {
  event.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys
          .filter(function(key) { return key !== CACHE; })
          .map(function(key) {
            // console.log("[SW] Removing old cache:", key);
            return caches.delete(key);
          })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Fetch â€” routing
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
self.addEventListener("fetch", function(event) {
  var request = event.request;
  var url     = new URL(request.url);

  // Only handle HTTP/HTTPS
  if (url.protocol !== "http:" && url.protocol !== "https:") return;

  // Only handle GET (POST/PUT/DELETE go straight to network)
  if (request.method !== "GET") return;

  // 1. Backend API â€” always network-only (auth tokens, never cache)
  if (url.hostname === BACKEND_HOST) {
    // /docs/* offline fallback: return a detectable 503 so the page's
    // fetchVaultDocWithOfflineFallback() can read from IndexedDB instead.
    if (url.pathname.startsWith("/docs/")) {
      // Let the fetch fail naturally when offline.
      // viewer.js catches the TypeError and reads from IndexedDB.
      // The old 503 JSON response was being thrown as an Error by
      // viewer.js, bypassing the IndexedDB fallback entirely.
      return; // passthrough â€” no SW interception
    }
    // All other backend calls: pure network passthrough
    return;
  }

  // 2. AI / chat endpoints â€” network-only, no cache at all
  var neverCache = NEVER_CACHE_PATTERNS.some(function(p) {
    return url.pathname.includes(p);
  });
  if (neverCache) {
    event.respondWith(fetch(request));
    return;
  }

  // 3. Non-same-origin requests (CDN fonts, scripts, etc.) â€” network-first, cache fallback
  if (url.origin !== self.location.origin) {
    event.respondWith(networkFirst(request));
    return;
  }

  // 4. Navigation (HTML pages) â€” network-first so a fresh login page is always served
  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request));
    return;
  }

  // SW script â€” always network-first for updates
  if (url.pathname === "/sw.js") {
    event.respondWith(networkFirst(request));
    return;
  }

  // 5. Same-origin shell assets (JS, CSS, images) â€” stale-while-revalidate.
  // Serves the cached copy instantly, but always re-fetches in the background
  // and updates the cache, so a stale vault-data.js/auth.js/etc. only ever
  // lasts one page load instead of persisting indefinitely until someone
  // remembers to bump CACHE.
  event.respondWith(staleWhileRevalidate(request));
});

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Strategies
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE);
  const cached = await cache.match(request);

  const networkFetch = fetch(request).then(function(response) {
    if (isCacheable(response)) {
      cache.put(request, response.clone());
    }
    return response;
  }).catch(function() {
    return null; // network failed â€” caller falls back to cached version below
  });

  if (cached) {
    // Kick off the revalidation but don't block on it.
    networkFetch;
    return cached;
  }

  // Nothing cached yet â€” must wait for network.
  const fresh = await networkFetch;
  if (fresh) return fresh;

  return new Response("Offline", {
    status: 503,
    headers: { "Content-Type": "text/plain" }
  });
}

async function networkFirst(request) {
  try {
    var response = await fetch(request);
    if (isCacheable(response)) {
      var cache = await caches.open(CACHE);
      await cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    var cached = await caches.match(request);
    if (cached) return cached;

    // For navigation requests serve the cached shell so the app still loads
    if (request.mode === "navigate") {
      var fallback = await caches.match("/index.html");
      if (fallback) return fallback;
    }

    return new Response("Offline", {
      status: 503,
      headers: { "Content-Type": "text/plain" }
    });
  }
}

function isCacheable(response) {
  if (!response || !response.ok) return false;
  var type = response.type;
  return type === "basic" || type === "default";
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Message handler
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
self.addEventListener("message", function(event) {
  if (!event.data) return;

  // Only accept messages from same-origin pages
  if (event.source && event.source.location && event.source.location.origin !== self.location.origin) {
    console.warn("[SW] Ignoring message from untrusted origin:", event.source.location.origin);
    return;
  }

  switch (event.data.type) {

    // Force the waiting SW to activate immediately (useful after updates)
    case "SKIP_WAITING":
      self.skipWaiting();
      break;

    // Called by the page on logout â€” wipes the entire cache so the next
    // page load fetches a fresh unauthenticated shell from the network.
    // This is the fix for "login doesn't work after logout".
    case "CLEAR_SESSION":
      caches.delete(CACHE).then(function() {
        console.log("[SW] Cache cleared on logout");
        if (event.source) {
          event.source.postMessage({ type: "SESSION_CLEARED" });
        }
      });
      break;

    // Manual full cache clear (dev / debug use)
    case "CLEAR_CACHE":
      caches.delete(CACHE).then(function() {
        if (event.source) {
          event.source.postMessage({ type: "CACHE_CLEARED" });
        }
      });
      break;
  }
});





















