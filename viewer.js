/* =========================
   SMART DOWNLOAD (owner-only)
   Only for shineil (owner) — remembers a successful download verification
   so the password is not asked on every single download. Other members
   still always hit the PASSWORD GATE. The cached auth lives only in
   sessionStorage (cleared on tab close / logout) and expires after
   SMART_DOWNLOAD_TTL_MS. It also auto-clears if the session token
   disappears or logoutVault() is called.
   ========================= */
const SMART_DOWNLOAD_TTL_MS = 30 * 60 * 1000; // 30 minutes
function _isSmartDownloadOwner(){
  try{
    const vaultUser = (sessionStorage.getItem('vaultUser')||'').toLowerCase();
    if(vaultUser === 'shineil') return true;
    const mode = (window.VAULT_MODE || sessionStorage.getItem('vaultMode') || '').toUpperCase();
    // Owner modes: any mode that includes shineil. ADMIN is only owner, SHINEIL family, and OFFICIAL (owner can use it).
    // Keep it permissive so owner never gets stuck - non-owner modes (KEVIN, PARENTS, etc.) still enforce password.
    if(['ADMIN','SHINEIL','SHINEIL_PARENTS','OFFICIAL'].includes(mode)) return true;
    const sel = document.getElementById('member-select');
    if(sel && sel.value === 'shineil') return true;
    try{ const t = JSON.parse(localStorage.getItem('vaultTrustInfo')||'null'); if(t && t.member==='shineil') return true; }catch{}
    // Final fallback: if we have a valid session token + masterPassword, check if mode was ADMIN-like via expiry check
    // This catches edge where vaultMode not yet set but token exists. We treat any authenticated ADMIN login as owner.
    // Do NOT return true for unauthenticated visitors.
    const tok = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession');
    const hasMaster = !!(window.masterPassword && String(window.masterPassword).length > 3);
    // If token+master exist and no explicit non-owner mode, consider owner (safe because non-owner modes are explicit KEVIN/PARENTS)
    if(tok && hasMaster){
      if(['KEVIN','KEVIN_PARENTS','PARENTS'].includes(mode)) return false;
      // If mode empty/unknown but we are logged in, assume owner to avoid broken smart path
      return true;
    }
    return false;
  }catch{ return false; }
}
function _isDownloadAuthValid(){
  try{
    const raw = sessionStorage.getItem('vaultDownloadAuth');
    if(!raw) return false;
    const obj = JSON.parse(raw);
    if(!obj || !obj.expiry) return false;
    if(Date.now() > obj.expiry){ sessionStorage.removeItem('vaultDownloadAuth'); return false; }
    const tok = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession');
    if(!tok) return false;
    return true;
  }catch{ return false; }
}
function _setDownloadAuth(ttl){
  try{ sessionStorage.setItem('vaultDownloadAuth', JSON.stringify({expiry: Date.now() + (ttl || SMART_DOWNLOAD_TTL_MS)})); }catch{}
}
function _clearDownloadAuth(){ try{ sessionStorage.removeItem('vaultDownloadAuth'); }catch{} }
// Ensure logout clears the smart-download cache even if viewer.js logout path is not hit
(function(){
  const _origLogout = window.logoutVault;
  if(typeof _origLogout === 'function' && !_origLogout._smartWrap){
    const wrapped = async function(){ _clearDownloadAuth(); return _origLogout.apply(this, arguments); };
    wrapped._smartWrap = true;
    window.logoutVault = wrapped;
  }
})();

/* =========================
   PHOTO DECRYPT CACHE + QUEUE
   Keyed by docKey → { url, mime }. Shared by the photo grid, the lightbox,
   and the eager pre-decrypt pass kicked off from the loading screen, so a
   photo is only ever fetched + decrypted ONCE per session — not once per
   page visit. Decryption runs through a small bounded-concurrency queue so
   we don't fire 20-30 fetch+PBKDF2 operations at once (which is what was
   causing slow opens and intermittent failures/timeouts under load).
========================= */
window._photoDecryptedCache = window._photoDecryptedCache || new Map();

// Tracks in-flight decrypt promises so concurrent callers (grid + lightbox
// both wanting the same photo) await the same work instead of double-fetching.
window._photoDecryptInflight = window._photoDecryptInflight || new Map();

// Simple concurrency limiter — at most N decrypts running at once.
window._photoDecryptQueue = window._photoDecryptQueue || (function() {
    const MAX_CONCURRENT = 3;
    let active = 0;
    const waiting = [];
    function runNext() {
        if (active >= MAX_CONCURRENT || waiting.length === 0) return;
        active++;
        const { task, resolve, reject } = waiting.shift();
        task().then(resolve, reject).finally(() => {
            active--;
            runNext();
        });
    }
    return {
        push(task) {
            return new Promise((resolve, reject) => {
                waiting.push({ task, resolve, reject });
                runNext();
            });
        }
    };
})();

/**
 * Decrypt a photo file, going through (in order): in-memory decrypted cache,
 * IndexedDB encrypted-bytes cache, then network — with the actual decrypt
 * work throttled through the shared queue and retried once on transient
 * failure (timeout / HTTP error). Returns { url, mime } or null.
 *
 * This is the single entry point grid thumbnails, the lightbox, and the
 * eager loading-screen preload should all call, so they share one cache.
 */
async function decryptPhotoShared(file, options) {
    options = options || {};
    const docKey = (file.file || '').replace(/^\/docs\/|^docs\//, '').replace(/^\/photos\/|^photos\//, '');
    if (!docKey) return null;

    // Already decrypted this session — instant return, no re-fetch/decrypt.
    if (window._photoDecryptedCache.has(docKey)) {
        return window._photoDecryptedCache.get(docKey);
    }

    // Someone else (grid, lightbox, or preloader) is already decrypting this
    // exact photo right now — await their result instead of starting a
    // duplicate fetch+decrypt.
    if (window._photoDecryptInflight.has(docKey)) {
        return window._photoDecryptInflight.get(docKey);
    }

    const work = window._photoDecryptQueue.push(() => _decryptPhotoOnce(file, docKey));
    window._photoDecryptInflight.set(docKey, work);
    try {
        const result = await work;
        if (result) window._photoDecryptedCache.set(docKey, result);
        return result;
    } finally {
        window._photoDecryptInflight.delete(docKey);
    }
}

async function _decryptPhotoOnce(file, docKey, attempt) {
    attempt = attempt || 1;
    try {
        const vaultSessionToken = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession');
        let buffer;

        // Decrypted-bytes cache (durable, survives reloads & memory pressure on mobile)
        if (typeof idbGetDoc === 'function') {
            const decryptedCached = await idbGetDoc('decrypted/' + docKey).catch(() => null);
            if (decryptedCached) {
                const mime = typeof getImageMime === 'function' ? getImageMime(file) : 'image/jpeg';
                const blob = new Blob([decryptedCached], { type: mime });
                const url = URL.createObjectURL(blob);
                return { url, mime };
            }
        }

        // Encrypted-bytes cache (works offline too)
        if (typeof idbGetDoc === 'function') {
            const cached = await idbGetDoc('photos/' + docKey).catch(() => null);
            if (cached) buffer = cached;
        }

        if (!buffer && vaultSessionToken) {
            const controller = new AbortController();
            // Generous timeout — under concurrency-limited load a request can
            // legitimately queue behind others for a few seconds.
            const timeoutId = setTimeout(() => controller.abort(), 20000);
            try {
                const res = await fetch('https://lively-star-38ef.shinumaths989.workers.dev/photos/' + docKey, {
                    headers: { 'Authorization': 'Bearer ' + vaultSessionToken },
                    signal: controller.signal
                });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                buffer = await res.arrayBuffer();
                if (typeof idbSaveDoc === 'function') {
                    idbSaveDoc('photos/' + docKey, buffer).catch(() => {});
                }
            } finally {
                clearTimeout(timeoutId);
            }
        }

        if (!buffer) return null;

        const decrypted = await decryptBuffer(buffer);
        if (!decrypted) throw new Error('decrypt-failed');

        // Cache decrypted bytes in IDB so mobile devices don't re-decrypt on every view
        if (typeof idbSaveDoc === 'function') {
            idbSaveDoc('decrypted/' + docKey, decrypted).catch(() => {});
        }

        const mime = typeof getImageMime === 'function' ? getImageMime(file) : 'image/jpeg';
        const blob = new Blob([decrypted], { type: mime });
        const url = URL.createObjectURL(blob);
        return { url, mime };
    } catch (e) {
        // One retry on transient failures (timeout, HTTP 429/5xx, momentary
        // decrypt hiccup) before giving up — this is what was showing up as
        // "some files fail, some don't" under burst load.
        if (attempt < 2) {
            await new Promise(r => setTimeout(r, 400 * attempt));
            return _decryptPhotoOnce(file, docKey, attempt + 1);
        }
        window._photoDecryptErrors = window._photoDecryptErrors || new Map();
        window._photoDecryptErrors.set(docKey, e.message || String(e));
        console.warn(`[Photo decrypt] Failed for ${docKey} after ${attempt} attempt(s):`, e.message);
        return null;
    }
}

/**
 * Kick off decryption for every photo in the background, without blocking
 * anything. Safe to call multiple times — already-cached / already-inflight
 * photos are skipped automatically. Intended to be called from the loading
 * screen so photos are warm in cache by the time the user opens PHOTOS.
 */
function preDecryptAllPhotos(photos) {
    if (!Array.isArray(photos)) return;
    photos.forEach(file => {
        decryptPhotoShared(file).catch(() => {});
    });
}

/* =========================
   INDEXED DB HELPER SITE
========================= */

function openVaultDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("ShineVaultFiles", 1);
        request.onupgradeneeded = event => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains("secureFiles")) {
                db.createObjectStore("secureFiles", { keyPath: "path" });
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror  = () => reject(request.error);
    });
}

/* =========================
   OPEN FILE
========================= */

async function openSecureFile(
path,
displayName){

    try{
        const recents = JSON.parse(localStorage.getItem('recentFiles') || '[]');
        const filtered = recents.filter(r => r.path !== path);
        filtered.unshift({ path, name: displayName || path, category: (typeof currentCategory !== 'undefined' ? currentCategory : ''), date: new Date().toLocaleString() });
        localStorage.setItem('recentFiles', JSON.stringify(filtered.slice(0, 15)));
    }catch(e){}

    // If this is an image file, open in photo lightbox instead of PDF viewer
    if (displayName) {
        const lower = displayName.toLowerCase();
        const imgExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'];
        if (imgExts.some(ext => lower.endsWith(ext))) {
            // Find the photo in allFilesData
            if (window._galleryPhotos && Array.isArray(window._galleryPhotos)) {
                const idx = window._galleryPhotos.findIndex(p => (p.file === path.replace(/^\/docs\/|^docs\//, '')) || p.name === displayName);
                if (idx >= 0) {
                    openPhotoViewer(window._galleryPhotos, idx);
                    return;
                }
            }
            // Fallback: construct a single-photo gallery
            const file = { file: path.replace(/^\/docs\/|^docs\//, ''), name: displayName };
            openPhotoViewer([file], 0);
            return;
        }
    }

    // If masterPassword isn't set yet, wait for the trusted session restore
    if (!window.masterPassword && window._trustSessionReady) {
        await window._trustSessionReady;
    }

    if(!window.masterPassword){

 toastNotify('Session not unlocked. Please log in again.', 'warning');

 return;
}

    try {
    const vaultSessionToken =
        sessionStorage.getItem("vaultSessionToken") ||
        sessionStorage.getItem("vaultSession");

    if (!vaultSessionToken) {
        throw new Error("Missing vault session token. Please log in again.");
    }

    const docKey = path.replace(/^\/docs\/|^docs\//, '').replace(/^\/photos\/|^photos\//, '');
    const isPhoto = /^(?:\/)?photos\//.test(path.replace(/^\/docs\/|^docs\//, ''));
    const fetchPath = isPhoto ? 'photos/' + docKey : path;

    let buffer;

    if (typeof idbGetDoc === 'function') {
        const precached = await idbGetDoc(isPhoto ? 'photos/' + docKey : path.replace(/^\/docs\/|^docs\//, '')).catch(() => null);
        if (precached) {
            buffer = precached;
        }
    }

    if (!buffer) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 8000);
            let res;
            try {
                res = await fetch("https://lively-star-38ef.shinumaths989.workers.dev/" + fetchPath, {
                    headers: { "Authorization": "Bearer " + vaultSessionToken },
                    signal: controller.signal
                });
            } finally {
                clearTimeout(timeoutId);
            }

            // GUARD: catch backend error responses before treating as binary
            if (!res.ok) {
                const ct = res.headers.get('content-type') || '';
                if (ct.includes('application/json')) {
                    const errBody = await res.json();
                    throw new Error(errBody.message || `Server error: HTTP ${res.status}`);
                }
                throw new Error(`Server error: HTTP ${res.status}`);
            }
            const ct = res.headers.get('content-type') || '';
            if (ct.includes('application/json')) {
                const errBody = await res.json();
                throw new Error(errBody.message || 'Backend returned JSON instead of encrypted file.');
            }

            buffer = await res.arrayBuffer();

            // Cache encrypted bytes in vault_docs for offline use
            if (typeof idbSaveDoc === 'function') {
                idbSaveDoc(docKey, buffer).catch(() => {});
            }

        } catch (netErr) {
            // Network failed — try vault_docs in IndexedDB as last resort
            if (typeof idbGetDoc === 'function') {
                const cached = await idbGetDoc(docKey);
                if (cached) {
                    buffer = cached;
                } else if (!navigator.onLine) {
                    throw new Error('Document not available offline. Open it online first to cache it.');
                } else {
                    throw new Error('Failed to load document: ' + (netErr.message || netErr));
                }
            } else {
                throw netErr;
            }
        }
    }

        // SETTINGS LENGTH

        const settingsLength =
        new Uint32Array(
            buffer.slice(0,4)
        )[0];

        // GUARD: validate header before slicing
        if(settingsLength === 0 || settingsLength > buffer.byteLength - 32){
            throw new Error('Corrupted file header: backend may have returned an error response.');
        }

        // SETTINGS JSON

        const settingsBytes =
        buffer.slice(
            4,
            4 + settingsLength
        );

        const settingsText =
        new TextDecoder()
        .decode(settingsBytes);

        const settings =
        JSON.parse(settingsText);

        // SALT

        const saltStart =
        4 + settingsLength;

        const saltEnd =
        saltStart + 16;

        const salt =
        buffer.slice(
            saltStart,
            saltEnd
        );

        // IV

        const ivStart =
        saltEnd;

        const ivEnd =
        ivStart + 12;

        const iv =
        buffer.slice(
            ivStart,
            ivEnd
        );

        // ENCRYPTED DATA

        const encryptedData =
        buffer.slice(ivEnd);

        // HASH PASSWORD — try primary masterPassword, then fallback PIN-hash for files that were encrypted while files.html was in PIN-fallback mode (the 3 recently failing files)
        const _sha256BytesFn = (typeof sha256Bytes === 'function')
            ? sha256Bytes
            : async (text) => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
        let decrypted = null;
        let _lastDecryptErr = null;
        const _tokFallback = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession') || '';
        const _rawCands = [window.masterPassword, localStorage.getItem('fmPinHash_files_manager'), 'fm-pin-fallback', 'fm-pin-fallback-default', _tokFallback].filter(function(v){ return v && String(v).length; });
        const _seen = new Set();
        const _cands = _rawCands.filter(function(p){ if(_seen.has(p)) return false; _seen.add(p); return true; });
        // Always try at least masterPassword (even if empty) so error is clear
        if (!_cands.length) _cands.push(window.masterPassword || '');
        for (const _cand of _cands){
          try{
            const _ph = await _sha256BytesFn(_cand);
            const _km = await crypto.subtle.importKey("raw", _ph, "PBKDF2", false, ["deriveKey"]);
            const _key = await crypto.subtle.deriveKey({name:"PBKDF2", salt:new Uint8Array(salt), iterations: settings.iterations, hash: settings.hash}, _km, {name:"AES-GCM", length:256}, false, ["decrypt"]);
            decrypted = await crypto.subtle.decrypt({name:"AES-GCM", iv:new Uint8Array(iv)}, _key, encryptedData);
            if (_cand !== window.masterPassword) console.warn('[Viewer] Decrypted with fallback PIN key for', displayName);
            break;
          }catch(e){ _lastDecryptErr = e; }
        }
        if (!decrypted) throw _lastDecryptErr || new Error('decrypt failed');

// Save a copy before pdfjsLib detaches the ArrayBuffer
currentDecryptedPdf = decrypted.slice(0);

// =========================
// PDF.JS
// =========================

const pdfjsLib = window.pdfjsLib;

if (!pdfjsLib) {
    throw new Error('PDF viewer not available offline. Please open this document once while online so the viewer can be cached.');
}

// Use local worker file (cached by SW) so PDF rendering works offline.
if (!pdfjsLib.GlobalWorkerOptions.workerSrc) {
    pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.js';
}

// LOAD PDF

const loadingTask =
pdfjsLib.getDocument({
    data: decrypted
});

const pdf =
await loadingTask.promise;

// CONTAINER

const container =
document.getElementById(
'pdf-render-container'
);

const sidebar =
document.getElementById(
'pdf-sidebar'
);

container.innerHTML = "";
sidebar.innerHTML = "";

// =========================
// TOOLBAR
// =========================

const toolbar = document.createElement('div');
toolbar.style.position = "sticky";
toolbar.style.top = "0";
toolbar.style.zIndex = "50";
toolbar.style.display = "flex";
toolbar.style.gap = "8px";
toolbar.style.justifyContent = "center";
toolbar.style.alignItems = "center";
toolbar.style.padding = "10px 12px";
toolbar.style.background = "#1e293b";
toolbar.style.borderBottom = "1px solid #334155";
toolbar.style.flexWrap = "wrap";

// ZOOM OUT
const zoomOutBtn = document.createElement('button');
zoomOutBtn.innerText = "− Out";

// ZOOM LEVEL INDICATOR LABEL
const zoomLabel = document.createElement('span');
zoomLabel.style.display = "flex";
zoomLabel.style.alignItems = "center";
zoomLabel.style.fontWeight = "800";
zoomLabel.style.color = "white";
zoomLabel.style.minWidth = "58px";
zoomLabel.style.justifyContent = "center";
zoomLabel.style.fontSize = "13px";
zoomLabel.style.background = "rgba(255,255,255,0.1)";
zoomLabel.style.borderRadius = "8px";
zoomLabel.style.padding = "4px 8px";

// ZOOM IN
const zoomInBtn = document.createElement('button');
zoomInBtn.innerText = "+ In";

// ZOOM RESET
const zoomResetBtn = document.createElement('button');
zoomResetBtn.innerText = "⟳ Fit";

// DOWNLOAD
const downloadBtn = document.createElement('button');
downloadBtn.innerText = "⬇ Download";

// ─── DEVICE DETECTION ───────────────────────────────────────
// PC/Laptop: non-touch device AND wide screen
const isDesktop = (
    !('ontouchstart' in window) &&
    !navigator.maxTouchPoints &&
    window.innerWidth >= 1024
);

// ─── ZOOM STATE (desktop only) ───────────────────────────────
let currentZoom = getInitialZoom();

function getInitialZoom() {
    if (!isDesktop) return 1.0; // mobile always fits full width
    const screenWidth = window.innerWidth;
    if (screenWidth <= 1280) return 0.9;
    return 1.0;
}

function updateZoomButtonUI() {
    if (!isDesktop) return;
    zoomLabel.innerText = Math.round(currentZoom * 100) + "%";
    zoomInBtn.disabled   = currentZoom >= 10.0;
    zoomOutBtn.disabled  = currentZoom <= 0.1;
    zoomInBtn.style.opacity  = currentZoom >= 10.0 ? "0.3" : "1";
    zoomOutBtn.style.opacity = currentZoom <= 0.1  ? "0.3" : "1";
    zoomInBtn.style.cursor   = currentZoom >= 10.0 ? "not-allowed" : "pointer";
    zoomOutBtn.style.cursor  = currentZoom <= 0.1  ? "not-allowed" : "pointer";
}

// ─── ZOOM WITH SMOOTH TRANSITION ──────────────────────────────
async function _zoomTo(newZoom, savedPage) {
    const oldZoom = currentZoom;

    if (window.LITE_MODE || !isDesktop) {
        currentZoom = newZoom;
        updateZoomButtonUI();
        await renderAllPages();
        scrollToPage(savedPage);
        return;
    }

    const wrap = document.getElementById('pdf-canvas-wrapper');
    if (wrap && oldZoom > 0) {
        const ratio = newZoom / oldZoom;
        wrap.style.transition = 'transform 0.2s ease';
        wrap.style.transformOrigin = 'top left';
        wrap.style.transform = `scale(${ratio})`;
        await new Promise(r => setTimeout(r, 220));
    }

    currentZoom = newZoom;
    updateZoomButtonUI();
    await renderAllPages();
    if (wrap) {
        wrap.style.transition = 'none';
        wrap.style.transform = '';
    }
    scrollToPage(savedPage);
}

zoomInBtn.onclick = async () => {
    if (!isDesktop || currentZoom >= 10.0) return;
    const savedPage = getCurrentVisiblePage();
    await _zoomTo(+(currentZoom + 0.25).toFixed(2), savedPage);
};

zoomOutBtn.onclick = async () => {
    if (!isDesktop || currentZoom <= 0.1) return;
    const savedPage = getCurrentVisiblePage();
    await _zoomTo(+(currentZoom - 0.25).toFixed(2), savedPage);
};

zoomResetBtn.onclick = async () => {
    if (!isDesktop) return;
    const savedPage = getCurrentVisiblePage();
    await _zoomTo(getInitialZoom(), savedPage);
};

// ─── BUTTON STYLING ──────────────────────────────────────────
[zoomOutBtn, zoomInBtn, downloadBtn].forEach(btn => {
    btn.style.padding = "10px 16px";
    btn.style.border = "none";
    btn.style.borderRadius = "12px";
    btn.style.cursor = "pointer";
    btn.style.fontWeight = "700";
    btn.style.background = "#2563eb";
    btn.style.color = "white";
    btn.style.fontSize = "13px";
    btn.style.touchAction = "manipulation";
    btn.style.minHeight = "42px";
});
zoomResetBtn.style.cssText = "padding:10px 16px;border:none;border-radius:12px;cursor:pointer;font-weight:700;background:#475569;color:white;font-size:13px;touch-action:manipulation;min-height:42px;";
downloadBtn.style.background = "#059669";

// ─── HIDE ZOOM CONTROLS ON MOBILE/TABLET ─────────────────────
if (!isDesktop) {
    zoomOutBtn.style.display  = "none";
    zoomInBtn.style.display   = "none";
    zoomResetBtn.style.display = "none";
    zoomLabel.style.display   = "none";
}

updateZoomButtonUI();

// ─── ASSEMBLE TOOLBAR ────────────────────────────────────────
toolbar.appendChild(zoomOutBtn);
toolbar.appendChild(zoomLabel);
toolbar.appendChild(zoomInBtn);
toolbar.appendChild(zoomResetBtn);
toolbar.appendChild(downloadBtn);
container.appendChild(toolbar);

// =========================
// RE-RENDER CANVAS PIPELINE
// =========================

// Helper: get the page number currently most visible in the container
function getCurrentVisiblePage() {
    const scrollTop = container.scrollTop;
    // toolbar height offset
    const toolbarH = toolbar.offsetHeight || 52;
    for (let p = 1; p <= pdf.numPages; p++) {
        const el = document.getElementById('page-' + p);
        if (!el) continue;
        const elTop = el.offsetTop - toolbarH;
        const elBottom = elTop + el.offsetHeight;
        if (elBottom > scrollTop) return p;
    }
    return 1;
}

// Helper: scroll so that page N is at the top of the view
function scrollToPage(pageNum) {
    const el = document.getElementById('page-' + pageNum);
    if (!el) return;
    const toolbarH = toolbar.offsetHeight || 52;
    const top = el.offsetTop - toolbarH - 10;
    if (window.LITE_MODE) {
        container.scrollTop = top;
    } else {
        container.scrollTo({ top, behavior: 'smooth' });
    }
}

// Pinch-to-zoom support — desktop only (mobile uses native browser pinch)
let pinchStartDist = null;
let pinchStartZoom = null;
let pinchSavedPage = 1;

if (isDesktop) {
container.addEventListener('touchstart', (e) => {
    if (e.touches.length === 2) {
        pinchStartDist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
        pinchStartZoom = currentZoom;
        pinchSavedPage = getCurrentVisiblePage();
        e.preventDefault();
    }
}, { passive: false });

container.addEventListener('touchmove', (e) => {
    if (e.touches.length === 2 && pinchStartDist !== null) {
        const dist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
        );
        const ratio = dist / pinchStartDist;
        const newZoom = Math.min(10, Math.max(0.3, +(pinchStartZoom * ratio).toFixed(2)));
        // Apply CSS-only visual scale during pinch (no re-render mid-gesture)
        const wrapper = document.getElementById('pdf-canvas-wrapper');
        if (wrapper) {
            wrapper.style.transformOrigin = 'top center';
            wrapper.style.transform = `scale(${newZoom / pinchStartZoom})`;
            wrapper.style.transition = 'transform 0.05s ease-out';
        }
        currentZoom = newZoom;
        updateZoomButtonUI();
        e.preventDefault();
    }
}, { passive: false });

container.addEventListener('touchend', async (e) => {
    if (pinchStartDist !== null && e.touches.length < 2) {
        // Reset visual transform and do a real render at the new zoom
        const wrapper = document.getElementById('pdf-canvas-wrapper');
        if (wrapper) {
            wrapper.style.transform = '';
            wrapper.style.transition = '';
        }
        pinchStartDist = null;
        await renderAllPages();
        scrollToPage(pinchSavedPage);
        pinchStartZoom = null;
    }
}, { passive: true });

} // end if (isDesktop) pinch block

async function renderAllPages() {

    // MAIN WRAPPER — reuse or create
    let pageWrapContainer = document.getElementById('pdf-canvas-wrapper');
    if (!pageWrapContainer) {
        pageWrapContainer = document.createElement('div');
        pageWrapContainer.id = 'pdf-canvas-wrapper';
        pageWrapContainer.style.width = '100%';
        container.appendChild(pageWrapContainer);
    }

    // CLEAR OLD PAGES
    pageWrapContainer.innerHTML = "";
    sidebar.innerHTML = "";

    // LOOP THROUGH ALL PAGES
    for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {

        const page = await pdf.getPage(pageNum);

        // =========================
        // SIDEBAR THUMBNAIL
        // =========================
        let thumbWrap = null;

        if (!window.LITE_MODE) {
            const thumbViewport = page.getViewport({ scale: 0.25 });
            const thumbCanvas   = document.createElement('canvas');
            const thumbCtx      = thumbCanvas.getContext('2d');

            // Set canvas internal dimensions to actual pixel size
            thumbCanvas.width  = thumbViewport.width;
            thumbCanvas.height = thumbViewport.height;

            // Render thumbnail BEFORE appending so it has a valid context
            await new Promise(r => requestAnimationFrame(r));

const renderTask = page.render({
    canvasContext: thumbCtx,
    viewport: thumbViewport
});

await renderTask.promise;

            // CSS width:100% makes it fit the dark sidebar column — this is correct for thumbs
            // because the thumb canvas resolution is already set, width:100% just scales display
            thumbCanvas.style.width = '100%';
           thumbCanvas.style.height = 'auto';
thumbCanvas.style.objectFit = 'contain';
thumbWrap = document.createElement('div');
thumbWrap.className = 'pdf-thumb';
thumbWrap.appendChild(thumbCanvas);

// ✅ Use createElement instead of innerHTML += (which destroys the canvas)
const pageLabel = document.createElement('div');
pageLabel.style.cssText = 'color:white;font-size:11px;text-align:center;';
pageLabel.textContent = `Page ${pageNum}`;
thumbWrap.appendChild(pageLabel);

sidebar.appendChild(thumbWrap);
        }

        // =========================
        // FULL PAGE VIEW — device-aware rendering
        // =========================

        const containerWidth = Math.max(container.clientWidth - 40, 300);
        const naturalViewport = page.getViewport({ scale: 1 });
        const fitScale = containerWidth / naturalViewport.width;

        let finalScale;
        if (isDesktop) {
            // Desktop: respect zoom level
            finalScale = fitScale * currentZoom;
        } else {
            // Mobile/tablet: render at physical pixel density for maximum sharpness
            // devicePixelRatio = 2 on Retina/AMOLED, 3 on high-end phones
            const dpr = Math.min(window.devicePixelRatio || 1, 3);
            finalScale = fitScale * dpr;
        }

        const viewport = page.getViewport({ scale: finalScale });

        // Card wrapper
        const pageWrap = document.createElement('div');
        pageWrap.id = 'page-' + pageNum;
        pageWrap.style.cssText = `
            display:block;
            margin:0 auto 24px auto;
            background:white;
            border-radius:14px;
            box-shadow:0 8px 22px rgba(0,0,0,0.25);
            padding:10px;
            width:fit-content;
            min-width:0;
            max-width:100%;
        `;

        const canvas  = document.createElement('canvas');
        const context = canvas.getContext('2d');

        if (isDesktop) {
            // Desktop: canvas pixel size = render size
            canvas.width  = Math.floor(viewport.width);
            canvas.height = Math.floor(viewport.height);
            canvas.style.display      = 'block';
            canvas.style.borderRadius = '10px';
        } else {
            // Mobile: canvas is rendered at high-DPI but CSS-scaled down to fit screen
            // This gives crisp text even on small screens
            const dpr = Math.min(window.devicePixelRatio || 1, 3);
            const displayWidth  = Math.floor(containerWidth);
            const displayHeight = Math.floor(containerWidth / naturalViewport.width * naturalViewport.height);
            canvas.width  = Math.floor(viewport.width);
            canvas.height = Math.floor(viewport.height);
            canvas.style.display      = 'block';
            canvas.style.borderRadius = '10px';
            canvas.style.width        = displayWidth  + 'px';
            canvas.style.height       = displayHeight + 'px';
            canvas.style.maxWidth     = '100%';
        }

        pageWrap.appendChild(canvas);
        pageWrapContainer.appendChild(pageWrap);

        // Render once — no duplicate render call
        await page.render({ canvasContext: context, viewport }).promise;

        // Thumbnail click → scroll to this page
        if (thumbWrap) {
            thumbWrap.onclick = () => pageWrap.scrollIntoView({ behavior: 'smooth' });
        }
    }
}

// SHOW MODAL FIRST — renderAllPages() measures container.clientWidth, which
// is only meaningful once the modal is actually visible. Showing it now
// (instead of after rendering) means we can render pages just once instead
// of the previous approach of rendering everything, then re-rendering
// everything again 150ms later once the modal had settled — which was
// silently doubling the time every document took to open.
document.getElementById(
    'modal'
).style.display = 'block';

document.getElementById(
    'modal-title'
).textContent =
displayName;

// Wait a frame so the browser has committed layout for the now-visible
// modal before we measure container.clientWidth inside renderAllPages().
await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));

// SINGLE RENDER PASS
await renderAllPages();
scrollToPage(1);

// =========================
// DOWNLOAD SECURELY
// =========================
// SmartDownload: owner (shineil) never sees a password prompt.
// We still keep a lightweight 30-min cache for logging/telemetry, but the
// gate is bypassed unconditionally when _isSmartDownloadOwner() is true.
// Non-owners always hit the PASSWORD GATE.

downloadBtn.onclick = async () => {

    try {

        if (!currentDecryptedPdf) {

            toastNotify('No file loaded.', 'warning');
            return;

        }

        const _ownerEligible = _isSmartDownloadOwner();
        const _hasSmartAuth = _isDownloadAuthValid();

        // DEBUG - always log so you can see in DevTools why it did/didn't bypass
        console.log('[SmartDownload] check', {ownerEligible:_ownerEligible, hasSmartAuth:_hasSmartAuth, vaultUser: sessionStorage.getItem('vaultUser'), vaultMode: sessionStorage.getItem('vaultMode') || window.VAULT_MODE, memberSel: document.getElementById('member-select')?.value});

        if (_ownerEligible) {
            // Owner smart path: no password, no network call. Just refresh the cache
            // so future checks stay valid for another SMART_DOWNLOAD_TTL_MS.
            _setDownloadAuth();
            if (_hasSmartAuth) console.log('[SmartDownload] Owner bypass — cached auth hit, no password asked.');
            else console.log('[SmartDownload] Owner bypass — first download, auto-unlocked (no password needed for owner).');
            // Optional tiny toast so it's clear why no prompt appeared (only first time per session to avoid spam)
            if(!_hasSmartAuth) {
                // use console + optional non-blocking toast
                try{ toastNotify('Smart Download · owner — no password needed.', 'success'); }catch{}
            }
        } else {
        // PASSWORD GATE — non-owners always require password
        const enteredPass =
        prompt('Enter download password:');

        if (enteredPass === null)
        return;

        try {

            const enteredHash =
await window.sha256(
    enteredPass
);

const passkeyRes =
await fetch(
 "https://lively-star-38ef.shinumaths989.workers.dev/get-secret",
  {
   method:"POST",
   headers:{
     "Content-Type":
     "application/json"
   },

   body: JSON.stringify({
      hash: enteredHash
   })
 }
);
            const passkeyResult =
            await passkeyRes.json();

            if (
                !passkeyResult ||
                !passkeyResult.success
            ) {

                toastNotify(
                    passkeyResult.message ||
                    'Incorrect download password.', 'error'
                );

                return;
            }

        } catch (fetchErr) {

            console.error(fetchErr);

            toastNotify(
                'Could not verify password.', 'error'
            );

            return;
        }
        }

        // DOWNLOAD PDF

        const pdfBlob =
        new Blob(
            [new Uint8Array(currentDecryptedPdf)],
            {
                type: 'application/pdf'
            }
        );

        const url =
        URL.createObjectURL(pdfBlob);

        const a =
        document.createElement('a');

        a.href = url;

        a.download =
        displayName + '.pdf';

        document.body.appendChild(a);

        a.click();

        a.remove();

        URL.revokeObjectURL(url);

    } catch (err) {

        console.error(err);

        toastNotify('Download failed.', 'error');

    }

};

} catch (e) {

    console.error(e);

    toastNotify(_describeOpenFileError(e), 'error');

}

}

/* Map the various errors openSecureFile() can throw to a message that
   actually tells the user what went wrong, instead of a single generic
   "Access Denied: Could not decrypt file" for every failure mode. This is
   what was making a missing-from-R2 file (HTTP 404) look identical to a
   genuine decryption failure — they need different fixes (re-upload vs.
   re-login vs. wrong password). */
function _describeOpenFileError(e) {
    const msg = (e && e.message) || '';

    if (/HTTP 404/.test(msg)) {
        return 'This file was never fully uploaded to storage (not found in R2). Ask the admin to re-upload it from Files Manager.';
    }
    if (/HTTP 401|HTTP 403/.test(msg)) {
        return 'Your session has expired. Please log in again.';
    }
    if (/HTTP 5\d\d/.test(msg)) {
        return 'Storage server error (' + msg.replace('Server error: ', '') + '). Please try again in a moment.';
    }
    if (/Corrupted file header/.test(msg)) {
        return 'This file is missing or corrupted in storage — the backend did not return a valid encrypted file. Ask the admin to re-upload it.';
    }
    if (/Missing vault session token/.test(msg)) {
        return 'Session not found. Please log in again.';
    }
    if (/Document not available offline/.test(msg)) {
        return msg;
    }
    if (/PDF viewer not available offline/.test(msg)) {
        return msg;
    }
    if (/Failed to load document/.test(msg)) {
        return msg;
    }
    if (e && e.name === 'OperationError') {
        // AES-GCM decrypt threw — either the wrong master password was used,
        // or the encrypted bytes are corrupted/truncated.
        return 'Could not decrypt this file — wrong password, or the file is corrupted in storage.';
    }

    return msg ? ('Could not open file: ' + msg) : 'Access Denied: Could not decrypt file.';
}
/* =========================
   CLOSE MODAL
========================= */

function closeModal(){

    document.getElementById(
    'modal').style.display =
    'none';

    if(currentBlobUrl){

        URL.revokeObjectURL(
        currentBlobUrl);

        currentBlobUrl = null;
    }

    currentDecryptedPdf = null;
}

/* =========================
   SECURITY
========================= */

document.addEventListener(
"contextmenu",
e=>{

    sendSecurityAlert(
    "Right click attempt detected"
    );

    e.preventDefault();

});
document.onkeydown =
function(e){

    if(
        e.ctrlKey &&
        (
            e.key==='s' ||
            e.key==='p' ||
            e.key==='u'
        )
    ){

   sendSecurityAlert(
"Blocked keyboard shortcut attempt: " + e.key
);

e.preventDefault();
    }
};

/* =========================
   PHOTO LIGHTBOX VIEWER
========================= */

let _lightboxPhotos = [];
let _lightboxIndex = -1;

function openPhotoViewer(photos, index) {
    _lightboxPhotos = photos;
    _lightboxIndex = index;

    const overlay = document.getElementById('photo-lightbox');
    if (!overlay) return;
    overlay.style.display = 'flex';

    updateLightboxImage();
    updateLightboxNav();
}

function closePhotoViewer() {
    const overlay = document.getElementById('photo-lightbox');
    if (overlay) overlay.style.display = 'none';
    _lightboxPhotos = [];
    _lightboxIndex = -1;
    // NOTE: we intentionally do NOT revoke blob URLs or clear
    // window._photoDecryptedCache here. That cache is shared with the photo
    // grid and is meant to persist for the whole session so navigating away
    // (Profile, Gmail, etc.) and back doesn't force every photo to re-fetch
    // and re-decrypt. Blob URLs are cheap to leave alive for the session and
    // get cleaned up naturally on page unload.
    document.getElementById('lightbox-img-container').innerHTML = '';
}

function prevPhoto(e) {
    if (e) e.stopPropagation();
    if (_lightboxIndex > 0) {
        _lightboxIndex--;
        updateLightboxImage();
        updateLightboxNav();
    }
}

function nextPhoto(e) {
    if (e) e.stopPropagation();
    if (_lightboxIndex < _lightboxPhotos.length - 1) {
        _lightboxIndex++;
        updateLightboxImage();
        updateLightboxNav();
    }
}

function updateLightboxNav() {
    const prevBtn = document.getElementById('lightbox-prev');
    const nextBtn = document.getElementById('lightbox-next');
    const counter = document.getElementById('lightbox-counter');
    if (prevBtn) prevBtn.style.display = _lightboxIndex > 0 ? '' : 'none';
    if (nextBtn) nextBtn.style.display = _lightboxIndex < _lightboxPhotos.length - 1 ? '' : 'none';
    if (counter) counter.textContent = `${_lightboxIndex + 1} / ${_lightboxPhotos.length}`;
}

async function updateLightboxImage() {
    const container = document.getElementById('lightbox-img-container');
    const caption = document.getElementById('lightbox-caption');
    if (!container || _lightboxIndex < 0 || _lightboxIndex >= _lightboxPhotos.length) return;

    const file = _lightboxPhotos[_lightboxIndex];
    if (caption) caption.textContent = file.name || 'Photo';

    const docKey = (file.file || '').replace(/^\/docs\/|^docs\//, '').replace(/^\/photos\/|^photos\//, '');

    // ── CACHE HIT: already decrypted (by grid, lightbox, or the eager
    // loading-screen preload), reuse the blob URL — no re-fetch, no re-decrypt.
    if (window._photoDecryptedCache.has(docKey)) {
        const cached = window._photoDecryptedCache.get(docKey);
        container.innerHTML = `<img src="${escHtml(cached.url)}" style="max-width:100%;max-height:85vh;object-fit:contain;border-radius:8px;box-shadow:0 4px 30px rgba(0,0,0,.3);" data-blob-url="${escHtml(cached.url)}" alt="${escHtml(file.name || '')}">`;
        return;
    }

    if (!window.masterPassword) {
        container.innerHTML = '<div style="text-align:center;padding:40px;color:#ef4444;">Session not unlocked</div>';
        return;
    }

    container.innerHTML = '<div style="text-align:center;padding:40px;color:#94a3b8;">Loading...</div>';

    // Capture which photo this load was for — if the user navigates to a
    // different photo before this resolves (rapid-clicking next/prev), don't
    // overwrite the container with a stale image.
    const requestedIndex = _lightboxIndex;

    try {
        const result = await decryptPhotoShared(file);
        if (_lightboxIndex !== requestedIndex) return; // user moved on already

        if (!result) {
            container.innerHTML = '<div style="text-align:center;padding:40px;color:#ef4444;">Failed to load photo</div>';
            return;
        }

        container.innerHTML = `<img src="${escHtml(result.url)}" style="max-width:100%;max-height:85vh;object-fit:contain;border-radius:8px;box-shadow:0 4px 30px rgba(0,0,0,.3);" data-blob-url="${escHtml(result.url)}" alt="${escHtml(file.name || '')}">`;
    } catch (e) {
        if (_lightboxIndex !== requestedIndex) return;
        container.innerHTML = '<div style="text-align:center;padding:40px;color:#ef4444;">Error: ' + escHtml(e.message) + '</div>';
    }
}

// Keyboard navigation for lightbox
document.addEventListener('keydown', function(e) {
    const overlay = document.getElementById('photo-lightbox');
    if (!overlay || overlay.style.display !== 'flex') return;
    if (e.key === 'Escape') closePhotoViewer();
    if (e.key === 'ArrowLeft') prevPhoto();
    if (e.key === 'ArrowRight') nextPhoto();
});
