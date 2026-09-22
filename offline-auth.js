/* =============================================================
   OFFLINE AUTH  —  offline-auth.js
   v20260609-clean

   Authentication method: LOCAL PBKDF2 + SHA-256 server-hash,
   stored in IndexedDB (vaultOfflineDB). No server required after
   first online login.

   ALL 7 VAULT MODES are cached on the device after the first
   online login by any member. Every device can then authenticate
   any of the 7 modes fully offline.

   Algo types stored in vault_auth:
     'pbkdf2-sha256-200k' — current user, hashed locally (most secure)
     'sha256-server'      — all-members sync, hash from server env vars
     (legacy) plain       — v3 records, plain sha256, backward compat

   Public API:
     syncOfflineAuth()      — saves current user after online login
     syncAllMembersOffline()— fetches all 7 modes from backend, saves all
     offlineLogin(_, pass)  — full-password offline verify → secret | false
     idbSetVaultMeta(data)  — caches file list
     idbGetVaultMeta()      — returns cached file list
     idbSaveDoc(key, buf)   — caches encrypted document bytes
     idbGetDoc(key)         — returns cached encrypted document bytes
   ============================================================= */

window.SHINE_OFFLINE_AUTH_VERSION = '20260609-clean';

const _WORKER_URL = window.BACKEND_URL || 'https://backend.shinumaths989.workers.dev';

// ── IndexedDB setup ────────────────────────────────────────────────────────
const _AUTH_DB_NAME    = 'vaultOfflineDB';
const _AUTH_DB_VERSION = 8;

function _openAuthDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_AUTH_DB_NAME, _AUTH_DB_VERSION);

        req.onupgradeneeded = e => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('pm_entries'))
                db.createObjectStore('pm_entries',  { keyPath: 'id' });
            if (!db.objectStoreNames.contains('vault_docs'))
                db.createObjectStore('vault_docs',  { keyPath: 'filename' });
            if (!db.objectStoreNames.contains('vault_meta'))
                db.createObjectStore('vault_meta',  { keyPath: 'key' });
            if (!db.objectStoreNames.contains('vault_auth'))
                db.createObjectStore('vault_auth',  { keyPath: 'id' });
            if (!db.objectStoreNames.contains('vault_notifications'))
                db.createObjectStore('vault_notifications', { keyPath: 'id', autoIncrement: true });
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
    });
}

// ── Crypto helpers ─────────────────────────────────────────────────────────

function _randomSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// PBKDF2 — used for current-user sync (typed password, 200k rounds)
async function _pbkdf2Hash(text, hexSalt, iterations = 200_000) {
    const enc    = new TextEncoder();
    const salt   = Uint8Array.from(hexSalt.match(/.{2}/g), h => parseInt(h, 16));
    const keyMat = await crypto.subtle.importKey(
        'raw', enc.encode(String(text)), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
        keyMat, 256
    );
    return Array.from(new Uint8Array(bits))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// SHA-256 matching auth.js hashPassword() exactly:
// password.trim().normalize("NFKC") → SHA-256 → hex
async function _sha256AuthHash(password) {
    const normalized = String(password).trim().normalize('NFKC');
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(normalized)
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// Legacy plain SHA-256 (no normalize) — backward compat with v3 records
async function _sha256Legacy(text) {
    const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(String(text))
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Write helpers ──────────────────────────────────────────────────────────

// Encrypt secret using a key derived from the password (separate salt from PBKDF2 hash)
async function _wrapSecret(secret, password) {
    const wrapSalt = _randomSalt();
    const keyMaterial = await crypto.subtle.importKey('raw',
        new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const keyBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: Uint8Array.from(wrapSalt.match(/.{2}/g), h => parseInt(h, 16)), iterations: 200000 },
        keyMaterial, 256);
    const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBits),
        { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv },
        key, new TextEncoder().encode(String(secret)));
    const combined = new Uint8Array(16 + 12 + ct.byteLength);
    combined.set(Uint8Array.from(wrapSalt.match(/.{2}/g), h => parseInt(h, 16)), 0);
    combined.set(iv, 16);
    combined.set(new Uint8Array(ct), 28);
    return 'w1:' + btoa(String.fromCharCode(...combined));
}

async function _unwrapSecret(wrapped, password) {
    if (!wrapped || !wrapped.startsWith('w1:')) return String(password || '');
    try {
        const raw = Uint8Array.from(atob(wrapped.slice(3)), c => c.charCodeAt(0));
        const wrapSalt = Array.from(raw.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
        const iv = raw.slice(16, 28);
        const ct = raw.slice(28);
        const keyMaterial = await crypto.subtle.importKey('raw',
            new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
        const keyBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', hash: 'SHA-256', salt: Uint8Array.from(wrapSalt.match(/.{2}/g), h => parseInt(h, 16)), iterations: 200000 },
            keyMaterial, 256);
        const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBits),
            { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
        return new TextDecoder().decode(pt);
    } catch (e) {
        console.warn('[OfflineAuth] Failed to unwrap secret, falling back to typed password:', e.message);
        return String(password || '');
    }
}

// ── Hash-keyed wrap/unwrap ──────────────────────────────────────────────────
// Used for "full sync" records (syncAllMembersOffline) where we only ever
// receive a member's server-computed passwordHash — never their plaintext
// password. We can't derive a PBKDF2 key from a password we don't have, but
// we DO get that exact same hash back from the client at offline-login time
// (offlineLogin recomputes _sha256AuthHash(password) to find the matching
// record), so the hash itself is a safe, deterministic key to wrap/unwrap
// the real secret with.
async function _deriveRawKeyFromHash(passwordHashHex, usage) {
    const keyBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(passwordHashHex)));
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [usage]);
}

async function _wrapSecretWithHash(secret, passwordHashHex) {
    const key = await _deriveRawKeyFromHash(passwordHashHex, 'encrypt');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(String(secret)));
    const combined = new Uint8Array(12 + ct.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ct), 12);
    return 'w2:' + btoa(String.fromCharCode(...combined));
}

async function _unwrapSecretWithHash(wrapped, passwordHashHex) {
    if (!wrapped || !wrapped.startsWith('w2:')) return null;
    try {
        const raw = Uint8Array.from(atob(wrapped.slice(3)), c => c.charCodeAt(0));
        const iv = raw.slice(0, 12);
        const ct = raw.slice(12);
        const key = await _deriveRawKeyFromHash(passwordHashHex, 'decrypt');
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
        return new TextDecoder().decode(pt);
    } catch (e) {
        console.warn('[OfflineAuth] Failed to unwrap server-hash secret:', e.message);
        return null;
    }
}

async function _saveAuthRecordLocal({ mode, password, secret, token }) {
    const salt         = _randomSalt();
    const passwordHash = await _pbkdf2Hash(password, salt);
    const wrappedSecret = await _wrapSecret(secret || password, password);
    const db           = await _openAuthDB();

    return new Promise((res, rej) => {
        const tx = db.transaction('vault_auth', 'readwrite');
        tx.objectStore('vault_auth').put({
            id:           mode + '-pbkdf2',
            passwordHash,
            wrappedSecret,
            salt,
            algo:         'pbkdf2-sha256-200k',
            token:        token || '',
            mode,
            trusted:      true,
            savedAt:      Date.now()
        });
        tx.oncomplete = res;
        tx.onerror = tx.onabort = () => rej(tx.error);
    });
}

async function _saveAuthRecordFromServerHash({ mode, passwordHash, secret, token }) {
    const db = await _openAuthDB();

    // Previously `secret` was received but never stored, so offline login
    // for these records had no wrappedSecret to unwrap and silently fell
    // back to using the typed password as the decryption key — which is
    // NOT the same as the real secret, so every file/photo failed to
    // decrypt offline. Wrap it (keyed off the server passwordHash, since
    // that's all we have for members whose plaintext password we never see)
    // so it can be correctly recovered at offline-login time.
    const wrappedSecret = secret ? await _wrapSecretWithHash(secret, passwordHash) : '';

    return new Promise((res, rej) => {
        const tx = db.transaction('vault_auth', 'readwrite');
        tx.objectStore('vault_auth').put({
            id:           mode + '-sha256',
            passwordHash,
            wrappedSecret,
            algo:         'sha256-server',
            token:        token || '',
            mode,
            trusted:      true,
            savedAt:      Date.now()
        });
        tx.oncomplete = res;
        tx.onerror = tx.onabort = () => rej(tx.error);
    });
}

// ── syncOfflineAuth: save CURRENT logged-in user ───────────────────────────
async function syncOfflineAuth() {
    try {
        const password = window._pendingAuthPass || window.masterPassword || '';
        const secret   = window.masterPassword || '';
        const token    = sessionStorage.getItem('vaultSessionToken') ||
                         sessionStorage.getItem('vaultSession') || '';
        const mode     = sessionStorage.getItem('vaultMode') ||
                         window.VAULT_MODE || '';

        if (!password || !mode) {
            console.warn('[OfflineAuth] syncOfflineAuth: missing password or mode, skipping.');
            return;
        }

        await _saveAuthRecordLocal({ mode, password, secret, token });
        console.log('[OfflineAuth] Current user saved (PBKDF2) for mode:', mode);

    } catch (e) {
        console.warn('[OfflineAuth] syncOfflineAuth failed:', e);
    }
}

// ── Progress helpers (creates a floating toast, always visible) ──
let _offlineToastId = null;

// Mobile: the toast used to keep its cramped desktop min/max-width, leaving
// a large empty gap of unused screen beneath/around it on phones. On narrow
// viewports let it use the available width/height properly instead.
function _ensureOfflineToastMobileStyles() {
    if (document.getElementById('_offlineToastMobileStyles')) return;
    const style = document.createElement('style');
    style.id = '_offlineToastMobileStyles';
    style.textContent = `
        @media (max-width: 640px) {
            #offline-toast {
                left: 16px !important;
                right: 16px !important;
                bottom: 16px !important;
                min-width: 0 !important;
                max-width: none !important;
                width: auto !important;
                padding: 16px 18px !important;
            }
            #offline-toast-text { font-size: 14px !important; }
            #offline-toast-label { font-size: 12px !important; }
        }
    `;
    document.head.appendChild(style);
}

function _showOfflineProgress() {
    _hideOfflineToast();
    _ensureOfflineToastMobileStyles();
    const toast = document.createElement('div');
    toast.id = 'offline-toast';
    toast.innerHTML =
        '<div style="display:flex;align-items:center;gap:10px;">' +
            '<span id="offline-toast-icon" style="font-size:20px;">💾</span>' +
            '<div style="flex:1;min-width:0;">' +
                '<div id="offline-toast-text" style="font-size:13px;font-weight:700;color:#4338ca;"></div>' +
                '<div style="margin-top:6px;height:6px;border-radius:3px;background:#c7d2fe;overflow:hidden;">' +
                    '<div id="offline-toast-bar" style="height:100%;width:0%;border-radius:3px;background:linear-gradient(90deg,#6366f1,#4f46e5);transition:width .3s;"></div>' +
                '</div>' +
                '<div id="offline-toast-label" style="font-size:11px;color:#6366f1;margin-top:3px;font-weight:600;">0 / 0</div>' +
            '</div>' +
        '</div>';
    Object.assign(toast.style, {
        position:'fixed', bottom:'20px', right:'20px', zIndex:'999999',
        background:'linear-gradient(135deg,#eef2ff,#e0e7ff)',
        border:'1px solid #c7d2fe', borderRadius:'12px',
        padding:'14px 18px', minWidth:'280px', maxWidth:'360px',
        boxShadow:'0 4px 20px rgba(0,0,0,0.15)',
        fontFamily:'system-ui,sans-serif', display:''
    });
    document.body.appendChild(toast);
}

function _hideOfflineToast() {
    const old = document.getElementById('offline-toast');
    if (!old) return;
    old.style.animation = 'toastFadeOut .25s ease forwards';
    setTimeout(() => { if (old.parentNode) old.remove(); }, 260);
    if (_offlineToastId) { clearTimeout(_offlineToastId); _offlineToastId = null; }
}

function _updateOfflineProgress(current, total) {
    const bar = document.getElementById('offline-toast-bar');
    const label = document.getElementById('offline-toast-label');
    const pct = total > 0 ? Math.round((current / total) * 100) : 0;
    if (bar) bar.style.width = `${pct}%`;
    if (label) label.textContent = `${current} / ${total} — ${pct}%`;
}

function _setOfflineProgressText(text) {
    const el = document.getElementById('offline-toast-text');
    if (el) el.textContent = text;
}

function _setOfflineProgressDone(msg) {
    const icon = document.getElementById('offline-toast-icon');
    if (icon) icon.textContent = '✅';
    _setOfflineProgressText(msg || '✓ Site is ready for offline use');
    _updateOfflineProgress(1, 1);
    if (_offlineToastId) clearTimeout(_offlineToastId);
    _offlineToastId = setTimeout(_hideOfflineToast, 10000);
}

// ── Check if offline data already cached (for "already ready" on subsequent logins) ──
async function _isOfflineDataCached() {
    try {
        const db = await _openAuthDB();
        const row = await new Promise((res, rej) => {
            const req = db.transaction('vault_meta', 'readonly')
                          .objectStore('vault_meta').get('offlineSyncComplete');
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        return !!row;
    } catch (e) { return false; }
}

async function _markOfflineSyncComplete() {
    try {
        const db = await _openAuthDB();
        const tx = db.transaction('vault_meta', 'readwrite');
        tx.objectStore('vault_meta').put({ key: 'offlineSyncComplete', value: true, savedAt: Date.now() });
    } catch (e) {
        console.warn('[OfflineAuth] Failed to mark sync complete:', e);
    }
}

// ── Silent re-auth: use stored credentials to get a session token ──────────
async function _silentReAuth() {
    try {
        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        // 1) Prefer a pbkdf2 record with a server-issued token — verify it
        let record = allRecords.find(r => r.algo === 'pbkdf2-sha256-200k' && r.token);
        if (record && record.token) {
            const res = await fetch(`${_WORKER_URL}/check-session`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${record.token}`
                },
                body: JSON.stringify({})
            });
            if (res.ok) return record.token;
        }

        // 2) Fallback: any trusted record → generate an offline token
        record = allRecords.find(r => r.trusted === true);
        if (record) {
            const offlineToken = 'offline-' + crypto.randomUUID();
            // Persist the token back so subsequent calls don't re-generate
            const tx = db.transaction('vault_auth', 'readwrite');
            tx.objectStore('vault_auth').put({ ...record, token: offlineToken });
            console.log('[OfflineAuth] _silentReAuth: generated offline token for trusted user');
            return offlineToken;
        }

        console.warn('[OfflineAuth] _silentReAuth: no usable token or trusted record found');
        return null;
    } catch (e) {
        console.warn('[OfflineAuth] _silentReAuth failed:', e.message);
        return null;
    }
}

// ── Helper: count files across all categories ──────────────────────────────
function _countFiles(filesData) {
  let n = 0;
  for (const v of Object.values(filesData)) {
    if (Array.isArray(v)) n += v.length;
  }
  return n;
}

// ── syncAllMembersOffline: fetch & cache ALL data for offline ──────────────
async function syncAllMembersOffline(_retried) {
    _showOfflineProgress();
    _setOfflineProgressText('Preparing site for offline access...');
    _updateOfflineProgress(0, 0);

    const token = sessionStorage.getItem('vaultSessionToken') ||
                  sessionStorage.getItem('vaultSession') || '';

    if (!token) {
        _setOfflineProgressText('⚠️ No session — offline sync skipped');
        _updateOfflineProgress(1, 1);
        console.warn('[OfflineAuth] syncAllMembersOffline: no session token, skipping.');
        _offlineToastId = setTimeout(_hideOfflineToast, 10000);
        return { synced: 0, failed: [] };
    }

    if (!navigator.onLine) {
        _setOfflineProgressText('⚡ Already offline — cache available');
        _updateOfflineProgress(1, 1);
        console.warn('[OfflineAuth] syncAllMembersOffline: offline, skipping.');
        _offlineToastId = setTimeout(_hideOfflineToast, 10000);
        return { synced: 0, failed: [] };
    }

    console.log('[OfflineAuth] Fetching all member credentials for offline caching...');

    let members = [];

    try {
        const res = await fetch(`${_WORKER_URL}/sync-offline-members`, {
            method:  'POST',
            headers: {
                'Content-Type':  'application/json',
                'Authorization': `Bearer ${token}`
            }
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || err.message || `HTTP ${res.status}`);
        }

        const data = await res.json();

        if (!data.success || !Array.isArray(data.members)) {
            throw new Error('Backend returned no member data.');
        }
        if (!data.members.length) {
            // No new data — check if we have cached data already
            const hasCached = await _isOfflineDataCached();
            if (hasCached) {
                _setOfflineProgressDone('✓ Already up to date');
                return { synced: 0, failed: [], skipped: true };
            }
            throw new Error('No member data from server and no local cache.');
        }

        members = data.members;
        _updateOfflineProgress(0, members.length);

    } catch (fetchErr) {
        const _offlineToken = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession') || '';
        if (_offlineToken.startsWith('offline-')) {
            console.log('[OfflineAuth] /sync-offline-members skipped (offline token)');
        } else {
            console.warn('[OfflineAuth] /sync-offline-members failed:', fetchErr.message);
        }
        const is401 = fetchErr.message.includes('401') || fetchErr.message.includes('Unauthorized');

        // If unauthorized (and not already a retry), try to silently re-authenticate using stored login hash
        if (is401 && !_retried) {
            const newToken = await _silentReAuth();
            if (newToken) {
                sessionStorage.setItem('vaultSessionToken', newToken);
                sessionStorage.setItem('vaultSession', newToken);
                // Don't retry if we got an offline token — server won't accept it
                if (newToken.startsWith('offline-')) {
                    console.log('[OfflineAuth] Offline token generated, skipping server retry');
                } else {
                    console.log('[OfflineAuth] Re-authenticated, retrying sync...');
                    return await syncAllMembersOffline(true);
                }
            }
        }

        if (_offlineToken.startsWith('offline-')) {
            const hasCached = await _isOfflineDataCached();
            if (hasCached) {
                _setOfflineProgressDone('✓ Using offline cache');
            } else {
                _setOfflineProgressText('ℹ️ No server access — offline data not available');
                _updateOfflineProgress(1, 1);
            }
        } else {
            _setOfflineProgressText(is401 && !_retried
                ? '🔑 Session expired — log in again to enable offline access'
                : '⚠️ Sync failed: ' + fetchErr.message);
            _updateOfflineProgress(1, 1);
        }
        _offlineToastId = setTimeout(_hideOfflineToast, 10000);
        return { synced: 0, failed: [], error: fetchErr.message };
    }

    const failed = [];
    let   synced = 0;

    for (const m of members) {
        if (!m.mode || !m.passwordHash) {
            console.warn('[OfflineAuth] Skipping member with missing mode/passwordHash:', m.mode);
            _updateOfflineProgress(synced + failed.length + 1, members.length);
            continue;
        }
        try {
            await _saveAuthRecordFromServerHash({
                mode:         m.mode,
                passwordHash: m.passwordHash,
                secret:       m.secret || '',
                token:        m.token  || ''
            });
            synced++;
            _updateOfflineProgress(synced + failed.length, members.length);
            _setOfflineProgressText(`Caching: ${m.mode}`);
            console.log(`[OfflineAuth] ✓ Cached mode: ${m.mode}`);
        } catch (saveErr) {
            console.warn(`[OfflineAuth] ✗ Failed to cache mode ${m.mode}:`, saveErr.message);
            failed.push(m.mode);
            _updateOfflineProgress(synced + failed.length, members.length);
        }
    }

    // ── Phase 2: Fetch file list + cache all documents ──
    let fileCount = 0;
    let filesCached = 0;
    let filesFailed = 0;

    try {
      _setOfflineProgressText('Fetching file list...');
      const filesRes = await fetch(`${_WORKER_URL}/files.json`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (filesRes.ok) {
        const raw = await filesRes.json();
        let filesData = {};
        if (Array.isArray(raw)) {
          raw.forEach(f => {
            const cat = f.category || f.type || 'Documents';
            if (!filesData[cat]) filesData[cat] = [];
            filesData[cat].push(f);
          });
        } else if (raw && typeof raw === 'object') {
          filesData = raw;
        }
        fileCount = _countFiles(filesData);

        // Cache file list
        if (typeof idbSetVaultMeta === 'function') {
          await idbSetVaultMeta(filesData);
        }

        const totalSteps = members.length + fileCount + 1;
        _updateOfflineProgress(members.length + 0, totalSteps);

        // Cache each file's content
        const allFiles = [];
        Object.entries(filesData).forEach(([catName, cat]) => {
          if (Array.isArray(cat)) cat.forEach(f => allFiles.push({ ...f, category: f.category || catName }));
        });

        for (const f of allFiles) {
          if (!f.file) { filesFailed++; continue; }
          const isPhoto = f.category === 'PHOTOS' || /\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(f.file);
          const prefix = isPhoto ? 'photos/' : 'docs/';
          try {
            if (typeof idbGetDoc === 'function') {
              const existing = await idbGetDoc(f.file);
              if (existing) { filesCached++; continue; }
            }
            const docRes = await fetch(`${_WORKER_URL}/${prefix}${f.file}`, {
              headers: { 'Authorization': `Bearer ${token}` }
            });
            if (docRes.ok) {
              const buf = await docRes.arrayBuffer();
              if (typeof idbSaveDoc === 'function') await idbSaveDoc(f.file, buf);
              filesCached++;
            } else {
              filesFailed++;
            }
          } catch (e) {
            filesFailed++;
          }
          const done = members.length + filesCached + filesFailed;
          _updateOfflineProgress(done, totalSteps);
          _setOfflineProgressText(`Caching files... (${filesCached + filesFailed}/${fileCount})`);
        }
      }
    } catch (e) {
      console.warn('[OfflineAuth] File caching failed:', e.message);
    }

    // ── Phase 3: Sync notifications ──
    try {
      _setOfflineProgressText('Caching notifications...');
      const notifRes = await fetch(`${_WORKER_URL}/get-notifications`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ user: sessionStorage.getItem('vaultUser') || 'all' })
      });
      if (notifRes.ok) {
        const data = await notifRes.json();
        const serverNotifs = data.notifications || [];
        // Store in vault_notifications store of offline DB
        const db = await _openAuthDB();
        await new Promise((resolve, reject) => {
          const tx = db.transaction('vault_notifications', 'readwrite');
          tx.objectStore('vault_notifications').clear();
          for (const n of serverNotifs) {
            tx.objectStore('vault_notifications').put({ ...n, read: n.read || false });
          }
          tx.oncomplete = resolve;
          tx.onerror = reject;
        });
        console.log(`[OfflineAuth] Cached ${serverNotifs.length} notifications`);
      }
    } catch (e) {
      console.warn('[OfflineAuth] Notification caching failed:', e.message);
    }

    // ── All done — verify everything is cached ──
    const totalExpected = members.length + fileCount + 1;
    const totalDone = synced + filesCached + 1; // +1 for notifications
    if (totalDone >= totalExpected) {
      _setOfflineProgressDone('✓ Site is ready for offline use');
    } else {
      _setOfflineProgressText(`⚠️ ${totalDone}/${totalExpected} items cached — partial offline`);
      _updateOfflineProgress(totalDone, totalExpected);
      setTimeout(() => {
        _setOfflineProgressDone('✓ Partial cache ready');
      }, 2000);
    }
    _markOfflineSyncComplete();

    console.log(`[OfflineAuth] Full sync done — ${synced}/${members.length} members, ${filesCached}/${fileCount} files, notifications cached.`);
    return { synced, failed, filesCached, filesFailed };
}

// ── offlineLogin: full-password path ──────────────────────────────────────
async function offlineLogin(_ignored, password) {
    try {
        const db = await _openAuthDB();
        const allRecords = await new Promise((res, rej) => {
            const req = db.transaction('vault_auth', 'readonly')
                          .objectStore('vault_auth').getAll();
            req.onsuccess = () => res(req.result || []);
            req.onerror   = () => rej(req.error);
        });

        if (!allRecords.length) {
            _showOfflineError('No offline credentials found. Please connect to the internet and log in once to enable offline access.');
            return false;
        }

        let match = null;

        for (const r of allRecords) {
            if (r.algo === 'pbkdf2-sha256-200k') {
                const derived = await _pbkdf2Hash(password, r.salt);
                if (derived === r.passwordHash) { match = r; break; }

            } else if (r.algo === 'sha256-server') {
                const derived = await _sha256AuthHash(password);
                if (derived === r.passwordHash) { match = r; break; }

            } else {
                const derived = await _sha256Legacy(password);
                if (derived === r.passwordHash) { match = r; break; }
            }
        }

        if (!match) {
            console.warn('[OfflineAuth] No matching record found across', allRecords.length, 'stored mode(s).');
            _showOfflineError('Incorrect password. Please try again.');
            return false;
        }

        await _restoreSession(match, password);
        console.log('[OfflineAuth] Offline login OK, mode:', window.VAULT_MODE, '| algo:', match.algo);
        return window.masterPassword;

    } catch (e) {
        console.error('[OfflineAuth] offlineLogin error:', e);
        _showOfflineError('Offline authentication error. Please try again.');
        return false;
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

async function _restoreSession(record, passwordFallback) {
    let secret = null;

    if (record.algo === 'sha256-server' && record.wrappedSecret) {
        // Full-sync record — unwrap using the server passwordHash as the key.
        secret = await _unwrapSecretWithHash(record.wrappedSecret, record.passwordHash);
    }

    if (secret === null) {
        // Own-login record (w1: PBKDF2-from-password), or a server-hash
        // record with no wrappedSecret at all (older cached data saved
        // before this fix) — fall back to the previous behavior.
        secret = await _unwrapSecret(record.wrappedSecret, passwordFallback);
    }

    window.masterPassword = String(secret);
    window.VAULT_MODE     = record.mode || record.id;
    sessionStorage.setItem('vaultMode', window.VAULT_MODE);
    if (record.token) {
        sessionStorage.setItem('vaultSessionToken', record.token);
        sessionStorage.setItem('vaultSession',      record.token);
    } else {
        const offlineToken = 'offline-' + crypto.randomUUID();
        sessionStorage.setItem('vaultSessionToken', offlineToken);
        sessionStorage.setItem('vaultSession',      offlineToken);
    }
}

// ── Animated wrong password error ─────────────────────────────────────────
function _showOfflineError(msg) {
    // Inject keyframes once
    if (!document.getElementById('_offlineAuthStyles')) {
        const style = document.createElement('style');
        style.id = '_offlineAuthStyles';
        style.textContent = `
            @keyframes _offlineShake {
                0%,100% { transform: translateX(0); }
                15%     { transform: translateX(-8px); }
                30%     { transform: translateX(8px); }
                45%     { transform: translateX(-6px); }
                60%     { transform: translateX(6px); }
                75%     { transform: translateX(-3px); }
                90%     { transform: translateX(3px); }
            }
            @keyframes _offlineFadeSlide {
                from { opacity: 0; transform: translateY(-10px) scale(0.97); }
                to   { opacity: 1; transform: translateY(0) scale(1); }
            }
            @keyframes _offlinePulse {
                0%,100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
                50%     { box-shadow: 0 0 0 6px rgba(239,68,68,0.18); }
            }
            #offline-auth-error {
                animation: _offlineFadeSlide .28s cubic-bezier(.34,1.56,.64,1) forwards,
                           _offlinePulse 1.2s ease 0.28s 2;
            }
            #offline-auth-error.shake {
                animation: _offlineShake .45s ease forwards;
            }
        `;
        document.head.appendChild(style);
    }

    const existing = document.getElementById('offline-auth-error');
    if (existing) {
        // Re-shake if already visible
        existing.classList.remove('shake');
        void existing.offsetWidth; // force reflow
        existing.classList.add('shake');
        const errMsg = existing.querySelector('.offline-err-msg');
        if (errMsg) errMsg.textContent = msg;
        return;
    }

    const box = document.createElement('div');
    box.id = 'offline-auth-error';
    box.style.cssText = `
        background: linear-gradient(135deg, rgba(239,68,68,0.13) 0%, rgba(185,28,28,0.09) 100%);
        border: 1.5px solid rgba(239,68,68,0.55);
        border-radius: 14px;
        padding: 14px 16px 12px;
        margin-top: 14px;
        display: flex;
        align-items: flex-start;
        gap: 11px;
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
        position: relative;
        overflow: hidden;
    `;

    box.innerHTML = `
        <div style="
            width:34px; height:34px; border-radius:50%;
            background:rgba(239,68,68,0.18);
            display:flex; align-items:center; justify-content:center;
            flex-shrink:0; font-size:17px; margin-top:1px;
        ">🔑</div>
        <div style="flex:1; min-width:0;">
            <div style="
                font-weight:800; color:#fca5a5; font-size:13px;
                margin-bottom:3px; letter-spacing:0.3px;
            ">Access Denied</div>
            <div class="offline-err-msg" style="
                font-size:12px; color:rgba(255,255,255,0.75);
                line-height:1.55;
            ">${msg}</div>
        </div>
        <button onclick="this.closest('#offline-auth-error').remove()" style="
            position:absolute; top:9px; right:10px;
            background:transparent; border:none; cursor:pointer;
            color:rgba(252,165,165,0.6); font-size:15px; line-height:1;
            padding:2px 4px; border-radius:4px;
            transition: color .15s;
        " onmouseenter="this.style.color='#fca5a5'" onmouseleave="this.style.color='rgba(252,165,165,0.6)'">✕</button>
        <div style="
            position:absolute; bottom:0; left:0; right:0; height:2px;
            background:linear-gradient(90deg, #ef4444, #b91c1c, #ef4444);
            background-size:200% 100%;
            animation: _offlineShake 0s; /* reuse @keyframes slot — no actual shake */
        "></div>
    `;

    // Also shake the password field
    const passField = document.getElementById('vault-pass');
    if (passField) {
        passField.style.borderColor = 'rgba(239,68,68,0.6)';
        passField.style.animation = '_offlineShake .45s ease';
        setTimeout(() => {
            passField.style.animation = '';
            passField.style.borderColor = '';
        }, 500);
    }

    const card = document.querySelector('#step1 .login-wrapper') || document.getElementById('step1');
    if (card) card.appendChild(box);
}

// ── idbSetVaultMeta / idbGetVaultMeta ──────────────────────────────────────

async function idbSetVaultMeta(data) {
    try {
        const db = await _openAuthDB();
        await new Promise((res, rej) => {
            const tx = db.transaction('vault_meta', 'readwrite');
            tx.objectStore('vault_meta').put({
                key: 'allFilesData', value: data, savedAt: Date.now()
            });
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });
        console.log('[OfflineAuth] Vault file list cached.');
    } catch (e) {
        console.warn('[OfflineAuth] idbSetVaultMeta failed:', e);
    }
}

async function idbGetVaultMeta() {
    try {
        const db = await _openAuthDB();
        const row = await new Promise((res, rej) => {
            const req = db.transaction('vault_meta', 'readonly')
                          .objectStore('vault_meta').get('allFilesData');
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        return row ? row.value : null;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetVaultMeta failed:', e);
        return null;
    }
}

// ── Trust device session restore ──────────────────────────────────────────
// Unwraps a secret written by features.js's _wrapTrustSecret() into
// vaultTrustInfo.secret. Must match that function's format exactly:
// salt(16) + iv(12) + ciphertext, AES-GCM key from PBKDF2(_getDeviceKey()+salt).
async function _unwrapTrustSecret(wrapped) {
    if (!wrapped) return '';
    try {
        const raw = Uint8Array.from(atob(wrapped), c => c.charCodeAt(0));
        const salt = raw.slice(0, 16);
        const iv = raw.slice(16, 28);
        const ct = raw.slice(28);
        const deviceKey = typeof _getDeviceKey === 'function' ? _getDeviceKey() : '';
        const keyMaterial = await crypto.subtle.importKey('raw',
            new TextEncoder().encode(deviceKey + salt), 'PBKDF2', false, ['deriveBits']);
        const keyBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
            keyMaterial, 256);
        const key = await crypto.subtle.importKey('raw', new Uint8Array(keyBits),
            { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
        return new TextDecoder().decode(pt);
    } catch (e) {
        console.warn('[OfflineAuth] Failed to unwrap trust secret:', e.message);
        return '';
    }
}

// ── Refresh a (likely expired) trust-restored session token ────────────────
// Session tokens minted by the worker expire after 1 hour (see
// createSessionToken in worker.js), but trust-device info is kept for up to
// 14 days. That mismatch meant every "remembered" login after the first hour
// silently restored an EXPIRED token into sessionStorage — every subsequent
// authenticated call (access log, PIN sync, AI chat, offline caching,
// status/notifications) then failed its server-side auth check, which is
// what produced "Failed to load logs", the AI chat "offline mode" message,
// and the "No server access — offline data not available" banner even while
// fully online. This mints a fresh token from the still-known secret before
// the dashboard starts making authenticated calls.
async function _refreshTrustToken(secret) {
    if (!secret || typeof navigator === 'undefined' || navigator.onLine === false) return null;
    try {
        const enc = new TextEncoder();
        const normalized = String(secret).trim().replace(/[\u200B-\u200D\uFEFF\u00A0]/g, '').normalize('NFKC');

        // PBKDF2 + SHA-256 (matches auth.js hashPassword(password, true))
        const salt = enc.encode('vault-pbkdf2-v1');
        const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(normalized), 'PBKDF2', false, ['deriveBits']);
        const keyBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 200000 }, keyMaterial, 256);
        const slowHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(keyBits))))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        // Legacy SHA-256 fallback (matches auth.js hashPassword(password, false))
        const legacyHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(normalized))))
            .map(b => b.toString(16).padStart(2, '0')).join('');

        const tryHash = async (hash) => {
            const controller = new AbortController();
            const tid = setTimeout(() => controller.abort(), 8000);
            try {
                const res = await fetch(`${_WORKER_URL}/get-secret`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hash }),
                    signal: controller.signal
                });
                if (!res.ok) return null;
                const data = await res.json().catch(() => null);
                return (data && data.success && data.authorized && data.sessionToken) ? data : null;
            } catch {
                return null;
            } finally {
                clearTimeout(tid);
            }
        };

        return (await tryHash(slowHash)) || (await tryHash(legacyHash));
    } catch (e) {
        console.warn('[OfflineAuth] _refreshTrustToken failed:', e.message);
        return null;
    }
}

async function restoreTrustSession() {
    try {
        const trust = JSON.parse(localStorage.getItem('vaultTrustInfo') || 'null');
        if (!trust || !trust.member) return false;
        const modeToId = { shineil:'SHINEIL', brother:'KEVIN', father:'PARENTS', mother:'PARENTS', official:'OFFICIAL' };
        const mode = sessionStorage.getItem('vaultMode') || modeToId[trust.member] || 'ADMIN';
        // trust.secret is encrypted (see features.js _wrapTrustSecret) — never
        // stored or used raw. Unwrap it here before assigning to masterPassword.
        if (trust.secret) {
            const secret = await _unwrapTrustSecret(trust.secret);
            if (secret) {
                window.masterPassword = secret;
                window.VAULT_MODE = mode;
                sessionStorage.setItem('vaultMode', window.VAULT_MODE);
                if (trust.token) {
                    sessionStorage.setItem('vaultSessionToken', trust.token);
                    sessionStorage.setItem('vaultSession', trust.token);
                }

                // Mint a fresh, guaranteed-valid token before returning, so
                // every call the dashboard makes right after boot succeeds.
                const fresh = await _refreshTrustToken(secret);
                if (fresh && fresh.sessionToken) {
                    sessionStorage.setItem('vaultSessionToken', fresh.sessionToken);
                    sessionStorage.setItem('vaultSession', fresh.sessionToken);
                    if (fresh.mode) {
                        window.VAULT_MODE = fresh.mode;
                        sessionStorage.setItem('vaultMode', fresh.mode);
                    }
                    try {
                        trust.token = fresh.sessionToken;
                        localStorage.setItem('vaultTrustInfo', JSON.stringify(trust));
                    } catch (e) { /* non-fatal */ }
                    console.log('[OfflineAuth] Trust session token refreshed from server.');
                } else {
                    console.warn('[OfflineAuth] Trust token could not be refreshed (offline or server unreachable) — using cached token, which may be expired.');
                }

                console.log('[OfflineAuth] Trust session restored from vaultTrustInfo.secret');
                return true;
            }
            console.warn('[OfflineAuth] restoreTrustSession: could not unwrap stored secret');
            return false;
        }
        console.warn('[OfflineAuth] restoreTrustSession: no secret found in IDB or trust info');
        return false;
    } catch (e) {
        console.warn('[OfflineAuth] restoreTrustSession failed:', e);
        return false;
    }
}

function _isTrustDevice() {
    try {
        const trust = JSON.parse(localStorage.getItem('vaultTrustInfo') || 'null');
        return trust && trust.expiry > Date.now();
    } catch(e) {
        return false;
    }
}

// ── idbSaveDoc / idbGetDoc — encrypted document caching ───────────────────
// Used by viewer.js to cache encrypted bytes for offline document access.
// Key = docKey (e.g. "abc.enc"), value = ArrayBuffer.

async function idbSaveDoc(filename, arrayBuffer) {
    try {
        const db = await _openAuthDB();
        // Store as Uint8Array — ArrayBuffer is not directly storable in all browsers
        const bytes = new Uint8Array(arrayBuffer);
        await new Promise((res, rej) => {
            const tx = db.transaction('vault_docs', 'readwrite');
            tx.objectStore('vault_docs').put({
                filename,
                bytes,
                savedAt: Date.now()
            });
            tx.oncomplete = res;
            tx.onerror = tx.onabort = () => rej(tx.error);
        });
        console.log(`[OfflineAuth] Cached doc: ${filename} (${(arrayBuffer.byteLength / 1024).toFixed(1)} KB)`);
    } catch (e) {
        console.warn('[OfflineAuth] idbSaveDoc failed:', e);
    }
}

async function idbGetDoc(filename) {
    try {
        const db = await _openAuthDB();
        const row = await new Promise((res, rej) => {
            const req = db.transaction('vault_docs', 'readonly')
                          .objectStore('vault_docs').get(filename);
            req.onsuccess = () => res(req.result || null);
            req.onerror   = () => rej(req.error);
        });
        if (!row) return null;
        // Return as ArrayBuffer for compatibility with viewer.js
        return row.bytes instanceof Uint8Array
            ? row.bytes.buffer.slice(row.bytes.byteOffset, row.bytes.byteOffset + row.bytes.byteLength)
            : row.bytes;
    } catch (e) {
        console.warn('[OfflineAuth] idbGetDoc failed:', e);
        return null;
    }
}
