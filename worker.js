/**
 * 🛡️ Advanced Secure Vault Backend (v3.9 - Global Status + PIN Sync + Unified File Routing)
 *
 * FIXES in v3.9:
 * - [FILES] /docs/, /file/, and /photos/ now ALL route through handleGetDoc,
 *   so /photos/ requests get the same member-visibility check that /docs/
 *   and /file/ already had (previously /photos/ went straight to
 *   handleDownload with only a raw session check — no per-file access
 *   control, and no path-safety check).
 * - [FILES] handleGetDoc's bucket-key fallback chain now also tries a
 *   `photos/<path>` key, and the path-normalization regex used to match a
 *   requested file against files.json entries now also strips a leading
 *   `photos/` prefix (previously only `docs/` and `file/` were stripped).
 *   This was the root cause of "/photos or /file always resolves as /docs":
 *   any file whose real bucket key lived under `photos/` could never be
 *   found when requested via /file/ or /photos/, because the lookup chain
 *   never tried the `photos/` prefix — only the /docs/ fallback (which
 *   matched files stored under the default root or `docs/` prefix) ever
 *   succeeded, making it look like every request "fell back to docs".
 *
 * FIXES in v3.8:
 * - [STATUS] Added /status-report (POST) and /status-history (GET) so the
 *   90-day uptime dashboard is stored in Firestore and shared across every
 *   device ("global status"), instead of being per-device localStorage only.
 *   Each device still also runs its own live checks ("local status") which
 *   are shown separately and are NOT persisted globally.
 * - [PIN] /save-pin-hash now upserts (no more 409 conflict block), so a PIN
 *   change made after correct-old-PIN verification on the client always
 *   updates the shared hash. /get-pin-hashes is unchanged and is the single
 *   source of truth other devices sync from before deciding "set" vs "enter".
 *
 * FIXES in v3.7:
 * - [OFFLINE] Added /vault-auth-hashes endpoint.
 *   Returns SHA-256 hashes of all 7 member passwords so the frontend
 *   can cache them in IndexedDB and allow offline login for any member.
 *   Plaintext passwords never leave the worker — only pre-hashed values.
 * - Requires valid session token (any mode) to call the endpoint.
 */

const ALLOWED_ORIGINS = new Set([
  "https://72oe-v2sx.shine-ministry.com",
  "https://shineministry.github.io",
  "https://72oe-vtsx.shineministry.github.io",
  "https://2183-vertex-7779.shine-ministry.com",
  "https://shinevoicetv.github.io",

  // Sound Mixer Controller origins
  "http://localhost:8000",
  "http://127.0.0.1:8000",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
]);

// ─── R2 Sound Mixer API ──────────────────────────────────────────────
const R2_API_KEY = "Mfyi2019wIbSC#Honour";

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Cross-Origin-Embedder-Policy": "credentialless",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "cross-origin",
  "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
  "Content-Security-Policy":
    "default-src 'self'; " +
    "script-src 'self' https://www.google.com https://www.gstatic.com https://www.recaptcha.net https://cdn.jsdelivr.net; " +
    "script-src-elem 'self' https://www.google.com https://www.gstatic.com https://www.recaptcha.net https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com data:; " +
    "img-src 'self' data: blob: https:; " +
    "connect-src 'self' https:; " +
    "frame-src https://www.google.com https://recaptcha.google.com https://www.recaptcha.net; " +
    "worker-src 'self' blob: https://www.google.com https://www.gstatic.com; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'; " +
    "frame-ancestors 'none';"
};

const FAVICON_URL = "https://72oe-v2sx.shine-ministry.com/favicon.png";
const _MC = "110,231,247";

// ═══════════════════════════════════════════════════════════════════════════
//  2. GLOBAL CORE UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

function createJsonResponse(data, status = 200, corsOrigin = "null", customHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "Content-Type": "application/json; charset=UTF-8",
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
      "Vary": "Origin",
      ...customHeaders
    }
  });
}

function normalizePassword(pw) {
  return (pw || "")
    .trim()
    .replace(/[\u200B-\u200D\uFEFF\u00A0]/g, "")
    .normalize("NFKC");
}

// ─── Rate limiting fallback (in-memory) ──────────────────────────────
const rateLimitStore = new Map();
function checkRateLimit(key, maxRequests = 30, windowMs = 60000) {
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  if (!entry || now - entry.windowStart > windowMs) {
    rateLimitStore.set(key, { windowStart: now, count: 1 });
    return true;
  }
  entry.count++;
  if (entry.count > maxRequests) return false;
  return true;
}

// ─── Body size limits ─────────────────────────────────────────────────
const MAX_BODY_BYTES = 2 * 1024 * 1024;     // 2 MB
const MAX_UPLOAD_BODY_BYTES = 500 * 1024 * 1024; // 500 MB

// ─── Path traversal prevention ────────────────────────────────────────
function isPathSafe(relativePath) {
  const normalized = relativePath.replace(/\\/g, "/");
  if (normalized.includes("..")) return false;
  return true;
}

// ─── R2 Sound Mixer helpers ──────────────────────────────────────────
function r2IsAudioFile(key) {
  return /\.(wav|mp3|ogg|flac|m4a|aac|wma)$/i.test(key);
}

function r2GetMime(key) {
  const ext = key.split(".").pop()?.toLowerCase() || "";
  const map = {
    wav: "audio/wav", mp3: "audio/mpeg", ogg: "audio/ogg",
    flac: "audio/flac", m4a: "audio/mp4", aac: "audio/aac", wma: "audio/x-ms-wma"
  };
  return map[ext] || "application/octet-stream";
}

function r2ListPrefix(prefix) {
  if (!prefix) return "";
  return prefix.endsWith("/") ? prefix : prefix + "/";
}

function r2GetFileName(key) {
  return key.split("/").pop().replace(/\.[^.]+$/, "");
}

function timingSafeEqual(a, b) {
  const sa = String(a ?? "");
  const sb = String(b ?? "");
  const maxLen = Math.max(sa.length, sb.length);
  const aPadded = sa.padEnd(maxLen, "\0");
  const bPadded = sb.padEnd(maxLen, "\0");
  let result = sa.length === sb.length ? 0 : 1;
  for (let i = 0; i < maxLen; i++) {
    result |= aPadded.charCodeAt(i) ^ bPadded.charCodeAt(i);
  }
  return result === 0;
}

// ─── SHA-256 hex helper (used by handleVaultAuthHashes) ──────────────────
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(str)
  );
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── TOTP (RFC 6238) ────────────────────────────────────────────────────────
async function generateTOTP(secret, timeStep = 60, digits = 8) {
  // Decode base32 secret
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const secretUpper = secret.toUpperCase().replace(/=+$/, "");
  let bits = "";
  for (const ch of secretUpper) {
    const idx = base32Chars.indexOf(ch);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }

  // Time counter
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  const counterBytes = new Uint8Array(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }

  // HMAC-SHA1
  const key = await crypto.subtle.importKey(
    "raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const hmac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterBytes)
  );

  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset]     & 0x7f) << 24) |
     ((hmac[offset + 1] & 0xff) << 16) |
     ((hmac[offset + 2] & 0xff) <<  8) |
      (hmac[offset + 3] & 0xff)) % Math.pow(10, digits);

  return code.toString().padStart(digits, "0");
}

async function verifyTOTP(secret, userCode, window = 1) {
  // Check current window ± 1 step (handles clock drift)
  const timeStep = 60;
  const digits = 8;
  const now = Math.floor(Date.now() / 1000 / timeStep);
  for (let delta = -window; delta <= window; delta++) {
    const counter = now + delta;
    const counterBytes = new Uint8Array(8);
    let tmp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBytes[i] = tmp & 0xff;
      tmp = Math.floor(tmp / 256);
    }
    const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const secretUpper = secret.toUpperCase().replace(/=+$/, "");
    let bits = "";
    for (const ch of secretUpper) {
      const idx = base32Chars.indexOf(ch);
      if (idx === -1) continue;
      bits += idx.toString(2).padStart(5, "0");
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
    }
    const key = await crypto.subtle.importKey(
      "raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
    );
    const hmac = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, counterBytes)
    );
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code =
      (((hmac[offset]     & 0x7f) << 24) |
       ((hmac[offset + 1] & 0xff) << 16) |
       ((hmac[offset + 2] & 0xff) <<  8) |
        (hmac[offset + 3] & 0xff)) % Math.pow(10, digits);
    const expected = code.toString().padStart(digits, "0");
    if (timingSafeEqual(userCode, expected)) return true;
  }
  return false;
}
// ═══════════════════════════════════════════════════════════════════════════
//  3. FIREBASE / FIRESTORE
// ═══════════════════════════════════════════════════════════════════════════

async function getFirebaseAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);

  const header = btoa(JSON.stringify({ alg: "RS256", typ: "JWT" }))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const payload = btoa(JSON.stringify({
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
    scope: "https://www.googleapis.com/auth/datastore"
  })).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const signingInput = `${header}.${payload}`;

  const pemKey = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n");
  const pemBody = pemKey
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const derBuffer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

  const privateKey = await crypto.subtle.importKey(
    "pkcs8", derBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false, ["sign"]
  );

  const enc = new TextEncoder();
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, enc.encode(signingInput));

  const sig64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const jwt = `${signingInput}.${sig64}`;

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  });

  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    throw new Error("Firebase token exchange failed: " + JSON.stringify(tokenData));
  }
  return tokenData.access_token;
}

async function firestoreWrite(env, collection, data, docId = null) {
  const token = await getFirebaseAccessToken(env);
  const projectId = env.FIREBASE_PROJECT_ID;

  function toFirestoreValue(val) {
    if (val === null || val === undefined) return { nullValue: null };
    if (typeof val === "boolean") return { booleanValue: val };
    if (typeof val === "number") return Number.isInteger(val)
      ? { integerValue: String(val) }
      : { doubleValue: val };
    if (typeof val === "string") return { stringValue: val };
    if (Array.isArray(val)) return { arrayValue: { values: val.map(toFirestoreValue) } };
    if (typeof val === "object") return {
      mapValue: {
        fields: Object.fromEntries(
          Object.entries(val).map(([k, v]) => [k, toFirestoreValue(v)])
        )
      }
    };
    return { stringValue: String(val) };
  }

  const fields = Object.fromEntries(
    Object.entries(data).map(([k, v]) => [k, toFirestoreValue(v)])
  );

  const baseUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}`;
  const url    = docId ? `${baseUrl}/${docId}` : baseUrl;
  const method = docId ? "PATCH" : "POST";

  const res = await fetch(url, {
    method,
    headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields })
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Firestore write failed: ${err}`);
  }

  const result = await res.json();
  const autoId = (result.name || "").split("/").pop();
  return { id: docId || autoId, result };
}

async function firestoreRead(env, collection, docId) {
  const token = await getFirebaseAccessToken(env);
  const projectId = env.FIREBASE_PROJECT_ID;
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`;

  const res = await fetch(url, { headers: { "Authorization": `Bearer ${token}` } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Firestore read failed: ${await res.text()}`);

  const doc = await res.json();
  return firestoreDocToObject(doc);
}

async function firestoreDelete(env, collection, docId) {
  const token = await getFirebaseAccessToken(env);
  const projectId = env.FIREBASE_PROJECT_ID;
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`;

  const res = await fetch(url, {
    method: "DELETE",
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (res.status === 404) return true;
  if (!res.ok) throw new Error(`Firestore delete failed: ${await res.text()}`);
  return true;
}

async function firestoreQuery(env, collection, filters = [], limit = 200) {
  const token = await getFirebaseAccessToken(env);
  const projectId = env.FIREBASE_PROJECT_ID;

  function toFirestoreValue(val) {
    if (val === null || val === undefined) return { nullValue: null };
    if (typeof val === "boolean") return { booleanValue: val };
    if (typeof val === "number") return { integerValue: String(val) };
    if (typeof val === "string") return { stringValue: val };
    return { stringValue: String(val) };
  }

  const structuredQuery = { from: [{ collectionId: collection }], limit };

  if (filters.length > 0) {
    const conditions = filters.map(f => ({
      fieldFilter: {
        field: { fieldPath: f.field },
        op: f.op,
        value: toFirestoreValue(f.value)
      }
    }));
    structuredQuery.where = conditions.length === 1
      ? conditions[0]
      : { compositeFilter: { op: "AND", filters: conditions } };
  }

  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ structuredQuery })
  });

  if (!res.ok) throw new Error(`Firestore query failed: ${await res.text()}`);

  const rows = await res.json();
  return rows
    .filter(r => r.document)
    .map(r => ({ id: r.document.name.split("/").pop(), ...firestoreDocToObject(r.document) }));
}

// Delete all documents in a collection (used for re-indexing)
async function firestoreDeleteCollection(env, collection) {
  const token = await getFirebaseAccessToken(env);
  const projectId = env.FIREBASE_PROJECT_ID;

  // Query all docs
  const docs = await firestoreQuery(env, collection, [], 500);

  // Delete each one
  const deletes = docs.map(doc => {
    const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${doc.id}`;
    return fetch(url, { method: "DELETE", headers: { "Authorization": `Bearer ${token}` } });
  });

  await Promise.all(deletes);
  return docs.length;
}

function firestoreDocToObject(doc) {
  if (!doc || !doc.fields) return {};

  function fromValue(val) {
    if (val.nullValue    !== undefined) return null;
    if (val.booleanValue !== undefined) return val.booleanValue;
    if (val.integerValue !== undefined) return parseInt(val.integerValue);
    if (val.doubleValue  !== undefined) return val.doubleValue;
    if (val.stringValue  !== undefined) return val.stringValue;
    if (val.mapValue) return Object.fromEntries(
      Object.entries(val.mapValue.fields || {}).map(([k, v]) => [k, fromValue(v)])
    );
    if (val.arrayValue) return (val.arrayValue.values || []).map(fromValue);
    return null;
  }

  return Object.fromEntries(
    Object.entries(doc.fields).map(([k, v]) => [k, fromValue(v)])
  );
}

// ═══════════════════════════════════════════════════════════════════════════
//  SESSION TOKEN
// ═══════════════════════════════════════════════════════════════════════════

async function createSessionToken(env, mode) {
  const expires = Date.now() + (60 * 60 * 1000);
  const payload = { exp: expires, nonce: crypto.randomUUID(), mode };
  const payloadStr = JSON.stringify(payload);
  const encoder = new TextEncoder();
  const normalizedPw = normalizePassword(env.MASTER_PASSWORD);

  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(normalizedPw),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadStr));

  return btoa(JSON.stringify({ payload, sig: Array.from(new Uint8Array(signature)) }));
}

async function verifySessionToken(token, env) {
  try {
    const parsed = JSON.parse(atob(token));
    const { payload, sig } = parsed;

    if (Date.now() > payload.exp) return { valid: false };

    // Check session blocklist (revoked tokens)
    if (payload.nonce) {
      try {
        const blocked = await firestoreRead(env, "revokedSessions", payload.nonce);
        if (blocked) return { valid: false };
      } catch { /* skip blocklist check on error */ }
    }

    const encoder = new TextEncoder();
    const normalizedPw = normalizePassword(env.MASTER_PASSWORD);

    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(normalizedPw),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC", key, new Uint8Array(sig), encoder.encode(JSON.stringify(payload))
    );

    if (!valid) return { valid: false };
    return { valid: true, mode: payload.mode };
  } catch {
    return { valid: false };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  ACCESS CONTROL
// ═══════════════════════════════════════════════════════════════════════════

const MODE_MEMBERS = {
  ADMIN:           ["shineil", "brother", "father", "mother", "official"],
  OFFICIAL:        ["shineil", "brother", "father", "mother"],
  PARENTS:         ["father", "mother"],
  SHINEIL_PARENTS: ["shineil", "father", "mother"],
  KEVIN_PARENTS:   ["brother", "father", "mother"],
  KEVIN:           ["brother"],
  SHINEIL:         ["shineil"]
};

// ═══════════════════════════════════════════════════════════════════════════
//  4. SHARED VISUAL CSS / HTML
// ═══════════════════════════════════════════════════════════════════════════

const SHARED_HTML_BG = `
  <canvas id="bg-cvs" style="position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;"></canvas>
  <div class="bg-layer">
    <div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div>
  </div>
  <div class="bg-grid-css"></div>
  <div class="bg-scanlines"></div>
  <div class="bg-vignette"></div>
  <script>
    (function(){
      var _MC="${_MC}";
      var c=document.getElementById('bg-cvs'),ctx=c.getContext('2d'),W,H,stars=[],meteors=[];
      function resize(){
        W=c.width=window.innerWidth;H=c.height=window.innerHeight;
        stars=Array.from({length:90},function(){return{
          x:Math.random()*W,y:Math.random()*H,r:Math.random()*1.1+0.2,
          a:Math.random(),da:(Math.random()-0.5)*0.007,
          col:['#6ee7f7','#a78bfa','#f472b6','#ffffff','#4ade80'][Math.floor(Math.random()*5)]
        }});
      }
      setInterval(function(){meteors.push({x:Math.random()*W*1.6,y:-10,vx:-4.5-Math.random()*3,vy:2.5+Math.random()*2,life:1,tail:100+Math.random()*60});},4200);
      function draw(){
        ctx.clearRect(0,0,W,H);
        stars.forEach(function(s){
          s.a+=s.da;if(s.a>1||s.a<0.07)s.da*=-1;
          ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,Math.PI*2);
          ctx.fillStyle=s.col+(Math.floor(s.a*200).toString(16).padStart(2,'0'));ctx.fill();
        });
        meteors=meteors.filter(function(m){return m.life>0;});
        meteors.forEach(function(m){
          var g=ctx.createLinearGradient(m.x,m.y,m.x-m.vx*m.tail/5,m.y-m.vy*m.tail/5);
          g.addColorStop(0,'rgba('+_MC+','+( m.life*0.95)+')');
          g.addColorStop(0.4,'rgba(167,139,250,'+(m.life*0.35)+')');
          g.addColorStop(1,'rgba('+_MC+',0)');
          ctx.beginPath();ctx.moveTo(m.x,m.y);ctx.lineTo(m.x-m.vx*m.tail/5,m.y-m.vy*m.tail/5);
          ctx.strokeStyle=g;ctx.lineWidth=m.life*2;ctx.stroke();
          m.x+=m.vx;m.y+=m.vy;m.life-=0.011;
        });
        requestAnimationFrame(draw);
      }
      resize();window.addEventListener('resize',resize);draw();
    })();
  <\/script>
`;

const SHARED_CSS_STYLES = `
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --c0:#03040a;--acc:#6ee7f7;--acc2:#a78bfa;--acc3:#f472b6;--acc4:#4ade80;
    --txt:#e8eaf6;--txt2:rgba(232,234,246,0.5);--txt3:rgba(232,234,246,0.18);--err:#f87171;
    --glass:rgba(255,255,255,0.032);--gb:rgba(255,255,255,0.08);--gbr:rgba(255,255,255,0.12);
  }
  html,body{height:100%;background:var(--c0);color:var(--txt);font-family:'DM Sans',-apple-system,sans-serif;overflow:hidden}
  .bg-layer{position:fixed;inset:0;z-index:1;pointer-events:none;overflow:hidden}
  .orb{position:absolute;border-radius:50%;filter:blur(90px)}
  .orb1{width:700px;height:700px;top:-250px;left:-200px;background:radial-gradient(circle,rgba(167,139,250,0.16) 0%,transparent 70%);animation:fo1 22s ease-in-out infinite alternate}
  .orb2{width:600px;height:600px;bottom:-220px;right:-180px;background:radial-gradient(circle,rgba(110,231,247,0.13) 0%,transparent 70%);animation:fo2 28s ease-in-out infinite alternate}
  .orb3{width:400px;height:400px;top:50%;left:50%;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(244,114,182,0.07) 0%,transparent 70%);animation:fo3 18s ease-in-out infinite alternate}
  @keyframes fo1{from{transform:translate(0,0)}to{transform:translate(65px,40px)}}
  @keyframes fo2{from{transform:translate(0,0)}to{transform:translate(-55px,-65px)}}
  @keyframes fo3{from{transform:translate(-50%,-50%) scale(0.82)}to{transform:translate(-50%,-50%) scale(1.22)}}
  .bg-grid-css{position:fixed;inset:0;z-index:2;pointer-events:none;
    background-image:linear-gradient(rgba(255,255,255,0.022) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.022) 1px,transparent 1px);
    background-size:64px 64px;
    -webkit-mask-image:radial-gradient(ellipse 75% 75% at 50% 50%,black 0%,transparent 100%);
    mask-image:radial-gradient(ellipse 75% 75% at 50% 50%,black 0%,transparent 100%)}
  .bg-scanlines{position:fixed;inset:0;z-index:3;pointer-events:none;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 3px)}
  .bg-vignette{position:fixed;inset:0;z-index:4;pointer-events:none;
    background:radial-gradient(ellipse at center,transparent 35%,rgba(0,0,0,0.72) 100%)}
  .scene{position:relative;z-index:10;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{
    width:min(92vw,440px);background:var(--glass);border:1px solid var(--gb);border-radius:28px;
    padding:46px 42px 38px;
    backdrop-filter:blur(40px) saturate(1.5);-webkit-backdrop-filter:blur(40px) saturate(1.5);
    box-shadow:0 0 0 1px rgba(255,255,255,0.06) inset,0 1px 0 rgba(255,255,255,0.1) inset,0 48px 96px rgba(0,0,0,0.72);
    position:relative;overflow:hidden
  }
  .card-top-line{position:absolute;top:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,transparent,rgba(167,139,250,0.4) 30%,rgba(110,231,247,0.65) 50%,rgba(167,139,250,0.4) 70%,transparent);
    animation:tls 4s ease-in-out infinite}
  @keyframes tls{0%,100%{opacity:0.35;transform:scaleX(0.55)}50%{opacity:1;transform:scaleX(1)}}
  .card-glow{position:absolute;inset:0;border-radius:28px;pointer-events:none;
    background:radial-gradient(ellipse at 20% -10%,rgba(110,231,247,0.07) 0%,transparent 50%),radial-gradient(ellipse at 85% 108%,rgba(167,139,250,0.06) 0%,transparent 50%)}
  .icon-wrap{width:76px;height:76px;margin:0 auto 28px;position:relative}
  .icon-ring{position:absolute;inset:-9px;border-radius:50%;border:1px solid var(--gb);animation:rp 3.6s ease-in-out infinite}
  .icon-inner{width:100%;height:100%;border-radius:50%;border:1px solid var(--gbr);display:flex;align-items:center;justify-content:center;position:relative;z-index:1}
  .icon-zone{width:76px;height:76px;margin:0 auto 28px;position:relative}
  .ring{position:absolute;border-radius:50%;border:1px solid}
  .r1{inset:-9px;animation:rp 3.6s ease-in-out infinite}
  .r2{inset:-18px;animation:rp 3.6s ease-in-out infinite 0.7s}
  .r3{inset:-28px;animation:rp 3.6s ease-in-out infinite 1.4s}
  @keyframes rp{0%,100%{opacity:0.5;transform:scale(1)}50%{opacity:1;transform:scale(1.08)}}
  .icon-bg{width:100%;height:100%;border-radius:50%;border:1px solid var(--gbr);display:flex;align-items:center;justify-content:center;position:relative;z-index:1}
  .eyebrow{font-family:'Space Mono',monospace;font-size:10px;letter-spacing:.22em;text-transform:uppercase;text-align:center;margin-bottom:10px;opacity:.65;animation:fu .8s .2s both}
  h1{font-family:'Syne',sans-serif;font-weight:800;font-size:28px;letter-spacing:-1px;text-align:center;margin-bottom:8px;animation:fu .8s .3s both}
  .sub{font-size:13.5px;color:var(--txt2);text-align:center;margin-bottom:28px;line-height:1.75;animation:fu .8s .45s both}
  hr.div{border:none;height:1px;margin:0 0 18px;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.07),rgba(110,231,247,0.1),rgba(255,255,255,0.07),transparent);animation:fu .8s .7s both}
  .footer{font-size:11px;color:var(--txt3);text-align:center;letter-spacing:.3px}
  .footer span{font-family:'Syne',sans-serif;font-weight:700}
  @keyframes fu{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
`;

// ─── Gemini retry + model fallback helper ─────────────────────────────────
const GEMINI_MODELS = [
  "gemini-2.5-flash",     // current primary (already in your worker)
  "gemini-1.5-flash",     // fallback 1
  "gemini-1.5-flash-8b",  // fallback 2
  "gemini-1.0-pro",       // fallback 3
];

async function callGeminiFallback(apiKey, payload, maxRetries = 3) {
  for (const model of GEMINI_MODELS) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }
      );
      const data = await res.json();
      const errMsg = (data?.error?.message || "").toLowerCase();

      if (errMsg.includes("high demand") || errMsg.includes("overloaded") || res.status === 503) {
        console.log(`Gemini model ${model} overloaded (attempt ${attempt}/${maxRetries}), waiting...`);
        if (attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1500 * attempt)); // backoff: 1.5s, 3s
          continue;
        }
        break; // tried this model enough, move to next
      }

      return { model, data, ok: res.ok }; // success or a different error
    }
    console.log(`Trying next model after ${model}...`);
  }
  return { model: "none", data: { error: { message: "All Gemini models busy. Try again in a moment." } }, ok: false };
}

async function callFreeAI(env, context, question) {

  const systemPrompt = `You are Shine AI, a warm and intelligent personal assistant for Shineil Keith Mathias and his family. You have access to their private document vault and answer questions based on those documents.

PERSONALITY & TONE:
Speak like a trusted, articulate family secretary — warm, clear, and human. Never robotic. Never stiff. Write the way a well-spoken person would explain something to a close friend.

FORMATTING RULES:
- Always put exactly one space after every full stop, comma, colon, and semicolon before the next word.
- Group related sentences into a single paragraph. Never break a sentence or mid-thought into a new paragraph.
- Start a new paragraph only when the topic genuinely shifts — for example, moving from personal details to financial details.
- For longer answers covering multiple subtopics (e.g. passport + visa + insurance), use a short bold label before each section like: **Passport Details** or **Visa Status** — then write the information in natural sentences beneath it. Do not use bullet points.
- Never write in bullet points or numbered lists. Always use flowing, natural sentences.
- Short answers (one fact) stay as one or two sentences — no formatting needed.
- Bold only the single most important fact in the answer — such as one date, one number, one name, or one key term. Never bold more than one or two words per sentence. Never bold entire phrases, school names, or descriptive clauses.

LANGUAGE RULES:
- Never say "based on the documents", "according to the context", "as per the uploaded files", or any variation.
- Never use robotic phrases like "I have found", "The information indicates", or "It appears that".
- Speak directly: "Shineil's passport expires on 27 January 2036." Not: "According to the document, it appears the passport expiry is 14 March 2028."
- Use contractions naturally where it sounds human: "That's", "Here's", "It's".
- Do not bold adjectives, descriptions, or context — only the raw fact itself. For example: "Shineil is **16 years old**" not "Shineil is a **16-year-old Indian citizen born on 7 March 2010**".

ANSWER STYLE:
- Short factual question → one or two warm sentences.
- Multi-part or detailed question → structured paragraphs with bold subtopic labels, written in natural prose.
- If something is not found → say exactly: "I couldn't find that in the vault — you may want to check manually."

EXAMPLES:
Q: "When does Shineil's passport expire?"
A: "Shineil's passport expires on 14 March 2028."

Q: "Tell me about Shineil's school admission."
A: "Shineil has been granted admission to Privatgymnasium der Herz-Jesu-Missionare in Salzburg, Austria. His course begins in September 2026, and accommodation has been arranged at the school's boarding facility.

**Admission Details**
The school is a private secondary institution in Salzburg. Shineil will be pursuing his secondary education there, with the course commencing in September 2026.

**Accommodation**
He will be staying at the school's boarding facility, which provides a supervised and disciplined living environment."

Q: "What is the health insurance policy number?"
A: "The health insurance policy number is HX-4821-99."`;

  const userMessage = `VAULT DOCUMENTS:\n${context}\n\nQUESTION: ${question}`;

  // ═══════════════════════════════════════════════
  //  RACE ALL PROVIDERS IN PARALLEL — fastest wins
  // ═══════════════════════════════════════════════
  const providers = [];

  // 1️⃣ CLOUDFLARE AI
  if (env.AI) {
    providers.push((async () => {
      const cfTimeout = new Promise((_, rej) => setTimeout(() => rej(new Error("CF AI timeout")), 10000));
      const res = await Promise.race([
        env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user",   content: userMessage  }
          ],
          max_tokens: 2048
        }),
        cfTimeout
      ]);
      if (!res?.response?.trim()) throw new Error("Empty CF AI response");
      return { reply: res.response.trim(), model: "Cloudflare Llama 3.3 70B", source: "cloudflare" };
    })());
  }

  // 2️⃣ GROQ (fastest API, usually <2s)
  if (env.GROQ_API_KEY) {
    providers.push((async () => {
      const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Authorization": `Bearer ${env.GROQ_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          temperature: 0.2,
          max_tokens: 2048,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user",   content: userMessage  }
          ]
        })
      });
      const data = await res.json();
      const errMsg = (data?.error?.message || "").toLowerCase();
      if (res.status === 429 || res.status === 503 || errMsg.includes("rate limit") || errMsg.includes("overloaded")) {
        throw new Error("Groq rate limited");
      }
      const reply = data?.choices?.[0]?.message?.content?.trim();
      if (!reply) throw new Error("Empty Groq response");
      return { reply, model: "Groq Llama 3.3 70B", source: "groq" };
    })());
  }

  // 3️⃣ GEMINI (with model fallback)
  if (env.GEMINI_API_KEY) {
    providers.push((async () => {
      const geminiPayload = {
        contents: [{ parts: [{ text: `${systemPrompt}\n\n${userMessage}` }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 2048 }
      };
      const { model, data, ok } = await callGeminiFallback(env.GEMINI_API_KEY, geminiPayload);
      if (!ok) throw new Error("Gemini all models failed");
      const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
      if (!reply) throw new Error("Empty Gemini response");
      return { reply, model: `Gemini ${model}`, source: "gemini" };
    })());
  }

  // Wait for the first successful provider
  if (providers.length === 0) {
    return { reply: "No AI providers are configured.", model: "none", source: "none" };
  }

  // Promise.any ignores rejected promises — resolves with first success.
  // If ALL reject, it throws an AggregateError which we catch below.
  try {
    const result = await Promise.any(providers);
    console.log(`AI_RACE: Winner → ${result.source} (${result.model})`);
    return result;
  } catch (e) {
    console.log("AI_CHAIN: All providers failed.", e.message);
  }

  console.log("AI_CHAIN: All providers failed.");
  return {
    reply: "I'm temporarily unavailable — all AI services are busy right now. Please try again in a moment.",
    model: "none",
    source: "none"
  };
}
// ═══════════════════════════════════════════════════════════════════════════
//  5. CONTROLLERS
// ═══════════════════════════════════════════════════════════════════════════
const Controllers = {

  // ── Auth helpers ────────────────────────────────────────────────
  async requireAuth(request, env) {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) return null;
    return session;
  },

  async handleRoot(corsOrigin = "null") {
    const html = `
      <!DOCTYPE html><html lang="en"><head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
        <title>Secure Vault Backend</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
          ${SHARED_CSS_STYLES}
          .card-root { width:min(54vw,500px);max-width:1100px;min-height:65vh;animation:cardIn 0.7s cubic-bezier(0.22,1,0.36,1) both; }
          .icon-inner { background:linear-gradient(135deg,rgba(110,231,247,0.15),rgba(167,139,250,0.15)); }
          .icon-inner svg { width:28px;height:28px;color:var(--acc);filter:drop-shadow(0 0 8px rgba(110,231,247,0.6)); }
          .heading { font-family:'Syne',sans-serif;font-weight:800;font-size:24px;letter-spacing:-0.5px;text-align:center;margin-bottom:8px;background:linear-gradient(135deg,#e8eaf6 30%,var(--acc));-webkit-background-clip:text;-webkit-text-fill-color:transparent; }
          .subheading { font-size:14px;color:var(--txt2);text-align:center;margin-bottom:28px;line-height:1.6; }
          .status-badge-container { text-align:center; }
          .status-badge { background:rgba(74,222,128,0.08);color:#4ade80;border:1px solid rgba(74,222,128,0.2);padding:8px 18px;font-size:11px;font-weight:700;border-radius:9999px;display:inline-block;text-transform:uppercase;letter-spacing:0.08em;position:relative;overflow:hidden;font-family:'Syne',sans-serif; }
          .status-badge::after { content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(74,222,128,0.2),transparent);animation:shine 2.5s infinite linear; }
          @keyframes cardIn { from{opacity:0;transform:translateY(28px) scale(0.97);}to{opacity:1;transform:translateY(0) scale(1);} }
          @keyframes shine { to{left:100%;} }
          .card-footer { margin-top:28px;text-align:center;font-size:11px;color:rgba(232,234,246,0.2);letter-spacing:0.3px; }
          .card-footer span { color:rgba(110,231,247,0.35);font-family:'Syne',sans-serif;font-weight:700; }
          .arch-note { margin-top:20px;text-align:center;font-size:11px;color:rgba(232,234,246,0.15);font-family:monospace; }
        </style>
      </head><body>
        ${SHARED_HTML_BG}
        <div class="scene"><div class="card card-root">
          <div class="icon-wrap"><div class="icon-ring"></div><div class="icon-inner">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
            </svg>
          </div></div>
          <h1 class="heading">Gatekeeper Active</h1>
          <p class="subheading">The secure vault backend is running.<br>Welcome to the engine room — mysterious things happen here.<br>Everything works perfectly until one missing semicolon starts a civil war.</p>
          <div class="status-badge-container"><div class="status-badge">System Operational</div></div>
          <div class="arch-note">Made by SHINEIL KEITH MATHIAS</div>
          <div class="card-footer">Protected by <span>ONLINE VAULT</span> · End-to-end encryption</div>
        </div></div>
      </body></html>`;
    return new Response(html, {
      headers: {
        ...SECURITY_HEADERS,
        "Content-Type": "text/html; charset=UTF-8",
        "Access-Control-Allow-Origin": corsOrigin,
        "Vary": "Origin"
      }
    });
  },

  async handleGetFiles(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);

      if (!session.valid) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);

      const object = await env.MY_BUCKET.get("files.json");
      if (!object) return createJsonResponse({ error: "files.json not found" }, 404, corsOrigin);

      const files = JSON.parse(await object.text());
      const userMembers = MODE_MEMBERS[session.mode] ?? [];

      const filtered = {};
      for (const [category, items] of Object.entries(files)) {
        if (!Array.isArray(items)) continue;
        const visible = items.filter(item =>
          Array.isArray(item.members)
            ? item.members.some(m => userMembers.includes(m))
            : userMembers.includes(item.member)
        );
        if (visible.length > 0) filtered[category] = visible;
      }

      return createJsonResponse(filtered, 200, corsOrigin);
    } catch (error) {
      console.error("handleGetFiles error:", error?.stack ?? String(error));
      return createJsonResponse({ error: error.message }, 500, corsOrigin);
    }
  },

  // ═══════════════════════════════════════════════════════════════════════
  // handleGetDoc — now the SINGLE entry point for /docs/, /file/, AND
  // /photos/ requests. All three go through the same member-visibility
  // check and the same bucket-key fallback chain (which now also tries a
  // `photos/` prefix). This is the fix for "/photos or /file always
  // resolves as /docs": previously /photos/ bypassed this handler
  // entirely (going to handleDownload with no per-file access control),
  // and even /file/ requests could never find a file actually stored
  // under a `photos/` bucket key because that prefix was never tried.
  // ═══════════════════════════════════════════════════════════════════════
  async handleGetDoc(request, env, corsOrigin, docPath) {
  const session = await this.requireAuth(request, env);
  if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);

  if (!isPathSafe(docPath)) {
    return createJsonResponse({ error: "Invalid path" }, 400, corsOrigin);
  }

  const object = await env.MY_BUCKET.get("files.json");

  if (!object) {
    return createJsonResponse(
      { error: "files.json not found" },
      404,
      corsOrigin
    );
  }

  const files = JSON.parse(await object.text());
  const userMembers = MODE_MEMBERS[session.mode] ?? [];

  let allowed = false;

  // Check if requested file belongs to visible files
  for (const category of Object.values(files)) {
    if (!Array.isArray(category)) continue;

    for (const item of category) {
      const members = Array.isArray(item.members)
        ? item.members
        : [item.member];

      const canAccess = members.some(m =>
        userMembers.includes(m)
      );

      const filePath =
        item.path ||
        item.url ||
        item.file ||
        "";

      // NOTE: now also strips a leading "photos/" prefix, in addition to
      // "docs/" and "file/", so files.json entries that store their path
      // with a photos/ prefix match correctly regardless of which route
      // (/docs/, /file/, /photos/) the client used to request them.
      const normalizedItemPath = filePath.replace(/\\/g, "/").replace(/^\/?(?:docs\/|file\/|photos\/)?/, "");

      if (
        canAccess &&
        normalizedItemPath === docPath
      ) {
        allowed = true;
        break;
      }
    }

    if (allowed) break;
  }

  if (!allowed && session.mode !== "ADMIN") {
    return createJsonResponse(
      { error: "Forbidden" },
      403,
      corsOrigin
    );
  }

  // NOTE: added a `photos/${docPath}` fallback. Previously this chain only
  // tried the bare path, `docs/`, and `file/` prefixes — so any file whose
  // real bucket key lived under `photos/` could never be found here, and
  // requests would always end up 404ing unless the same file also happened
  // to exist under the docs/ prefix.
  const bucketFile =
  await env.MY_BUCKET.get(docPath) ||
  await env.MY_BUCKET.get(`docs/${docPath}`) ||
  await env.MY_BUCKET.get(`file/${docPath}`) ||
  await env.MY_BUCKET.get(`photos/${docPath}`);

  if (!bucketFile) {
    return new Response(
      "File not found",
      { status: 404 }
    );
  }

  const mimeMap = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png', '.gif': 'image/gif',
    '.webp': 'image/webp', '.bmp': 'image/bmp',
    '.pdf': 'application/pdf',
    '.enc': 'application/octet-stream'
  };
  const ext = '.' + (docPath.split('.').pop() || '').toLowerCase();
  const contentType = mimeMap[ext] || 'application/octet-stream';

  return new Response(
    await bucketFile.arrayBuffer(),
    {
      headers: {
        "Content-Type": contentType,
        "Access-Control-Allow-Origin":
          corsOrigin
      }
    }
  );
},

  async handleFavicon() {
    try {
      const response = await fetch(FAVICON_URL);
      if (!response.ok) throw new Error("favicon fetch failed");
      const imageBuffer = await response.arrayBuffer();
      return new Response(imageBuffer, {
        headers: {
          ...SECURITY_HEADERS,
          "Content-Type": "image/png",
          "Cache-Control": "public, max-age=604800, immutable"
        }
      });
    } catch {
      return new Response(new Uint8Array([
        0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x08,0x06,0x00,0x00,0x00,0x1f,0x15,0xc4,
        0x89,0x00,0x00,0x00,0x0d,0x49,0x44,0x41,0x54,0x78,0x9c,0x63,0x00,0x01,0x00,0x00,
        0x05,0x00,0x01,0x0d,0x0a,0x2d,0xb4,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82
      ]), { headers: { "Content-Type": "image/png" } });
    }
  },

  async handleGetSecret(request, env, corsOrigin) {
    const debugId = crypto.randomUUID();
    try {
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      if (!checkRateLimit(`get-secret:${clientIp}`, 10, 60000)) {
        return createJsonResponse({ success: false, error: "Rate limit exceeded" }, 429, corsOrigin);
      }
      console.log(JSON.stringify({
        event: "GET_SECRET_START", debugId,
        method: request.method,
        origin: request.headers.get("Origin") || "",
        ip: request.headers.get("CF-Connecting-IP") || "",
        hasMasterPassword: !!env.MASTER_PASSWORD
      }));

      if (request.method !== "POST") {
        return createJsonResponse({ success: false, error: "Method not allowed. Use POST.", debugId }, 405, corsOrigin, { "Allow": "POST" });
      }

      if (!env.MASTER_PASSWORD) {
        return createJsonResponse({ success: false, error: "MASTER_PASSWORD is missing", debugId }, 500, corsOrigin);
      }

      const body = await request.json().catch(() => null);
      if (!body) return createJsonResponse({ success: false, error: "Invalid JSON body", debugId }, 400, corsOrigin);

      const sentHash = String(body.hash || "").trim();
      let mode = null;

      if (timingSafeEqual(sentHash, env.ADMIN_HASH))                mode = "ADMIN";
      else if (timingSafeEqual(sentHash, env.OFFICIAL_HASH))        mode = "OFFICIAL";
      else if (timingSafeEqual(sentHash, env.PARENTS_HASH))         mode = "PARENTS";
      else if (timingSafeEqual(sentHash, env.SHINEIL_PARENTS_HASH)) mode = "SHINEIL_PARENTS";
      else if (timingSafeEqual(sentHash, env.KEVIN_PARENTS_HASH))   mode = "KEVIN_PARENTS";
      else if (timingSafeEqual(sentHash, env.KEVIN_HASH))           mode = "KEVIN";
      else if (timingSafeEqual(sentHash, env.SHINEIL_HASH))         mode = "SHINEIL";

      if (!mode) {
        console.log(JSON.stringify({ event: "GET_SECRET_WRONG_PASSWORD", debugId }));
        return createJsonResponse({ success: false, authorized: false, error: "Wrong password", debugId }, 403, corsOrigin);
      }

      const sessionToken = await createSessionToken(env, mode);
      console.log(JSON.stringify({ event: "GET_SECRET_SUCCESS", debugId }));

      return createJsonResponse({
        success: true, authorized: true, mode, sessionToken,
        secret: normalizePassword(env.MASTER_PASSWORD), debugId
      }, 200, corsOrigin);

    } catch (e) {
      console.error("GET_SECRET_CRASH:", debugId, e && e.stack ? e.stack : e);
      return createJsonResponse({ success: false, authorized: false, error: e.message, debugId }, 500, corsOrigin);
    }
  },

  // ─── GET /totp-setup (ADMIN only) — generate QR code URI ─────────────────
async handleTOTPSetup(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);

    if (!session.valid || session.mode !== "ADMIN") {
      return createJsonResponse({ error: "Admin only" }, 403, corsOrigin);
    }

    // Secret is stored in env: TOTP_SECRET
    // Generate the otpauth URI for QR scanning
    const secret = env.TOTP_SECRET;
    if (!secret) return createJsonResponse({ error: "TOTP_SECRET not configured in env" }, 500, corsOrigin);

    const issuer = encodeURIComponent("Secure Vault");
    const account = encodeURIComponent("Shineil");
    const uri = `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=8&period=60`;

    return createJsonResponse({ success: true, uri, secret }, 200, corsOrigin);
  } catch (err) {
    return createJsonResponse({ error: err.message }, 500, corsOrigin);
  }
},

// ─── POST /sync-offline-members — returns all 7 modes' credentials (no secret) for offline caching
async handleSyncOfflineMembers(request, env, corsOrigin) {
  try {
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!checkRateLimit(`sync-offline-members:${clientIp}`, 5, 60000)) {
      return createJsonResponse({ error: "Rate limit exceeded" }, 429, corsOrigin);
    }
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);

    if (!session.valid) {
      return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
    }

    // Return all 7 modes so the client can cache all credentials offline.
    // No 'secret' field is returned — client does NOT need the master secret.
    const ALL_MODES = [
      { envVar: "ADMIN_HASH",           mode: "ADMIN"           },
      { envVar: "OFFICIAL_HASH",        mode: "OFFICIAL"        },
      { envVar: "PARENTS_HASH",         mode: "PARENTS"         },
      { envVar: "SHINEIL_PARENTS_HASH", mode: "SHINEIL_PARENTS" },
      { envVar: "KEVIN_PARENTS_HASH",   mode: "KEVIN_PARENTS"   },
      { envVar: "KEVIN_HASH",           mode: "KEVIN"           },
      { envVar: "SHINEIL_HASH",         mode: "SHINEIL"         }
    ];

    const members = [];
    for (const m of ALL_MODES) {
      const passwordHash = env[m.envVar];
      if (passwordHash) {
        members.push({
          mode: m.mode,
          passwordHash,
          token: await createSessionToken(env, m.mode)
        });
      }
    }

    console.log(`[sync-offline-members] Returning ${members.length} members to mode: ${session.mode}`);

    return createJsonResponse({ success: true, members }, 200, corsOrigin);
  } catch (err) {
    console.error("handleSyncOfflineMembers error:", err);
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

// ─── POST /save-pin-hash — save/update a member's PIN hash for cross-device sync
// v3.8: Always upserts. The client is responsible for verifying the current
// PIN before calling this for a "change", and for checking /get-pin-hashes
// first before calling this for a "set" (so it never blindly overwrites a
// PIN that was already set on another device without the user confirming it).
async handleSavePinHash(request, env, corsOrigin) {
  try {
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!checkRateLimit(`save-pin-hash:${clientIp}`, 5, 60000)) {
      return createJsonResponse({ error: "Rate limit exceeded" }, 429, corsOrigin);
    }
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) {
      return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
    }
    const body = await request.json();
    const { memberKey, pinHash } = body;
    if (!memberKey || !pinHash) {
      return createJsonResponse({ error: "Missing memberKey or pinHash" }, 400, corsOrigin);
    }
    const docId = session.mode + '_' + memberKey;
    await firestoreWrite(env, "vault_pin_hashes", {
      mode: session.mode,
      memberKey,
      pinHash,
      updatedAt: Date.now()
    }, docId);
    return createJsonResponse({ success: true }, 200, corsOrigin);
  } catch (err) {
    console.error("handleSavePinHash error:", err);
    return createJsonResponse({ error: err.message }, 500, corsOrigin);
  }
},

// ─── GET /get-pin-hashes — retrieve all PIN hashes for the session mode ───
async handleGetPinHashes(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) {
      return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
    }
    // Fetch all pin hashes for this session mode
    const prefix = session.mode + '_';
    const docs = await firestoreQuery(env, "vault_pin_hashes");
    const hashes = {};
    if (docs && docs.length) {
      docs.forEach(doc => {
        if (doc.id && doc.id.startsWith(prefix)) {
          const memberKey = doc.id.slice(prefix.length);
          hashes[memberKey] = doc.pinHash;
        }
      });
    }
    return createJsonResponse({ success: true, hashes }, 200, corsOrigin);
  } catch (err) {
    console.error("handleGetPinHashes error:", err);
    return createJsonResponse({ error: err.message }, 500, corsOrigin);
  }
},

// ─── POST /verify-totp — verify a user-submitted code ────────────────────
async handleVerifyTOTP(request, env, corsOrigin) {
  try {
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!checkRateLimit(`verify-totp:${clientIp}`, 10, 60000)) {
      return createJsonResponse({ success: false, error: "Rate limit exceeded" }, 429, corsOrigin);
    }
    const body = await request.json();
    const { code, hash, username } = body;

    if (!code) {
      return createJsonResponse({ success: false, error: "Missing code" }, 400, corsOrigin);
    }

    if (!env.TOTP_SECRET) {
      return createJsonResponse({ success: false, error: "TOTP not configured" }, 500, corsOrigin);
    }

    // Determine mode from hash (password+TOTP flow) or default (TOTP-only flow)
    let mode = null;
    if (hash) {
      if      (timingSafeEqual(hash, env.ADMIN_HASH))          mode = "ADMIN";
      else if (timingSafeEqual(hash, env.OFFICIAL_HASH))        mode = "OFFICIAL";
      else if (timingSafeEqual(hash, env.PARENTS_HASH))         mode = "PARENTS";
      else if (timingSafeEqual(hash, env.SHINEIL_PARENTS_HASH)) mode = "SHINEIL_PARENTS";
      else if (timingSafeEqual(hash, env.KEVIN_PARENTS_HASH))   mode = "KEVIN_PARENTS";
      else if (timingSafeEqual(hash, env.KEVIN_HASH))           mode = "KEVIN";
      else if (timingSafeEqual(hash, env.SHINEIL_HASH))         mode = "SHINEIL";
      if (!mode) {
        return createJsonResponse({ success: false, error: "Invalid password" }, 403, corsOrigin);
      }
    }

    const valid = await verifyTOTP(env.TOTP_SECRET, code.trim());

    if (!valid) {
      return createJsonResponse({ success: false, error: "Invalid or expired code" }, 401, corsOrigin);
    }

    // If no hash provided, default to ADMIN mode for TOTP-only login
    const sessionToken = await createSessionToken(env, mode || "ADMIN");
    return createJsonResponse({
      success: true,
      authorized: true,
      mode: mode || "ADMIN",
      sessionToken,
      secret: normalizePassword(env.MASTER_PASSWORD)
    }, 200, corsOrigin);

  } catch (err) {
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

  async handleLogout(request, env, corsOrigin) {
    try {
      const body = await request.json().catch(() => ({}));
      const { sessionId } = body;
      if (sessionId) await firestoreDelete(env, "activeSessions", sessionId);
      return createJsonResponse({ success: true, message: "Logged out. Session cleared." }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: true, message: "Logged out with fallback cleanup." }, 200, corsOrigin);
    }
  },

  async handleLoginEmail(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const body = await request.json();
      const { email, name, purpose, loginTime, ip, location, device, browser } = body;

      const emailHtml = `
        <h2>🔐 New Vault Login Detected</h2>
        <p><strong>Name:</strong> ${name || 'Unknown'}</p>
        <p><strong>Email:</strong> ${email || 'Not provided'}</p>
        <p><strong>Purpose:</strong> ${purpose || 'Not specified'}</p>
        <p><strong>Login Time:</strong> ${loginTime || new Date().toLocaleString()}</p>
        <p><strong>IP Address:</strong> ${ip || 'Unknown'}</p>
        <p><strong>Location:</strong> ${location || 'Unknown'}</p>
        <p><strong>Device:</strong> ${device || 'Unknown'}</p>
        <p><strong>Browser:</strong> ${browser || 'Unknown'}</p>
      `;

      if (env.RESEND_API_KEY && env.EMAIL_FROM && env.LOGIN_ALERT_EMAIL) {
        console.log(`[LoginEmail] Sending email from=${env.EMAIL_FROM} to=${env.LOGIN_ALERT_EMAIL}`);
        const emailRes = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            from: env.EMAIL_FROM, to: env.LOGIN_ALERT_EMAIL,
            subject: "🔐 Secure Vault Access Notification", html: emailHtml
          })
        });
        if (!emailRes.ok) {
          const errText = await emailRes.text().catch(() => 'unknown');
          console.error(`[LoginEmail] Resend API error (${emailRes.status}): ${errText}`);
        } else {
          console.log('[LoginEmail] Sent successfully');
        }
      } else {
        console.warn('[LoginEmail] Skipped — missing env vars:', {
          hasResendKey: !!env.RESEND_API_KEY,
          hasEmailFrom: !!env.EMAIL_FROM,
          hasAlertEmail: !!env.LOGIN_ALERT_EMAIL
        });
      }

      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleCreateShare(request, env, corsOrigin) {
    try {
      const body = await request.json();
      if (!body.file) return createJsonResponse({ success: false, error: "Missing file parameter" }, 400, corsOrigin);

      let trustedVaultKey = null;
      if (body.vaultKey) {
        const normalizedPw = normalizePassword(env.MASTER_PASSWORD);
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(normalizedPw));
        const expectedHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
        const sentHash = Array.from(new Uint8Array(
          await crypto.subtle.digest("SHA-256", encoder.encode(normalizePassword(body.vaultKey)))
        )).map(b => b.toString(16).padStart(2, "0")).join("");

        if (timingSafeEqual(sentHash, expectedHash)) trustedVaultKey = normalizePassword(body.vaultKey);
      }

      const token = btoa(JSON.stringify({
        file: body.file, name: body.name || "Unnamed Link",
        exp: Date.now() + ((body.expiry || 24) * 3600000),
        pwd: body.password || null, vaultKey: trustedVaultKey
      }));

      return createJsonResponse({ success: true, token }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ═══════════════════════════════════════════════════════════════════════
  // ─── GET /vault-auth-hashes — return SHA-256 hashes of all 7 passwords
  //     for offline login caching in IndexedDB.
  //     Security: only pre-hashed values are sent — plaintext never leaves
  //     the worker. Requires any valid session token.
  // ═══════════════════════════════════════════════════════════════════════
  async handleVaultAuthHashes(request, env, corsOrigin) {
    try {
      // Require a valid session (any member who is already logged in online)
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);

      if (!session.valid) {
        return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      }

      // Each entry: { member: "MODE_KEY", passwordHash: "sha256hex", mode: "MODE_KEY" }
      // The worker stores passwords as already-hashed values in env secrets
      // (ADMIN_HASH, OFFICIAL_HASH, etc.) — these ARE the SHA-256 hashes.
      // We return them directly; no plaintext ever used here.
      const members = [
        { member: "ADMIN",           passwordHash: env.ADMIN_HASH           || "", mode: "ADMIN"           },
        { member: "OFFICIAL",        passwordHash: env.OFFICIAL_HASH        || "", mode: "OFFICIAL"        },
        { member: "PARENTS",         passwordHash: env.PARENTS_HASH         || "", mode: "PARENTS"         },
        { member: "SHINEIL_PARENTS", passwordHash: env.SHINEIL_PARENTS_HASH || "", mode: "SHINEIL_PARENTS" },
        { member: "KEVIN_PARENTS",   passwordHash: env.KEVIN_PARENTS_HASH   || "", mode: "KEVIN_PARENTS"   },
        { member: "KEVIN",           passwordHash: env.KEVIN_HASH           || "", mode: "KEVIN"           },
        { member: "SHINEIL",         passwordHash: env.SHINEIL_HASH         || "", mode: "SHINEIL"         },
      ].filter(m => m.passwordHash); // drop any unconfigured slots

      console.log(`[vault-auth-hashes] Returning ${members.length} member hashes to ${session.mode}`);

      return createJsonResponse({ success: true, members }, 200, corsOrigin);
    } catch (err) {
      console.error("handleVaultAuthHashes error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  GLOBAL STATUS DASHBOARD (v3.8)
  //  Every device that runs the client-side health checks reports its
  //  results here. Firestore stores ONE worst-of-the-day record per
  //  component per date, so every device that opens the Status modal sees
  //  the exact same 90-day uptime bars ("global status" / statuspage-style),
  //  no matter which device produced the report. Each device additionally
  //  keeps running its OWN live checks in real time ("local status") which
  //  are shown immediately without waiting on this endpoint.
  // ═══════════════════════════════════════════════════════════════════════

  // ─── POST /status-report — a device reports today's check results ───────
  async handleStatusReport(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);

      const body = await request.json();
      const results = Array.isArray(body.results) ? body.results : [];
      if (!results.length) return createJsonResponse({ success: false, error: "No results provided" }, 400, corsOrigin);

      const order = { operational: 0, degraded: 1, partial: 2, major: 3, maintenance: 4 };
      const today = new Date();
      const dayKey = today.getFullYear() + '-' + String(today.getMonth() + 1).padStart(2, '0') + '-' + String(today.getDate()).padStart(2, '0');

      // Only escalate — never silently downgrade an incident already logged today
      const writes = [];
      for (const r of results) {
        if (!r || !r.id || !r.state || !(r.state in order)) continue;
        const docId = `${r.id}_${dayKey}`;
        let existing = null;
        try { existing = await firestoreRead(env, "vault_status_history", docId); } catch { /* ignore */ }
        if (existing && order[existing.state] >= order[r.state]) continue; // keep the worse/equal existing state
        writes.push(firestoreWrite(env, "vault_status_history", {
          componentId: r.id,
          label: r.label || r.id,
          icon: r.icon || '⚪',
          date: dayKey,
          state: r.state,
          detail: r.detail || r.labelText || '',
          reportedBy: session.mode,
          updatedAt: Date.now()
        }, docId));
      }
      await Promise.all(writes);

      return createJsonResponse({ success: true, recorded: writes.length }, 200, corsOrigin);
    } catch (err) {
      console.error("handleStatusReport error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── GET /status-history — return the last 90 days for every component ──
  async handleStatusHistory(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);

      const docs = await firestoreQuery(env, "vault_status_history", [], 3000);

      // Group by componentId -> { "YYYY-MM-DD": {state, detail, time} }
      const history = {};
      for (const d of docs) {
        if (!d.componentId || !d.date) continue;
        if (!history[d.componentId]) history[d.componentId] = {};
        history[d.componentId][d.date] = {
          state: d.state,
          detail: d.detail || '',
          time: d.updatedAt ? new Date(d.updatedAt).toISOString() : ''
        };
      }

      return createJsonResponse({ success: true, history }, 200, corsOrigin);
    } catch (err) {
      console.error("handleStatusHistory error:", err);
      return createJsonResponse({ success: false, error: err.message, history: {} }, 500, corsOrigin);
    }
  },

  // ─── POST /frontend-error — client reports a runtime JS/CSS/resource error
  //     so the "Frontend Integrity" component can flip red automatically,
  //     globally, the moment any device hits a broken file. ───────────────
  async handleFrontendError(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);

      const body = await request.json();
      const { source, message, line, col, stack, resourceUrl } = body;

      await firestoreWrite(env, "vault_frontend_errors", {
        source: source || 'unknown',
        message: (message || '').slice(0, 500),
        line: line || 0,
        col: col || 0,
        stack: (stack || '').slice(0, 1000),
        resourceUrl: resourceUrl || '',
        reportedBy: session.mode,
        createdAt: Date.now()
      });

      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── GET /frontend-errors-today — used by the status dashboard to decide
  //     whether to flip the Frontend Integrity component red for everyone ─
  async handleFrontendErrorsToday(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ success: false, count: 0 }, 401, corsOrigin);

      const cutoff = Date.now() - (24 * 60 * 60 * 1000);
      const docs = await firestoreQuery(env, "vault_frontend_errors", [
        { field: "createdAt", op: "GREATER_THAN", value: cutoff }
      ], 200);

      return createJsonResponse({ success: true, count: docs.length, errors: docs.slice(0, 20) }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, count: 0, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── POST /ai-file-indexed ─────────────────────────
async handleAIFileIndexed(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);

    if (!session.valid) {
      return createJsonResponse(
        { success:false, error:"Unauthorized" },
        401,
        corsOrigin
      );
    }

    const body = await request.json();
    const { fileName } = body;

    if (!fileName) {
      return createJsonResponse(
        { success:false, error:"Missing fileName" },
        400,
        corsOrigin
      );
    }

    await firestoreWrite(
      env,
      "ai_index_progress",
      {
        fileName,
        completed: true,
        indexedAt: new Date().toISOString()
      },
      btoa(fileName)
    );

    return createJsonResponse(
      { success:true },
      200,
      corsOrigin
    );

  } catch(err) {
    return createJsonResponse(
      { success:false, error: err.message },
      500,
      corsOrigin
    );
  }
},

// ─── POST /ai-index-progress ──────────────────────
async handleAIIndexProgress(request, env, corsOrigin) {
  try {
    const authHeader =
      request.headers.get("Authorization") || "";

    const token =
      authHeader.replace("Bearer ", "");

    const session =
      await verifySessionToken(token, env);

    if (!session.valid) {
      return createJsonResponse(
        { files: [] },
        401,
        corsOrigin
      );
    }

    const docs = await firestoreQuery(
      env,
      "ai_index_progress",
      [],
      500
    );

    return createJsonResponse({
    success: true,
    files: docs.map(d => d.fileName)
}, 200, corsOrigin);

  } catch(err) {
    return createJsonResponse(
      { success:false, files:[] },
      500,
      corsOrigin
    );
  }
},

  // ─── POST /ai-index ───────────────────────────────────────────────────────
  async handleAIIndex(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);

    if (!session.valid) return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);

    const body = await request.json();
    const { fileName, chunkText, baseFileName, chunkIndex, totalChunks } = body;

    if (!fileName || !chunkText) {
      return createJsonResponse({ success: false, error: "Missing fileName or chunkText" }, 400, corsOrigin);
    }

    // ── Log every incoming chunk ────────────────
    console.log(`AI_INDEX: saving chunk ${chunkIndex + 1}/${totalChunks} for "${baseFileName}" (${chunkText.length} chars)`);

    const { id } = await firestoreWrite(env, "ai_documents", {
      fileName,
      baseFileName: baseFileName || fileName,
      chunkText,
      chunkIndex:  chunkIndex  ?? 0,
      totalChunks: totalChunks ?? 1,
      mode:        session.mode,
      createdAt:   new Date().toISOString()
    });

    console.log(`AI_INDEX: ✅ saved as Firestore doc ID: ${id}`);

    return createJsonResponse({
      success: true,
      message: "Indexed successfully",
      docId:   id
    }, 200, corsOrigin);

  } catch (err) {
    console.error("AI_INDEX_ERROR:", err);
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

  // ─── POST /ai-index-status ────────────────────────────────────────────────
  async handleAIIndexStatus(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);

      if (!session.valid) return createJsonResponse({ indexed: false, count: 0 }, 401, corsOrigin);

      const chunks = await firestoreQuery(env, "ai_documents", [], 1);
      return createJsonResponse({ indexed: chunks.length > 0, count: chunks.length }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ indexed: false, count: 0, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── POST /ai-chunk-status — check if a file is already chunked ──────────
  async handleAIChunkStatus(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ exists: false }, 401, corsOrigin);

      const body = await request.json();
      const { fileName } = body;
      if (!fileName) return createJsonResponse({ exists: false }, 400, corsOrigin);

      // Query by baseFileName field
      const chunks = await firestoreQuery(env, "ai_documents", [
        { field: "baseFileName", op: "EQUAL", value: fileName }
      ], 1);

      return createJsonResponse({ exists: chunks.length > 0 }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ exists: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── POST /ai-chunk-status-all — get ALL indexed file names ──────────────
async handleAIChunkStatusAll(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) return createJsonResponse({ exists: false, files: [] }, 401, corsOrigin);

    // Get all unique baseFileNames from ai_documents
    const chunks = await firestoreQuery(env, "ai_documents", [], 500);

    const fileSet = new Set();
    for (const chunk of chunks) {
      if (chunk.baseFileName) fileSet.add(chunk.baseFileName);
    }

    return createJsonResponse({
      success: true,
      files:   [...fileSet],
      count:   fileSet.size
    }, 200, corsOrigin);

  } catch (err) {
    return createJsonResponse({ success: false, files: [], error: err.message }, 500, corsOrigin);
  }
},
  // ─── POST /ai-chunk-delete — delete all chunks for a file ────────────────
  async handleAIChunkDelete(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);
      if (session.mode !== "ADMIN") return createJsonResponse({ success: false, error: "Admin only" }, 403, corsOrigin);

      const body = await request.json();
      const { fileName } = body;
      if (!fileName) return createJsonResponse({ success: false, error: "Missing fileName" }, 400, corsOrigin);

      // Find all chunks for this file
      const chunks = await firestoreQuery(env, "ai_documents", [
        { field: "baseFileName", op: "EQUAL", value: fileName }
      ], 500);

      // Delete them all
      const token2 = await getFirebaseAccessToken(env);
      const projectId = env.FIREBASE_PROJECT_ID;
      await Promise.all(chunks.map(doc => {
        const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/ai_documents/${doc.id}`;
        return fetch(url, { method: "DELETE", headers: { "Authorization": `Bearer ${token2}` } });
      }));

      console.log(`AI_CHUNK_DELETE: deleted ${chunks.length} chunks for "${fileName}"`);
      return createJsonResponse({ success: true, deleted: chunks.length }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── POST /ai-clear-index — ADMIN only wipes all chunks for re-indexing ──
  async handleAIClearIndex(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);

    if (!session.valid) return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);
    if (session.mode !== "ADMIN") return createJsonResponse({ success: false, error: "Admin only" }, 403, corsOrigin);

    // ── Clear BOTH collections ──────────────────
    const [deletedChunks, deletedProgress] = await Promise.all([
      firestoreDeleteCollection(env, "ai_documents"),
      firestoreDeleteCollection(env, "ai_index_progress")
    ]);

    console.log(`AI_CLEAR_INDEX: deleted ${deletedChunks} chunks, ${deletedProgress} progress records`);

    return createJsonResponse({
      success: true,
      deletedChunks,
      deletedProgress
    }, 200, corsOrigin);

  } catch (err) {
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

// ─── GET /passwords ── list all entries ───────────────────────────────────
async handleGetPasswords(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);

    // Allow any authenticated session to list passwords; frontend filters by member visibility
    const docs = await firestoreQuery(env, "vault_passwords", [], 200);
    return createJsonResponse({ success: true, entries: docs }, 200, corsOrigin);
  } catch (err) {
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

// ─── POST /passwords ── save new entry ────────────────────────────────────
async handleSavePassword(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
    if (session.mode !== "ADMIN") return createJsonResponse({ error: "Forbidden" }, 403, corsOrigin);

    const body = await request.json();
    const { site, username, password, notes, member } = body;
    if (!site || !password) return createJsonResponse({ error: "site and password are required" }, 400, corsOrigin);

    // Encrypt password using PM_ENCRYPTION_KEY (Worker Secret) before storing
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", enc.encode(env.PM_ENCRYPTION_KEY)),
      { name: "AES-GCM" }, false, ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyMaterial, enc.encode(password));
    const encryptedPassword = "v1:" + btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(ct)));

    const { id } = await firestoreWrite(env, "vault_passwords", {
      site,
      username: username || "",
      encryptedPassword,
      notes: notes || "",
      member: member || "",
      pmKeyVersion: "v1",
      createdAt: new Date().toISOString()
    });

    return createJsonResponse({ success: true, id }, 200, corsOrigin);
  } catch (err) {
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

// ─── POST /passwords/get-password ── decrypt & return one password ─────────
async handleGetPassword(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);

    const body = await request.json();
    const { id } = body;
    if (!id) return createJsonResponse({ error: "Missing id" }, 400, corsOrigin);

    const doc = await firestoreRead(env, "vault_passwords", id);
    if (!doc) return createJsonResponse({ error: "Not found" }, 404, corsOrigin);

    // Decrypt with key version support
    const enc = new TextEncoder();
    const encryptedData = doc.encryptedPassword || "";
    const keyVersion = encryptedData.startsWith("v1:") ? "v1" : "legacy";
    const b64Data = encryptedData.replace(/^v1:/, "");
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", enc.encode(env.PM_ENCRYPTION_KEY)),
      { name: "AES-GCM" }, false, ["decrypt"]
    );
    const raw = Uint8Array.from(atob(b64Data), c => c.charCodeAt(0));
    const iv = raw.slice(0, 12);
    const ct = raw.slice(12);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, keyMaterial, ct);
    const password = new TextDecoder().decode(pt);

    return createJsonResponse({ success: true, password }, 200, corsOrigin);
  } catch (err) {
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

// ─── POST /passwords/delete ── delete one entry ────────────────────────────
async handleDeletePassword(request, env, corsOrigin) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);
    if (!session.valid) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
    if (session.mode !== "ADMIN") return createJsonResponse({ error: "Forbidden" }, 403, corsOrigin);

    const body = await request.json();
    const { id } = body;
    if (!id) return createJsonResponse({ error: "Missing id" }, 400, corsOrigin);

    await firestoreDelete(env, "vault_passwords", id);
    return createJsonResponse({ success: true }, 200, corsOrigin);
  } catch (err) {
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

  // ─── POST /ai-search ──────────────────────────────────────────────────────
  async handleAISearch(request, env, corsOrigin) {
  try {
    // 🛡️ Security Check & Session Token Extraction
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace("Bearer ", "");
    const session = await verifySessionToken(token, env);

    if (!session.valid) {
      return createJsonResponse({ success: false, error: "Unauthorized" }, 401, corsOrigin);
    }

    // 📩 Parse Incoming Payload Parameters
    const body = await request.json();
    const question = (body.question || body.query || "").trim();

    if (!question) {
      return createJsonResponse({ success: false, error: "Question missing" }, 400, corsOrigin);
    }

    // 🔍 Step 1: Break question down into basic terms
    const queryTerms = question.toLowerCase().split(/\s+/).filter(term => term.length > 3);

    // 🗄️ Step 2: Extract ALL chunk structures directly from Firestore
    const chunks = await firestoreQuery(env, "ai_documents", [], 1000);

    console.log(`AI_SEARCH: found ${chunks.length} chunks for question: "${question}"`);

    if (!chunks.length) {
      return createJsonResponse({
        success: true,
        reply: "⚠️ No documents have been indexed yet. Please log out and log back in to trigger indexing."
      }, 200, corsOrigin);
    }

    // 🔠 Step 3: Stop-Word Suppression
    const questionWords = question
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, "")
      .split(/\s+/)
      .filter(w => w.length > 2)
      .filter(w => !["the","and","for","what","when","does","did",
                      "who","how","are","was","his","her","their",
                      "this","that","with","have","has"].includes(w));

    console.log(`AI_SEARCH: keywords extracted → [${questionWords.join(", ")}]`);

    // 🏆 Step 4: Combined Multi-Tier Scoring Engine
    const scored = chunks.map(chunk => {
      const textLower = (chunk.chunkText || "").toLowerCase();
      const fileName = (chunk.baseFileName || chunk.fileName || "").toLowerCase();
      let score = 0;

      queryTerms.forEach(term => {
        if (textLower.includes(term)) score++;
      });

      for (const word of questionWords) {
        const matches = (textLower.match(new RegExp(word, "g")) || []).length;
        score += matches;
        if (fileName.includes(word)) score += 5;
      }

      return { ...chunk, score };
    }).filter(c => c.score > 0);

    scored.sort((a, b) => b.score - a.score);

    let matchedChunks = scored.slice(0, scored.length) || chunks;

    if (matchedChunks.length === 0 || matchedChunks[0]?.score === 0) {
      matchedChunks = chunks.slice(0, 15);
    }

    console.log(`AI_SEARCH: top chunks scores → ${matchedChunks.slice(0, 5).map(c => `${c.baseFileName || 'file'}(${c.score || 0})`).join(", ")}`);

    // 🧩 Step 5: Build Context String
    let context = "";
    for (const chunk of matchedChunks) {
      const entry = `--- Document: ${chunk.baseFileName || chunk.fileName || "Unknown File"} ---\n${chunk.chunkText}\n\n`;
      if ((context + entry).length > 50000) break;
      context += entry;
    }

    console.log(`AI_SEARCH: context built → ${context.length} chars from ${matchedChunks.length} chunks`);

    // 🚀 Step 6: Query AI chain
    const aiResponse = await callFreeAI(env, context, question);

    // 📤 Step 7: Return response
    return createJsonResponse({
      success: true,
      reply: aiResponse.reply,
      model: aiResponse.model,
      modelUsed: aiResponse.model,
      source: aiResponse.source,
      chunksUsed: chunks.length,
      results: matchedChunks.map(c => ({
        fileName: c.fileName,
        baseFileName: c.baseFileName,
        chunkIndex: c.chunkIndex
      }))
    }, 200, corsOrigin);

  } catch (err) {
    console.error("AI_SEARCH_ERROR:", err);
    return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
  }
},

  async handleAI(request, env, corsOrigin) {
    try {
      let body;
      try { body = await request.json(); } catch {
        return createJsonResponse({ success: false, error: "Malformed JSON body" }, 400, corsOrigin);
      }
      const { question = "", context = "" } = body;
      if (!question) return createJsonResponse({ success: false, error: "Question missing" }, 400, corsOrigin);

      const aiRes = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "Authorization": `Bearer ${env.OPENAI_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [
            { role: "system", content: "Answer ONLY from supplied vault documents. If absent, say: 'Not found in documents'." },
            { role: "user", content: `DOCUMENTS:\n${context.slice(0, 15000)}\n\nQUESTION:\n${question}` }
          ],
          temperature: 0.15
        })
      });

      const data = await aiRes.json();
      const reply = data?.choices?.[0]?.message?.content || "Could not compile response.";
      return createJsonResponse({ success: true, reply }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleSaveVisitorLog(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const body = await request.json();
      await firestoreWrite(env, "visitorLogs", {
        visitorName: body.visitorName || "Unknown",
        purpose:     body.purpose     || "",
        loginTime:   body.loginTime   || new Date().toLocaleString(),
        logoutTime:  body.logoutTime  || null,
        status:      body.status      || "Logged In",
        device:      body.device      || "Unknown",
        browser:     body.browser     || "",
        platform:    body.platform    || "",
        screen:      body.screen      || "",
        timezone:    body.timezone    || "",
        ipAddress:   body.ipAddress   || request.headers.get("CF-Connecting-IP") || "Unknown",
        location:    body.location    || "Unknown",
        savedAt:     new Date().toISOString()
      });
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      console.error("save-visitor-log error:", err.message);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleRegisterSession(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const body = await request.json();
      const { sessionId, visitor, active, createdAt } = body;
      if (!sessionId) return createJsonResponse({ success: false, error: "Missing sessionId" }, 400, corsOrigin);

      await firestoreWrite(env, "activeSessions", {
        visitor:     visitor   || "Unknown",
        active:      active    !== undefined ? active : true,
        createdAt:   createdAt || new Date().toISOString(),
        forceLogout: false
      }, sessionId);

      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      console.error("register-session error:", err.message);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleCheckSession(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ forceLogout: true }, 401, corsOrigin);
      const body = await request.json();
      const { sessionId } = body;
      if (!sessionId) return createJsonResponse({ forceLogout: false }, 200, corsOrigin);

      const doc = await firestoreRead(env, "activeSessions", sessionId);
      if (!doc) return createJsonResponse({ forceLogout: false }, 200, corsOrigin);

      return createJsonResponse({ forceLogout: doc.forceLogout === true }, 200, corsOrigin);
    } catch (err) {
      console.error("check-session error:", err.message);
      return createJsonResponse({ forceLogout: false }, 200, corsOrigin);
    }
  },

  async handleGetLogs(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);

      const logs = await firestoreQuery(env, "visitorLogs", [], 100);
      return createJsonResponse(logs, 200, corsOrigin);
    } catch (err) {
      console.error("get-logs error:", err.message);
      return createJsonResponse([], 200, corsOrigin);
    }
  },

  async handleRequestPasskey(request, env, corsOrigin) {
    try {
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      if (!checkRateLimit(`request-passkey:${clientIp}`, 5, 60000)) {
        return createJsonResponse({ success: false, error: "Rate limit exceeded" }, 429, corsOrigin);
      }
      const body = await request.json();
      const visitorName = body.visitorName || body.visitorNameName || "";
      const purpose = body.purpose || body.purposeOfAccess || "";

      if (!visitorName || !purpose) {
        return createJsonResponse({ success: false, error: "Name and purpose are required" }, 400, corsOrigin);
      }

      const { id } = await firestoreWrite(env, "accessRequests", {
        visitorName, purpose,
        device: body.device || "Unknown",
        browser: body.browser || "",
        status: "pending",
        createdAt: body.createdAt || body.timestamp || new Date().toISOString(),
        ipAddress: request.headers.get("CF-Connecting-IP") || "Unknown"
      });

      return createJsonResponse({ success: true, requestId: id }, 200, corsOrigin);
    } catch (err) {
      console.error("request-passkey error:", err.message);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleCheckPasskey(request, env, corsOrigin) {
    try {
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      if (!checkRateLimit(`check-passkey:${clientIp}`, 10, 60000)) {
        return createJsonResponse({ success: false, error: "Rate limit exceeded" }, 429, corsOrigin);
      }
      const body = await request.json();
      const { requestId } = body;
      if (!requestId) return createJsonResponse({ success: false, status: "pending" }, 200, corsOrigin);

      const doc = await firestoreRead(env, "accessRequests", requestId);
      if (!doc) return createJsonResponse({ success: false, status: "pending" }, 200, corsOrigin);

      const status = doc.status || "pending";

      if (status === "approved") {
        const oneTimeToken = await createSessionToken(env, "ADMIN");
        return createJsonResponse({ success: true, status: "approved", sessionToken: oneTimeToken }, 200, corsOrigin);
      }
      if (status === "denied" || status === "declined" || status === "rejected") {
        return createJsonResponse({ success: false, status: "denied", error: "Access request denied" }, 403, corsOrigin);
      }
      return createJsonResponse({ success: false, status }, 200, corsOrigin);
    } catch (err) {
      console.error("check-passkey error:", err.message);
      return createJsonResponse({ success: false, status: "pending" }, 200, corsOrigin);
    }
  },

  async handleExpiryReminder(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const body = await request.json();
      const docs = body.docs || [];
      if (!docs.length) return createJsonResponse({ success: true }, 200, corsOrigin);

      const fields = docs.map(d => ({
        name: d.name, value: `Expires in ${d.daysLeft} day(s) — ${d.expiry}`, inline: false
      }));

      const webhookRes = await fetch(env.DISCORD_WEBHOOK, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [{ title: "⏳ Document Expiry Reminder", color: 16753920, fields, timestamp: new Date().toISOString() }]
        })
      });

      if (!webhookRes.ok) return createJsonResponse({ success: false, error: "Discord webhook failed" }, 500, corsOrigin);
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleSecurityAlert(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const body = await request.json();
      await firestoreWrite(env, "security_alerts", {
        type: body.type || "generic",
        message: body.message || "",
        source: body.source || "unknown",
        severity: body.severity || "low",
        reportedBy: session.mode,
        ip: request.headers.get("CF-Connecting-IP") || "",
        createdAt: new Date().toISOString()
      });
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      console.error("security-alert error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleRevokeSession(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session || session.mode !== "ADMIN") return createJsonResponse({ error: "Forbidden" }, 403, corsOrigin);
      const body = await request.json();
      const { nonce } = body;
      if (!nonce) return createJsonResponse({ error: "Missing nonce" }, 400, corsOrigin);
      await firestoreWrite(env, "revokedSessions", { nonce, revokedAt: Date.now(), revokedBy: session.mode }, nonce);
      return createJsonResponse({ success: true, message: "Session revoked" }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleUpload(request, env, corsOrigin, fileName) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const data = await request.arrayBuffer();
      await env.MY_BUCKET.put(fileName, data);
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleDownload(request, env, corsOrigin, fileName) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const object = await env.MY_BUCKET.get(fileName);
      if (!object) return createJsonResponse({ error: "Not found" }, 404, corsOrigin);
      const mimeMap = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.webp': 'image/webp', '.bmp': 'image/bmp',
        '.pdf': 'application/pdf',
        '.enc': 'application/octet-stream'
      };
      const ext = '.' + (fileName.split('.').pop() || '').toLowerCase();
      const contentType = mimeMap[ext] || 'application/octet-stream';
      return new Response(await object.arrayBuffer(), {
        headers: { "Content-Type": contentType, "Access-Control-Allow-Origin": corsOrigin }
      });
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── POST /verify-identity ── validate personal data ─────────────────────
  async handleVerifyIdentity(request, env, corsOrigin) {
    try {
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      if (!checkRateLimit(`verify-identity:${clientIp}`, 5, 60000)) {
        return createJsonResponse({ success: false, error: "Rate limit exceeded" }, 429, corsOrigin);
      }
      const body = await request.json();
      const type = body.type === "embassy" ? "embassy" : "school";
      const prefix = type === "embassy" ? "VALID_EMBASSY" : "VALID_SCHOOL";

      // Input sanitization: enforce max lengths and trim
      const sanitize = (val, maxLen = 200) => typeof val === "string" ? val.trim().slice(0, maxLen) : "";
      const name     = sanitize(body.name, 200);
      const email    = sanitize(body.email, 200);
      const city     = sanitize(body.city, 100);
      const country  = sanitize(body.country, 100);
      const dob      = sanitize(body.dob, 20);
      const loaDate  = sanitize(body.loaDate, 20);

      if (!name || !email || !city || !country || !dob || !loaDate) {
        return createJsonResponse({ success: false, error: "All fields are required" }, 400, corsOrigin);
      }

      // Collect array env vars: NAME_1..20, EMAIL_1..20, CITY_1..20, COUNTRY_1..20
      const collect = (key) => {
        const arr = [];
        for (let i = 1; i <= 20; i++) {
          const v = env[`${prefix}_${key}_${i}`];
          if (v) arr.push(v.toLowerCase());
        }
        return arr;
      };

      const validNames = collect("NAME");
      const validEmails = collect("EMAIL");
      const validCities = collect("CITY");
      const validCountries = collect("COUNTRY");

      // Fallbacks for school
      if (type === "school") {
        if (!validNames.length) validNames.push("peter porenta", "roman neumayer");
        if (!validEmails.length) validEmails.push("roman.neumayer@herzjesugym.at", "peter.porenta@herzjesugym.at", "direktion@herzjesugym.at");
        if (!validCities.length) validCities.push("salzburg");
        if (!validCountries.length) validCountries.push("austria");
      }

      const validDob = env[`${prefix}_DOB`] || (type === "school" ? "2010-03-07" : "");
      const validDateField = env[`${prefix}_${type === "embassy" ? "APPOINTMENT_DATE" : "LOA_DATE"}`] || (type === "school" ? "2026-03-25" : "");

      const checks = {
        name:    validNames.includes(name.toLowerCase()),
        email:   validEmails.includes(email.toLowerCase()),
        city:    validCities.length === 0 || validCities.includes(city.toLowerCase()),
        country: validCountries.length === 0 || validCountries.includes(country.toLowerCase()),
        dob:     dob === validDob,
        loaDate: loaDate === validDateField
      };

      const allValid = Object.values(checks).every(Boolean);

      let passwords = [];
      if (allValid) {
        if (type === "school") {
          const pw = env.VERIFY_SCHOOL_PASSWORD;
          if (pw) passwords.push({ label: "Shineil Mode Password", value: pw });
        } else {
          const pwKevin = env.VERIFY_EMBASSY_PASSWORD_KEVIN_PARENTS;
          const pwShineil = env.VERIFY_EMBASSY_PASSWORD_SHINEIL_PARENTS;
          const pwParents = env.VERIFY_EMBASSY_PASSWORD_PARENTS;
          if (pwKevin) passwords.push({ label: "Kevin's Parents", value: pwKevin });
          if (pwShineil) passwords.push({ label: "Shineil's Parents", value: pwShineil });
          if (pwParents) passwords.push({ label: "Parents Mode", value: pwParents });
        }
      }

      return createJsonResponse({ success: true, valid: allValid, checks, passwords }, 200, corsOrigin);
    } catch (err) {
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  // ─── POST /send-email ── send email template via MailerSend ─────────────
  async handleSendEmail(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      if (session.mode !== "ADMIN") return createJsonResponse({ error: "Forbidden" }, 403, corsOrigin);
      const body = await request.json();
      const { to, subject, templateUrl } = body;

      if (!to || !Array.isArray(to) || to.length === 0) {
        return createJsonResponse({ success: false, error: "Missing or invalid 'to' array" }, 400, corsOrigin);
      }

      const templateUrlFinal = templateUrl || env.EMAIL_TEMPLATE_URL;
      if (!templateUrlFinal) {
        return createJsonResponse({ success: false, error: "No template URL provided and EMAIL_TEMPLATE_URL env var not set" }, 400, corsOrigin);
      }

      const templateRes = await fetch(templateUrlFinal);
      if (!templateRes.ok) {
        return createJsonResponse({ success: false, error: `Failed to fetch template: ${templateRes.status}` }, 502, corsOrigin);
      }
      let htmlContent = await templateRes.text();

      // Replace subject placeholder if present
      const finalSubject = subject || "Submission of Important Updated Documents and Access to Online Vault";

      if (!env.MLS_API_KEY) {
        return createJsonResponse({ success: false, error: "MLS_API_KEY not configured" }, 500, corsOrigin);
      }

      const payload = {
        from: { email: env.EMAIL_FROM || "noreply@shine-ministry.com", name: "Shineil Keith Mathias" },
        to: to.map(r => ({ email: r.email, name: r.name || "" })),
        subject: finalSubject,
        html: htmlContent
      };

      const mlsRes = await fetch("https://api.mailersend.com/v1/email", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.MLS_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      const mlsBody = await mlsRes.text().catch(() => "");

      if (!mlsRes.ok) {
        console.error(`[SendEmail] MailerSend error (${mlsRes.status}): ${mlsBody}`);
        return createJsonResponse({ success: false, error: `MailerSend error: ${mlsRes.status}` }, 502, corsOrigin);
      }

      console.log(`[SendEmail] Sent successfully to ${to.map(r => r.email).join(", ")}`);
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      console.error("[SendEmail] Error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleSaveNotification(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      if (session.mode !== "ADMIN") return createJsonResponse({ error: "Forbidden" }, 403, corsOrigin);
      const body = await request.json();
      const { id, type, targets, title, body: notifBody, priority, timestamp, _key } = body;
      if (!title) return createJsonResponse({ success: false, error: "Title required" }, 400, corsOrigin);
      const docId = _key || id || null;
      await firestoreWrite(env, 'vault_notifications', {
        id: docId,
        type: type || 'global',
        targets: targets || 'all',
        title,
        body: notifBody || '',
        priority: priority || 'info',
        timestamp: timestamp || Date.now(),
        read: false,
        _key: docId,
        createdAt: Date.now()
      }, docId);
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      console.error("[SaveNotification] Error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleGetNotifications(request, env, corsOrigin) {
    try {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.replace("Bearer ", "");
      const session = await verifySessionToken(token, env);
      if (!session.valid) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      const docs = await firestoreQuery(env, 'vault_notifications', [], 200);
      return createJsonResponse({ success: true, notifications: docs }, 200, corsOrigin);
    } catch (err) {
      console.error("[GetNotifications] Error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleDeleteNotification(request, env, corsOrigin) {
    try {
      const session = await this.requireAuth(request, env);
      if (!session) return createJsonResponse({ error: "Unauthorized" }, 401, corsOrigin);
      if (session.mode !== "ADMIN") return createJsonResponse({ error: "Forbidden" }, 403, corsOrigin);
      const body = await request.json();
      const { id } = body;
      if (!id) return createJsonResponse({ error: "Missing id" }, 400, corsOrigin);
      await firestoreDelete(env, 'vault_notifications', id);
      return createJsonResponse({ success: true }, 200, corsOrigin);
    } catch (err) {
      console.error("[DeleteNotification] Error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  },

  async handleVerifyPortal(request, env, corsOrigin) {
    try {
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      if (!checkRateLimit(`verify-portal:${clientIp}`, 10, 60000)) {
        return createJsonResponse({ success: false, error: "Rate limit exceeded" }, 429, corsOrigin);
      }
      const body = await request.json();
      const { portal, password, username } = body;
      if (!portal || !password) {
        return createJsonResponse({ success: false, error: "Missing portal or password" }, 400, corsOrigin);
      }

      if (portal === "admin") {
        const expected = env.ADMIN_PORTAL_PASS;
        if (!expected) return createJsonResponse({ success: false, error: "Portal not configured" }, 500, corsOrigin);
        if (!timingSafeEqual(password, expected)) return createJsonResponse({ success: false, error: "Invalid password" }, 401, corsOrigin);
        return createJsonResponse({ success: true }, 200, corsOrigin);
      }

      if (portal === "notify") {
        const expectedUser = env.NOTIFY_PORTAL_USER || "admin";
        const expectedPass = env.NOTIFY_PORTAL_PASS;
        if (!expectedPass) return createJsonResponse({ success: false, error: "Portal not configured" }, 500, corsOrigin);
        if (!timingSafeEqual(username, expectedUser) || !timingSafeEqual(password, expectedPass)) {
          return createJsonResponse({ success: false, error: "Invalid credentials" }, 401, corsOrigin);
        }
        return createJsonResponse({ success: true }, 200, corsOrigin);
      }

      if (portal === "visitor") {
        const expected = env.VISITOR_PORTAL_PASS;
        if (!expected) return createJsonResponse({ success: false, error: "Portal not configured" }, 500, corsOrigin);
        if (!timingSafeEqual(password, expected)) return createJsonResponse({ success: false, error: "Invalid password" }, 401, corsOrigin);
        return createJsonResponse({ success: true }, 200, corsOrigin);
      }

      return createJsonResponse({ success: false, error: "Unknown portal" }, 400, corsOrigin);
    } catch (err) {
      console.error("[VerifyPortal] Error:", err);
      return createJsonResponse({ success: false, error: err.message }, 500, corsOrigin);
    }
  }
};

// ═══════════════════════════════════════════════════════════════════════════
//  5b. R2 SOUND MIXER API HANDLERS
// ═══════════════════════════════════════════════════════════════════════════

const R2Controllers = {

  async handleR2Auth(request) {
    const authHeader = request.headers.get("X-API-Key");
    if (!authHeader || authHeader !== R2_API_KEY) return false;
    return true;
  },

  async handleR2List(request, env) {
    try {
      const url = new URL(request.url);
      const prefix = url.searchParams.get("prefix") || "";
      const delimiter = "/";
      const folderPrefix = r2ListPrefix(prefix);

      const listed = await env.R2_BUCKET.list({
        prefix: folderPrefix,
        delimiter: delimiter,
        maxKeys: 1000,
      });

      const items = [];

      for (const commonPrefix of listed.delimitedPrefixes) {
        const name = commonPrefix
          .replace(folderPrefix, "")
          .replace(/\/$/, "")
          .split("/")
          .pop() || "";
        if (name) {
          items.push({ name, key: commonPrefix, type: "folder", size: 0, mime: "" });
        }
      }

      for (const obj of listed.objects) {
        if (obj.key === folderPrefix.replace(/\/$/, "")) continue;
        if (!r2IsAudioFile(obj.key)) continue;
        const fullName = obj.key.replace(folderPrefix, "");
        if (fullName.includes("/")) continue;
        const name = fullName.split("/").pop() || "";
        if (name) {
          items.push({
            name, key: obj.key, type: "file",
            size: obj.size, mime: r2GetMime(obj.key)
          });
        }
      }

      items.sort((a, b) => {
        if (a.type !== b.type) return a.type === "folder" ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

      return createJsonResponse({ prefix, items }, 200, "null", {
        "Access-Control-Allow-Origin": "*"
      });
    } catch (err) {
      return createJsonResponse({ error: err.message }, 500, "null", {
        "Access-Control-Allow-Origin": "*"
      });
    }
  },

  async handleR2File(request, env) {
    try {
      const url = new URL(request.url);
      const key = url.searchParams.get("key");
      if (!key) {
        return createJsonResponse({ error: "Missing key parameter" }, 400, "null", {
          "Access-Control-Allow-Origin": "*"
        });
      }

      const object = await env.R2_BUCKET.get(key);
      if (!object) {
        return createJsonResponse({ error: "File not found" }, 404, "null", {
          "Access-Control-Allow-Origin": "*"
        });
      }

      const headers = {
        "Content-Type": object.httpMetadata?.contentType || r2GetMime(key),
        "Content-Length": String(object.size),
        "Cache-Control": "public, max-age=86400",
        "ETag": object.etag,
        "Access-Control-Allow-Origin": "*"
      };

      const range = request.headers.get("Range");
      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : object.size - 1;
        const stream = object.range({ offset: start, length: end - start + 1 });
        return new Response(stream, {
          status: 206,
          headers: {
            ...headers,
            "Content-Range": `bytes ${start}-${end}/${object.size}`,
            "Accept-Ranges": "bytes",
          },
        });
      }

      return new Response(object.body, { headers });
    } catch (err) {
      return createJsonResponse({ error: err.message }, 500, "null", {
        "Access-Control-Allow-Origin": "*"
      });
    }
  },

  async handleR2Stats(env) {
    try {
      const listed = await env.R2_BUCKET.list({ maxKeys: 1 });
      return createJsonResponse({
        bucketExists: true, truncated: listed.truncated
      }, 200, "null", {
        "Access-Control-Allow-Origin": "*"
      });
    } catch (err) {
      return createJsonResponse({ error: err.message }, 500, "null", {
        "Access-Control-Allow-Origin": "*"
      });
    }
  }

};

// ═══════════════════════════════════════════════════════════════════════════
//  6. 403 FIREWALL PAGE
// ═══════════════════════════════════════════════════════════════════════════
function firewallResponse(corsOrigin) {
  const html = `
    <!DOCTYPE html><html lang="en"><head>
      <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
      <title>Access Denied</title>
      <link rel="icon" type="image/png" href="/favicon.png">
      <link href="https://fonts.googleapis.com/css2?family=Syne:wght@800&family=DM+Sans:wght@400;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
      <style>
        ${SHARED_CSS_STYLES}
        .card { border-color:rgba(248,113,113,0.15);box-shadow:0 0 0 1px rgba(255,255,255,0.04) inset,0 32px 64px rgba(0,0,0,0.5),0 0 80px rgba(248,113,113,0.05);animation:dramaticShake 0.5s cubic-bezier(.36,.07,.19,.97) both;transform:translate3d(0,0,0);backface-visibility:hidden; }
        .icon-inner { background:linear-gradient(135deg,rgba(248,113,113,0.15),rgba(167,139,250,0.15)); }
        .icon-inner svg { width:28px;height:28px;color:var(--err);filter:drop-shadow(0 0 8px rgba(248,113,113,0.6)); }
        .heading { font-family:'Syne',sans-serif;font-weight:800;font-size:22px;letter-spacing:-0.5px;text-align:center;margin-bottom:12px;background:linear-gradient(135deg,#e8eaf6 30%,var(--err));-webkit-background-clip:text;-webkit-text-fill-color:transparent; }
        .error-message { font-size:14px;text-align:center;color:rgba(232,234,246,0.75);line-height:1.6;font-weight:400; }
        @keyframes dramaticShake { 10%,90%{transform:translate3d(-2px,0,0);}20%,80%{transform:translate3d(4px,0,0);}30%,50%,70%{transform:translate3d(-6px,0,0);}40%,60%{transform:translate3d(6px,0,0);} }
        .card-footer { margin-top:28px;text-align:center;font-size:11px;color:rgba(232,234,246,0.15);letter-spacing:0.3px; }
        .card-footer span { color:rgba(248,113,113,0.35);font-family:'Syne',sans-serif;font-weight:700; }
      </style>
    </head><body>
      ${SHARED_HTML_BG}
      <div class="scene"><div class="card">
        <div class="icon-wrap"><div class="icon-ring" style="border-color:rgba(248,113,113,0.2)"></div><div class="icon-inner">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"/>
          </svg>
        </div></div>
        <h1 class="heading">Security Boundary Refusal</h1>
        <div class="error-message">Your requesting domain doesn't possess clearance to access this system. The gatekeeper has flagged and restricted your connection.</div>
        <div class="card-footer">Protected by <span>ONLINE VAULT</span> · Connection Aborted</div>
      </div></div>
    </body></html>`;

  return new Response(html, {
    status: 403,
    headers: { ...SECURITY_HEADERS, "Content-Type": "text/html; charset=UTF-8", "Access-Control-Allow-Origin": corsOrigin }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  7. WORKER ENTRYPOINT & ROUTE REGISTRY
// ═══════════════════════════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const method = request.method;
      const origin = request.headers.get("Origin");

      const isOriginAllowed = origin && ALLOWED_ORIGINS.has(origin);
      const corsOrigin = isOriginAllowed ? origin : "null";

      // ── OPTIONS preflight ──────────────────────────────────────────────
      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            ...SECURITY_HEADERS,
            "Access-Control-Allow-Origin": corsOrigin,
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
            "Access-Control-Max-Age": "86400",
            "Vary": "Origin"
          }
        });
      }

      // ── Public routes (no origin check) ──────────────────────────────
      if (url.pathname === "/" && method === "GET") return Controllers.handleRoot(corsOrigin);
      if (method === "GET" && (url.pathname === "/favicon.ico" || url.pathname === "/favicon.png")) {
        return Controllers.handleFavicon();
      }

      // ── R2 Sound Mixer API (X-API-Key auth, no CORS firewall) ────────
      if (url.pathname === "/api/list" && method === "GET") {
        if (!await R2Controllers.handleR2Auth(request)) {
          return createJsonResponse({ error: "Unauthorized" }, 401, "null", { "Access-Control-Allow-Origin": "*" });
        }
        return R2Controllers.handleR2List(request, env);
      }
      if (url.pathname === "/api/file" && method === "GET") {
        if (!await R2Controllers.handleR2Auth(request)) {
          return createJsonResponse({ error: "Unauthorized" }, 401, "null", { "Access-Control-Allow-Origin": "*" });
        }
        return R2Controllers.handleR2File(request, env);
      }
      if (url.pathname === "/api/stats" && method === "GET") {
        if (!await R2Controllers.handleR2Auth(request)) {
          return createJsonResponse({ error: "Unauthorized" }, 401, "null", { "Access-Control-Allow-Origin": "*" });
        }
        return R2Controllers.handleR2Stats(env);
      }

      // ── CORS firewall ─────────────────────────────────────────────────
      if (!isOriginAllowed) return firewallResponse(corsOrigin);

      // ── Rate limiter ──────────────────────────────────────────────────
      let clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      if (env.RATE_LIMITER) {
        try {
          const { success } = await env.RATE_LIMITER.limit({ key: `${clientIp}:${url.pathname}` });
          if (!success) {
            return createJsonResponse({ success: false, error: "Rate limit exceeded. Cool down." }, 429, corsOrigin);
          }
        } catch (e) {
          console.error("RATE_LIMITER_ERROR:", e && e.stack ? e.stack : e);
        }
      } else if (method !== "GET" && method !== "OPTIONS") {
        // In-memory fallback rate limit for state-changing requests
        const rlKey = `${clientIp}:${method}:${url.pathname}`;
        if (!checkRateLimit(rlKey, 60, 60000)) {
          return createJsonResponse({ success: false, error: "Rate limit exceeded. Cool down." }, 429, corsOrigin);
        }
      }

      // ── Body size limit for state-changing requests ──────────────────
if (method === "POST" || method === "PUT") {
  const contentLength = parseInt(request.headers.get("Content-Length") || "0", 10);
  const isUploadRoute = url.pathname.startsWith("/upload/");
  const limit = isUploadRoute ? MAX_UPLOAD_BODY_BYTES : MAX_BODY_BYTES;
  if (contentLength > limit) {
    return createJsonResponse({ error: "Request body too large" }, 413, corsOrigin);
  }
}

      // ── Auth routes ───────────────────────────────────────────────────
      if (url.pathname === "/get-secret"      && method === "POST") return Controllers.handleGetSecret(request, env, corsOrigin);
      if (url.pathname === "/logout"          && method === "POST") return Controllers.handleLogout(request, env, corsOrigin);
      if (url.pathname === "/login-email"     && method === "POST") return Controllers.handleLoginEmail(request, env, corsOrigin);
      if (url.pathname === "/security-alert"  && method === "POST") return Controllers.handleSecurityAlert(request, env, corsOrigin);
      if (url.pathname === "/revoke-session"  && method === "POST") return Controllers.handleRevokeSession(request, env, corsOrigin);

      // ── File routes ───────────────────────────────────────────────────
      if (url.pathname === "/files.json"      && method === "GET")  return Controllers.handleGetFiles(request, env, corsOrigin);
      if (url.pathname === "/create-share"    && method === "POST") return Controllers.handleCreateShare(request, env, corsOrigin);

      // ── Offline auth hashes ───────────────────────────────────────────
      if (url.pathname === "/vault-auth-hashes" && method === "GET") return Controllers.handleVaultAuthHashes(request, env, corsOrigin);

      // ── AI routes ─────────────────────────────────────────────────────
      if (url.pathname === "/ai-index"        && method === "POST") return Controllers.handleAIIndex(request, env, corsOrigin);
      if (url.pathname === "/ai-index-status" && (method === "POST" || method === "PUT")) return Controllers.handleAIIndexStatus(request, env, corsOrigin);
      if (url.pathname === "/ai-clear-index"  && method === "POST") return Controllers.handleAIClearIndex(request, env, corsOrigin);
      if (url.pathname === "/ai-file-indexed"   && method === "POST") return Controllers.handleAIFileIndexed(request, env, corsOrigin);
      if (url.pathname === "/ai-index-progress" && method === "POST") return Controllers.handleAIIndexProgress(request, env, corsOrigin);
      if (url.pathname === "/ai-search"       && method === "POST") return Controllers.handleAISearch(request, env, corsOrigin);
      if (url.pathname === "/ai"              && method === "POST") return Controllers.handleAI(request, env, corsOrigin);

      // ── Session / log routes ──────────────────────────────────────────
      if (url.pathname === "/save-visitor-log"  && method === "POST") return Controllers.handleSaveVisitorLog(request, env, corsOrigin);
      if (url.pathname === "/register-session"  && method === "POST") return Controllers.handleRegisterSession(request, env, corsOrigin);
      if (url.pathname === "/check-session"     && method === "POST") return Controllers.handleCheckSession(request, env, corsOrigin);
      if (url.pathname === "/get-logs"          && method === "POST") return Controllers.handleGetLogs(request, env, corsOrigin);
      if (url.pathname === "/expiry-reminder"   && method === "POST") return Controllers.handleExpiryReminder(request, env, corsOrigin);
      if (url.pathname === "/request-passkey"   && method === "POST") return Controllers.handleRequestPasskey(request, env, corsOrigin);
      if (url.pathname === "/ai-chunk-status"   && method === "POST") return Controllers.handleAIChunkStatus(request, env, corsOrigin);
      if (url.pathname === "/totp-setup"        && method === "GET")  return Controllers.handleTOTPSetup(request, env, corsOrigin);
      if (url.pathname === "/verify-totp"       && method === "POST") return Controllers.handleVerifyTOTP(request, env, corsOrigin);
      if (url.pathname === "/check-passkey"     && method === "POST") return Controllers.handleCheckPasskey(request, env, corsOrigin);
      if (url.pathname === "/ai-chunk-status-all" && method === "POST") return Controllers.handleAIChunkStatusAll(request, env, corsOrigin);
      if (url.pathname === "/passwords"              && method === "GET")  return Controllers.handleGetPasswords(request, env, corsOrigin);
      if (url.pathname === "/passwords"              && method === "POST") return Controllers.handleSavePassword(request, env, corsOrigin);
      if (url.pathname === "/passwords/get-password" && method === "POST") return Controllers.handleGetPassword(request, env, corsOrigin);
      if (url.pathname === "/passwords/delete"       && method === "POST") return Controllers.handleDeletePassword(request, env, corsOrigin);
      if (url.pathname === "/sync-offline-members" && method === "POST") return Controllers.handleSyncOfflineMembers(request, env, corsOrigin);
      if (url.pathname === "/ai-chunk-delete"        && method === "POST") return Controllers.handleAIChunkDelete(request, env, corsOrigin);
      if (url.pathname === "/verify-identity"        && method === "POST") return Controllers.handleVerifyIdentity(request, env, corsOrigin);
      if (url.pathname === "/send-email"              && method === "POST") return Controllers.handleSendEmail(request, env, corsOrigin);
      if (url.pathname === "/verify-portal"           && method === "POST") return Controllers.handleVerifyPortal(request, env, corsOrigin);

      // ── PIN sync routes ──────────────────────────────────────────────────
      if (url.pathname === "/save-pin-hash" && method === "POST") return Controllers.handleSavePinHash(request, env, corsOrigin);
      if (url.pathname === "/get-pin-hashes" && method === "GET") return Controllers.handleGetPinHashes(request, env, corsOrigin);

      // ── Notification routes ────────────────────────────────────────────
      if (url.pathname === "/save-notification"      && method === "POST") return Controllers.handleSaveNotification(request, env, corsOrigin);
      if (url.pathname === "/get-notifications"      && method === "POST") return Controllers.handleGetNotifications(request, env, corsOrigin);
      if (url.pathname === "/delete-notification"    && method === "POST") return Controllers.handleDeleteNotification(request, env, corsOrigin);

      // ── Global status dashboard routes (v3.8) ──────────────────────────
      if (url.pathname === "/status-report"           && method === "POST") return Controllers.handleStatusReport(request, env, corsOrigin);
      if (url.pathname === "/status-history"          && method === "GET")  return Controllers.handleStatusHistory(request, env, corsOrigin);
      if (url.pathname === "/frontend-error"          && method === "POST") return Controllers.handleFrontendError(request, env, corsOrigin);
      if (url.pathname === "/frontend-errors-today"   && method === "GET")  return Controllers.handleFrontendErrorsToday(request, env, corsOrigin);

      // ── Bucket routes ─────────────────────────────────────────────────
      // FIX (v3.9): /photos/ now routes through the SAME handleGetDoc used
      // by /docs/ and /file/, instead of going to the unfiltered
      // handleDownload. All three prefixes are stripped and passed through
      // one consistent, access-controlled path so a file whose bucket key
      // lives under photos/ resolves correctly no matter which of the
      // three URL prefixes the client used.
      if (
        method === "GET" &&
        (
          url.pathname.startsWith("/docs/") ||
          url.pathname.startsWith("/file/") ||
          url.pathname.startsWith("/photos/")
        )
      ) {
        let cleanPath = url.pathname
          .replace(/^\/docs\//, "")
          .replace(/^\/file\//, "")
          .replace(/^\/photos\//, "");
        try { cleanPath = decodeURIComponent(cleanPath); } catch {}
        return Controllers.handleGetDoc(request, env, corsOrigin, cleanPath);
      }

      if (method === "PUT"  && url.pathname.startsWith("/upload/"))   return Controllers.handleUpload(request, env, corsOrigin, url.pathname.replace("/upload/", ""));
      if (method === "GET"  && url.pathname.startsWith("/download/")) return Controllers.handleDownload(request, env, corsOrigin, url.pathname.replace("/download/", ""));

      if (method === "GET") return firewallResponse(corsOrigin);

      return createJsonResponse({ success: false, error: "Endpoint route non-existent" }, 404, corsOrigin);

    } catch (err) {
      console.error("UNCAUGHT_WORKER_ERROR:", err && err.stack ? err.stack : err);
      return createJsonResponse({ success: false, error: err && err.message ? err.message : String(err) }, 500, "null");
    }
  }
};