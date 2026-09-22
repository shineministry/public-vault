/* =========================
   GLOBAL VARIABLES SIT
========================= */
var masterPassword = "";

/* =========================
   DEFENSIVE CLEANUP
   Guarantees no leftover login-step markup — especially the reCAPTCHA
   widget, whose offline "could not connect" fallback text was showing up
   below the file list — can ever remain visible once the dashboard is up,
   no matter which login path (online, offline, TOTP, silent re-auth) got
   the user there.
========================= */
function hideAllAuthSteps() {
    ['step1', 'step2', 'step3', 'step-totp', 'passkey-wait', 'virtual-keypad-overlay'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });
    // Reset the widget so it isn't left mid-render / showing a stale
    // "no connection" state next time step3 is actually needed.
    if (typeof grecaptcha !== 'undefined') {
        try { grecaptcha.reset(); } catch (e) {}
    }
}


// ── HTML escape helper (prevents XSS in innerHTML) ──────────────────────
window.escHtml = function(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

function showCurtain(){
    const c = document.getElementById('white-curtain');
    if(c) c.classList.add('show');
}
function hideCurtain(delay){
    const c = document.getElementById('white-curtain');
    if(!c) return;
    setTimeout(()=>{ c.classList.remove('show'); }, delay || 50);
}

let sessionSeconds = 3600;

   let failedAttempts = 0;
let lockUntil = 0;

let currentBlobUrl = null;
let currentDecryptedPdf = null;
   
let sessionStartTime = null;

   let sessionId = crypto.randomUUID();
window.allFilesData = {};
window.SHINE_AUTH_VERSION = '20260607-offlinefix3';
let currentCategory = "";
   
   async function sha256Bytes(text){

    const enc =
    new TextEncoder();

    const hashBuffer =
    await crypto.subtle.digest(
        "SHA-256",
        enc.encode(text)
    );

    return new Uint8Array(
        hashBuffer
    );
}

/* =========================
   LITE MODE ENGINE
========================= */

window.LITE_MODE = false;

function detectLiteMode() {

    // Manual override
    const saved =
    localStorage.getItem(
        "vault-lite-mode"
    );

    if(saved !== null){

        window.LITE_MODE =
        saved === "true";

        document.body.classList.toggle(
            "lite-mode",
            window.LITE_MODE
        );

        return;
    }

    const cpu =
    navigator.hardwareConcurrency || 4;

    const memory =
    navigator.deviceMemory || 8;

    const isMobile =
    /Android|iPhone|iPad|iPod|Mobile/i
    .test(navigator.userAgent);

    const smallScreen =
    window.innerWidth <= 767;

    // Desktop/Laptop → NEVER lite automatically
    if(!isMobile){

        window.LITE_MODE =
        false;

    } else {

        // Mobile only
        window.LITE_MODE =

            cpu <= 4 ||

            memory <= 4 ||

            smallScreen;
    }

    document.body.classList.toggle(
        "lite-mode",
        window.LITE_MODE
    );


}

function toggleLiteMode(){

    window.LITE_MODE =
        !window.LITE_MODE;

    document.body.classList.toggle(
        "lite-mode",
        window.LITE_MODE
    );

    localStorage.setItem(
        "vault-lite-mode",
        window.LITE_MODE
    );

    location.reload();
}

detectLiteMode();

function notifyBackendLogout(reason = "Logged out.") {

    const visitorInput = document.getElementById("user-name");
    const visitorName = visitorInput ? visitorInput.value : "";

    const logPayload = JSON.stringify({
        visitorName,
        logoutTime: new Date().toLocaleString(),
        status: reason
    });

    const sessionPayload = JSON.stringify({
        sessionId,
        visitor: visitorName,
        active: false,
        endedAt: new Date().toISOString(),
        reason
    });

    try {
        fetch(
            "https://backend.shinumaths989.workers.dev/save-visitor-log",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: logPayload,
                keepalive: true
            }
        ).catch(() => {});
    } catch(e) {}

    try {
        fetch(
            "https://backend.shinumaths989.workers.dev/register-session",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: sessionPayload,
                keepalive: true
            }
        ).catch(() => {});
    } catch(e) {}
}

async function logoutVault( reason = "Logged out.", clearTrust = false ) {

    clearTimeout( inactivityTimer );
    if (typeof _sessionTimerInterval !== 'undefined' && _sessionTimerInterval) {
        clearInterval(_sessionTimerInterval);
        _sessionTimerInterval = null;
    }
    if (typeof _forceLogoutInterval !== 'undefined' && _forceLogoutInterval) {
        clearInterval(_forceLogoutInterval);
        _forceLogoutInterval = null;
    }
    _inactivityMonitorAttached = false;

    notifyBackendLogout(reason);

    if (!clearTrust) {
        // FIX: Before wiping sessionStorage, refresh the trust device record
        // (if this device is marked trusted) with the current live token and
        // secret. The 1-hour session token in vaultTrustInfo otherwise goes
        // stale after the first hour, and the next auto-restore-as-trusted
        // would try to reuse a dead token / mismatched secret, leading to
        // "Session not unlocked" even though the device shows as trusted.
        try {
            const _trust = JSON.parse(localStorage.getItem('vaultTrustInfo') || 'null');
            if (_trust && _trust.member && _trust.expiry > Date.now()) {
                const _liveToken = sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession') || _trust.token || '';
                // Never write window.masterPassword raw into localStorage — it must
                // go through the same encryption saveTrustDevice() uses, or DevTools
                // > Application > Local Storage would show the master secret in plain text.
                const _refreshSecret = window.masterPassword
                    ? await (typeof _wrapTrustSecret === 'function' ? _wrapTrustSecret(window.masterPassword) : Promise.resolve(_trust.secret || ''))
                    : (_trust.secret || '');
                localStorage.setItem('vaultTrustInfo', JSON.stringify({
                    ..._trust,
                    token: _liveToken,
                    secret: _refreshSecret
                }));
            }
        } catch(e) { console.warn('[logoutVault] trust info refresh failed:', e); }
    } else {
        localStorage.removeItem('vaultTrustInfo');
    }

    // Wipe session storage entirely
    sessionStorage.clear();

    // Clear memory string values
    window.masterPassword = null;
    masterPassword = "";
    failedAttempts = 0;

    // FIX: Force clear inputs so the browser doesn't submit stale/cached text values
    if (document.getElementById("user-name")) document.getElementById("user-name").value = "";
    if (document.getElementById("user-purpose")) document.getElementById("user-purpose").value = "";
    if (document.getElementById("vault-pass")) document.getElementById("vault-pass").value = "";
    if (document.getElementById("terms-tick")) document.getElementById("terms-tick").checked = false;

    // FIX: Reset reCAPTCHA if it was initialized
    try {
        if (typeof grecaptcha !== 'undefined') {
            grecaptcha.reset();
        }
    } catch(e) { console.log(e); }

    // If user is offline and session expired, show offline notification overlay
    if (!navigator.onLine && /session expired|session has expired/i.test(reason)) {
        const _ov = document.getElementById('offline-session-overlay');
        if (_ov) { _ov.style.display = 'flex'; }
        return;
    }

    showNotification('Session Ended', reason || 'Your session has ended.', {type:'warning'});

    // Hard refresh to completely clear window context
    location.reload(true);
}

/* =========================
   CLOCK
========================= */

function showLogoutOptions() {
    const overlay = document.createElement('div');
    overlay.id = 'logout-options-overlay';
    Object.assign(overlay.style, {
        position:'fixed',inset:'0',zIndex:'10000',
        display:'flex',alignItems:'center',justifyContent:'center',
        background:'rgba(0,0,0,.5)',backdropFilter:'blur(4px)'
    });
    overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
    overlay.innerHTML = `
        <div style="background:#fff;border-radius:20px;padding:28px 24px;max-width:360px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.25);text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;"><i data-lucide="log-out" style="width:32px;height:32px;color:#0f172a;"></i></div>
            <div style="font-weight:800;font-size:17px;color:#0f172a;margin-bottom:4px;">Logout Options</div>
            <div style="font-size:13px;color:#64748b;margin-bottom:20px;">How would you like to log out?</div>
            <button onclick="logoutVault('Logged out completely.', true);document.getElementById('logout-options-overlay').remove();" style="width:100%;padding:14px;border:none;border-radius:12px;background:#ef4444;color:white;font-weight:800;font-size:14px;cursor:pointer;margin-bottom:10px;"><i data-lucide="ban" style="width:16px;height:16px;vertical-align:middle;"></i> Logout Completely</button>
            <div style="font-size:11px;color:#94a3b8;margin:-6px 0 14px;">Clears trusted device — you'll need to log in fully next time</div>
            <button onclick="logoutVault('Logged out.', false);document.getElementById('logout-options-overlay').remove();" style="width:100%;padding:14px;border:1px solid #e2e8f0;border-radius:12px;background:transparent;color:#0f172a;font-weight:700;font-size:14px;cursor:pointer;"><i data-lucide="unlock" style="width:16px;height:16px;vertical-align:middle;"></i> Logout (Keep Trusted)</button>
            <div style="font-size:11px;color:#94a3b8;margin-top:4px;">Keeps device trusted for faster login next time</div>
            <button onclick="document.getElementById('logout-options-overlay').remove();" style="margin-top:16px;padding:8px 20px;border:none;border-radius:8px;background:transparent;color:#64748b;font-size:13px;cursor:pointer;">Cancel</button>
        </div>`;
    document.body.appendChild(overlay);
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function safeShowLogoutOptions() {
  if (typeof showLogoutOptions === 'function') {
    showLogoutOptions();
  } else {
    setTimeout(function() {
      if (typeof showLogoutOptions === 'function') {
        showLogoutOptions();
      } else {
        if (confirm('Logout completely?')) {
          logoutVault('Logged out.', true);
        }
      }
    }, 500);
  }
}

document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    setInterval(updateClock, 1000);
});

function updateClock(){

    return;

}

/* ========================= EXTRACT PDF TEXT ========================= */
async function searchAI() {

  try {

    const query =
      document
      .getElementById(
        "unified-search"
      )
      .value
      .trim()
      .toLowerCase();

    if (!query) {
      toastNotify('Please enter a search term.', 'warning');
      return;
    }

    const token =
      sessionStorage.getItem('vaultSessionToken') ||
      sessionStorage.getItem('vaultSession') || '';

    const res =
      await fetch(
        "https://backend.shinumaths989.workers.dev/ai-search",
        {
          method: "POST",

          headers: {
            "Content-Type":
            "application/json",

            "Authorization":
            `Bearer ${token}`
          },

          body: JSON.stringify({
  question: query
})
        }
      );

    const data =
      await res.json();

    console.log(data);

    if (
      !data.results ||
      data.results.length === 0
    ) {
      toastNotify('No matching document found.', 'info');
      return;
    }

    toastNotify('Found in: ' + data.results.map(x => x.fileName).join(', '), 'success');

  } catch (err) {

    console.error(err);

    toastNotify('AI Search failed. Please try again.', 'error');
  }
}

async function extractPDFText(file) {
  const arrayBuffer = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;

  let fullText = "";

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    console.log(`extractPDFText: processing page ${i}/${pdf.numPages}`);

    // ── PASS 1: Native text layer ──────────────────────────────────────────
    // Works for digital/born-digital PDFs (bank statements, certificates, etc.)
    let layerText = "";
    try {
      const content = await page.getTextContent();
      layerText = content.items
        .map(item => item.str)
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
    } catch (e) {
      console.warn(`extractPDFText: text layer failed page ${i}:`, e);
    }

    if (layerText.length > 50) {
      // Rich native text — use it directly
      console.log(`extractPDFText: page ${i} native text (${layerText.length} chars)`);
      fullText += layerText + "\n";
      continue; // no need to OCR this page
    }

    // ── PASS 2: OCR (scanned / image-based pages) ──────────────────────────
    // Covers passports, ID cards, certificates, handwritten docs, scanned PDFs
    try {
      const baseViewport = page.getViewport({ scale: 1.0 });

      // Scale up to at least 2480px wide (A4 at 300 DPI) for maximum OCR accuracy
      const TARGET_WIDTH = 2480;
      const scaleNeeded  = Math.max(
        3.0,                              // minimum 3× always
        TARGET_WIDTH / baseViewport.width // or whatever gets us to 300 DPI equivalent
      );

      const viewport = page.getViewport({ scale: scaleNeeded });
      const canvas   = document.createElement("canvas");
      canvas.width   = Math.ceil(viewport.width);
      canvas.height  = Math.ceil(viewport.height);

      console.log(`extractPDFText: page ${i} OCR canvas = ${canvas.width}×${canvas.height}px (scale ${scaleNeeded.toFixed(2)}×)`);

      // Render PDF page onto canvas
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#ffffff";           // white background (helps OCR on transparent pages)
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      await page.render({ canvasContext: ctx, viewport }).promise;

      // Hard guard — Tesseract requires at least 3px width
      if (canvas.width < 10 || canvas.height < 10) {
        console.warn(`extractPDFText: page ${i} canvas too small — skipping OCR`);
        continue;
      }

      // ── Contrast enhancement pass (greyscale + contrast boost) ────────
      // Improves recognition on faded stamps, light ink, MRZ zones
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const d = imgData.data;
      for (let p = 0; p < d.length; p += 4) {
        // Convert to greyscale
        const grey = 0.299 * d[p] + 0.587 * d[p + 1] + 0.114 * d[p + 2];
        // Apply contrast stretch (push towards black/white)
        const enhanced = grey < 128
          ? Math.max(0,   grey * 0.75)        // darken dark pixels
          : Math.min(255, 128 + (grey - 128) * 1.4); // brighten light pixels
        d[p] = d[p + 1] = d[p + 2] = enhanced;
        d[p + 3] = 255; // fully opaque
      }
      ctx.putImageData(imgData, 0, 0);

      // ── Run Tesseract with optimal settings ───────────────────────────
      const { data: { text } } = await Tesseract.recognize(canvas, "eng", {
        logger: () => {},
        tessedit_pageseg_mode:        "6",   // uniform block — scan everything
        tessedit_ocr_engine_mode:     "1",   // LSTM neural net only (most accurate)
        preserve_interword_spaces:    "1",   // keep spacing (important for MRZ)
        tessedit_char_whitelist:      "",    // no whitelist — recognize all characters
        min_characters_to_try:        "1",   // never skip short lines
      });

      const ocrText = (text || "").replace(/\s+/g, " ").trim();
      console.log(`extractPDFText: page ${i} OCR extracted ${ocrText.length} chars`);

      // If OCR returned nothing useful AND native layer had something (even thin), use native
      if (ocrText.length < 10 && layerText.length > 0) {
        console.warn(`extractPDFText: page ${i} OCR thin — falling back to native layer`);
        fullText += layerText + "\n";
      } else {
        fullText += ocrText + "\n";
      }

    } catch (ocrErr) {
      console.warn(`extractPDFText: OCR failed page ${i}:`, ocrErr);
      // Last resort: if native layer had anything at all, save it
      if (layerText.length > 0) {
        fullText += layerText + "\n";
      }
    }
  }

  return fullText;
}

/* ===== GEMINI AI CHAT ===== */

// ════════════════════════════════════════════
//  TOTP FRONTEND LOGIC
// ════════════════════════════════════════════

let _totpHash = null;        // holds password hash from step3
let _totpTimerInterval = null;

// ── Called from onCaptchaSuccess (your existing auth flow) ──
// Replace your existing successful login call with this:
// Instead of directly calling /get-secret, call startTOTPStep(hash)

function startTOTPStep(hash) {
  _totpHash = hash;
  showStepTOTP();
  startTOTPCountdown();
  focusFirstDigit();
}

function showStepTOTP() {
  document.getElementById("step1").style.display       = "none";
  document.getElementById("step2").style.display       = "none";
  document.getElementById("step3").style.display       = "none";
  document.getElementById("step-totp").style.display   = "flex";
  clearTOTPBoxes();
  hideTOTPError();
}

function showStep1() {
  document.getElementById("step-totp").style.display = "none";
  document.getElementById("step1").style.display     = "flex";
  stopTOTPCountdown();
  window._otpRequested = false;
}

// ── Digit box auto-advance + backspace ──────
document.addEventListener("DOMContentLoaded", () => {
  const digits = document.querySelectorAll(".totp-digit");

  digits.forEach((box, i) => {
    box.addEventListener("input", () => {
      // only keep numbers
      box.value = box.value.replace(/\D/g, "").slice(-1);
      if (box.value && i < digits.length - 1) {
        digits[i + 1].focus();
      }
      // auto-submit when last digit filled
      if (i === digits.length - 1 && box.value) {
        setTimeout(submitTOTP, 120);
      }
    });

    box.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !box.value && i > 0) {
        digits[i - 1].focus();
        digits[i - 1].value = "";
      }
    });

    // allow paste of full 8-digit code
    box.addEventListener("paste", (e) => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData)
        .getData("text").replace(/\D/g, "").slice(0, 8);
      digits.forEach((d, j) => { d.value = pasted[j] || ""; });
      if (pasted.length === 8) setTimeout(submitTOTP, 120);
    });
  });
});

function focusFirstDigit() {
  setTimeout(() => {
    const first = document.querySelector(".totp-digit");
    if (first) first.focus();
  }, 200);
}

function clearTOTPBoxes() {
  document.querySelectorAll(".totp-digit").forEach(d => {
    d.value = "";
    d.classList.remove("error");
  });
}

function getTOTPCode() {
  return [...document.querySelectorAll(".totp-digit")]
    .map(d => d.value).join("");
}

// ── Countdown ring (60s TOTP window) ────────
function startTOTPCountdown() {
  stopTOTPCountdown();

  function tick() {
    const sec = 60 - (Math.floor(Date.now() / 1000) % 60);
    const ring = document.getElementById("totp-ring");
    const label = document.getElementById("totp-timer-label");
    if (!ring) return;

    const pct = sec / 60;
    ring.setAttribute("stroke-dashoffset", (125.6 * (1 - pct)).toString());
    ring.setAttribute("stroke", sec <= 10 ? "#f87171" : sec <= 20 ? "#f59e0b" : "var(--accent,#6ee7f7)");
    if (label) label.textContent = sec + "s";
  }

  tick();
  _totpTimerInterval = setInterval(tick, 1000);
}

function stopTOTPCountdown() {
  if (_totpTimerInterval) {
    clearInterval(_totpTimerInterval);
    _totpTimerInterval = null;
  }
}

// ── Show / hide error ────────────────────────
function showTOTPError(msg) {
  const el = document.getElementById("totp-error");
  if (el) { el.textContent = msg; el.style.display = "block"; }
  document.querySelectorAll(".totp-digit").forEach(d => d.classList.add("error"));
  setTimeout(() => {
    document.querySelectorAll(".totp-digit").forEach(d => d.classList.remove("error"));
  }, 600);
}

function hideTOTPError() {
  const el = document.getElementById("totp-error");
  if (el) el.style.display = "none";
}

// ── Submit TOTP to backend ───────────────────
async function submitTOTP() {
  const code = getTOTPCode();

  if (code.length !== 8) {
    showTOTPError("Please enter all 8 digits.");
    return;
  }

  hideTOTPError();

  // Show loading state
  const btn = document.querySelector("#step-totp .btn-primary");
  if (btn) { btn.textContent = "Verifying..."; btn.disabled = true; }

  try {
    const BACKEND = window.BACKEND_URL || "https://backend.shinumaths989.workers.dev"; // ← update this

    const res = await fetch(`${BACKEND}/verify-totp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, hash: _totpHash, username: document.getElementById('user-name').value.trim() })
    });

    const data = await res.json();

    if (data.success) {
    stopTOTPCountdown();

    // ── Apply session data from the verified response ──────────────────
    const result = data;

    sessionStorage.setItem("vaultSessionToken", result.sessionToken);
    sessionStorage.setItem("vaultSession",       result.sessionToken);

    window.masterPassword = result.secret ? String(result.secret) : "";

    window.VAULT_MODE = result.mode;
    sessionStorage.setItem("vaultMode", result.mode);

    // Successful ADMIN auth is a real, backend-verified credential check —
    // safe to auto-trust this device on it (no separate secret needed).
    if (result.mode === "ADMIN" && window.__deviceIntegrity) {
        window.__deviceIntegrity.markTrusted();
    }

    resetInactivityTimer();

       // Derive vaultUser from mode for notification targeting
const _modeUserMap = {
    SHINEIL: 'shineil', KEVIN: 'brother', OFFICIAL: 'official',
    PARENTS: 'father', SHINEIL_PARENTS: 'shineil',
    KEVIN_PARENTS: 'brother', ADMIN: 'shineil'
};
sessionStorage.setItem('vaultUser', _modeUserMap[result.mode] || 'all');

    if (window.VAULT_MODE !== "ADMIN") {
        const shareGear = document.getElementById("share-gear");
        if (shareGear) shareGear.style.display = "none";
    }

    masterPassword = window.masterPassword;
    sessionStartTime = new Date();

    // Sync all member password hashes for offline login
    if (typeof syncOfflineAuth === 'function') await syncOfflineAuth();

    // ── Hide TOTP, show step2 (Legal Declaration) ──────────────────────
    document.getElementById("step-totp").style.display = "none";
    const step2 = document.getElementById("step2");
    if (step2) { step2.style.display = "flex"; step2.style.opacity = "1"; }
    window.scrollTo({ top: 0, behavior: "smooth" });

    // Clean up temp storage
    window._pendingAuthResult = null;
    window._pendingAuthPass   = null;
    window._pendingAuthHash   = null;

    } else {
      showTOTPError(data.error || "Invalid code. Try again.");
      if (btn) { btn.textContent = "VERIFY CODE"; btn.disabled = false; }
      clearTOTPBoxes();
      focusFirstDigit();
    }

  } catch (err) {
    console.error("TOTP verify error:", err);
    showTOTPError("Verification failed. Please try again.");
    if (btn) { btn.textContent = "VERIFY CODE"; btn.disabled = false; }
  }
}

// ── TOTP login entry point (independent, no password) ──
async function loginWithTOTP() {
  const visitorName = document.getElementById("user-name").value.trim();
  const purpose = document.getElementById("user-purpose").value.trim();

  if (!visitorName || !purpose) {
    toastNotify('Username and Access Context are required.', 'error');
    return;
  }

  _totpHash = null;
  showStepTOTP();
  startTOTPCountdown();
  focusFirstDigit();
}

// ── Cancel passkey wait and return to login ───────
function cancelPasskeyWait() {
  const pw = document.getElementById('passkey-wait');
  if (pw) pw.style.display = 'none';
  const s1 = document.getElementById('step1');
  if (s1) s1.style.display = 'flex';
}

// ── Security quotes rotation ──────────────────────
const SECURITY_QUOTES = [
  "Encryption is the great equalizer — it protects the powerless from the powerful.",
  "Privacy is not about hiding something; it's about protecting everything.",
  "Security is not a product, but a process. Stay vigilant.",
  "The only secure system is the one that is never connected to the network.",
  "Digital security is a habit, not a one-time setup.",
  "Your data is your identity — guard it like your life depends on it.",
  "In the digital world, trust but verify — always verify.",
  "Strong passwords are the first line of defense. Make them count.",
  "Two-factor authentication: because one lock is never enough.",
  "The best encryption is useless if the user is careless."
];

function initSecurityQuotes() {
  const el = document.getElementById('security-quotes');
  if (!el) { setTimeout(initSecurityQuotes, 100); return; }
  let idx = 0;
  el.innerHTML = '<i data-lucide="message-circle" style="width:16px;height:16px;vertical-align:middle;"></i> ' + SECURITY_QUOTES[0];
  if (typeof lucide !== 'undefined') lucide.createIcons({node:el});
  if (window._securityQuotesTimer) clearInterval(window._securityQuotesTimer);
  window._securityQuotesTimer = setInterval(() => {
    if (el.offsetParent === null) return;
    idx = (idx + 1) % SECURITY_QUOTES.length;
    el.style.opacity = '0';
    setTimeout(() => {
      el.innerHTML = '<i data-lucide="message-circle" style="width:16px;height:16px;vertical-align:middle;"></i> ' + SECURITY_QUOTES[idx];
      if (typeof lucide !== 'undefined') lucide.createIcons({node:el});
      el.style.opacity = '1';
    }, 300);
  }, 10000);
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSecurityQuotes);
} else {
  initSecurityQuotes();
}

/* ==========================================================
   PRODUCTION MERGED ENGINE: AI BACKGROUND INDEXING PIPELINE
========================================================== */
async function runAIIndexingOnLogin() {
    console.log("runAIIndexingOnLogin() CALLED");

    // Extract authorization payload tokens
    const token = sessionStorage.getItem("vaultSessionToken") ||
                  sessionStorage.getItem("vaultSession") || "";
    if (!token) {
        console.warn("AI Index: Halt. Operational authorization token is missing.");
        return;
    }

    // ── 1. CHECK ENGINE GLOBAL STATUS ────────────────────────────────────
    try {
        const checkRes = await fetch('https://backend.shinumaths989.workers.dev/ai-index-status', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        });
        const checkData = await checkRes.json();
        
        // Fast path check bypass parameter
        if (false && checkData.indexed) {
            console.log('✦ Vault AI: Already indexed. Fast answers ready.');
            updateAIBtn('ready');
            return;
        }
        console.log("FORCING RE-INDEX SCRIPT RUN");
    } catch(e) {
        console.log('✦ Index check failed, proceeding to index extraction layer.', e);
    }

    console.log('✦ Vault AI: Scanning and compiling repository documents...');
    updateAIBtn('indexing', '<i data-lucide="loader-2" style="width:14px;height:14px;vertical-align:middle;"></i> Indexing...');

    // ── 2. DYNAMIC MEMORY SYNCHRONIZATION LOOP ───────────────────────────
    let waited = 0;
    while ((!window.allFilesData || !Object.keys(window.allFilesData).length) && waited < 30000) {
        console.log("Waiting for files storage layer to materialize...", waited, window.allFilesData);
        await new Promise(r => setTimeout(r, 500));
        waited += 500;
    }

    console.log("Files map ready status:", window.allFilesData);

    // Parse files dictionary map into a sequential array schema
    let allFiles = [];
    try {
        for (const items of Object.values(window.allFilesData || {})) {
            if (Array.isArray(items)) {
                allFiles.push(...items);
            }
        }
    } catch(e) { 
        console.warn('allFilesData matrix storage parse error', e); 
    }

    // Fallback: If local memory structure is completely blank, query server directly
    if (!allFiles.length) {
        console.log("AI Index: Local payload trace empty. Polling server backend manifest instead...");
        try {
            const res = await fetch("https://backend.shinumaths989.workers.dev/files.json", {
                headers: { "Authorization": `Bearer ${token}` }
            });
            const data = await res.json();
            for (const items of Object.values(data)) {
                if (Array.isArray(items)) allFiles.push(...items);
            }
        } catch (e) {
            console.error("AI Index: Critical exit. Unable to gather file lists registry.", e);
            updateAIBtn('ready');
            return;
        }
    }

    // Filter pipeline tracking: Strict evaluation targeting document files (.pdf, .enc)
    // Exclude photos (paths starting with photos/ or /photos/) — only documents should be OCR-indexed
    const pdfFiles = allFiles.filter(f => {
        const pathStr = (f.file || f.name || f.fileName || f.path || "").toLowerCase();
        if (pathStr.startsWith("photos/") || pathStr.startsWith("/photos/")) return false;
        return pathStr.endsWith(".pdf") || pathStr.endsWith(".enc");
    });

    if (!pdfFiles.length) {
        console.log('✦ No compatible PDF documents found to index inside vault.');
        updateAIBtn('ready');
        return;
    }

    console.log(`AI Index: ${pdfFiles.length} candidate documents discovered. Validating chunk status logs...`);

    // ── 3. QUERY PERSISTENCE STATUS FOR SKIPPING COMPLETED DOCS ─────────
    let alreadyIndexed = new Set();
    try {
        const progressRes = await fetch('https://backend.shinumaths989.workers.dev/ai-chunk-status-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({})
        });
        const progressData = await progressRes.json();
        
        // Map target names from both potential status attributes (indexed / files)
        const completedList = progressData.indexed || progressData.files || [];
        completedList.forEach(name => alreadyIndexed.add(name));
        
        console.log(`AI Index: ${alreadyIndexed.size} document structures verified in Firestore.`);
    } catch(e) {
        console.warn('AI Index: Progress checkpoint trace failed — Processing full array index scope.', e);
    }

    let doneCount = alreadyIndexed.size;

    // ── 4. RESUME CORE INDEX EXTRACTION & CHUNKING LOOP ──────────────────
    for (const fileEntry of pdfFiles) {
        const filePath = fileEntry.file || fileEntry.path || fileEntry.fileName || "";
        const fileName = fileEntry.name || fileEntry.filename || filePath.split("/").pop() || "Unnamed Document";

        // Skip processed items immediately
        if (alreadyIndexed.has(fileName)) {
            console.log(`✦ Skipping processed index file: ${fileName}`);
            continue;
        }

        console.log(`✦ Resuming Index pipeline processing: ${fileName}`);
        updateAIBtn('indexing', `✦ ${doneCount}/${pdfFiles.length}`);

        try {
            // Step A: Download stream buffer from storage vault
            const dlRes = await fetch(
                `https://backend.shinumaths989.workers.dev/docs/${encodeURIComponent(filePath)}`,
                { headers: { "Authorization": `Bearer ${token}` } }
            );
            if (!dlRes.ok) {
                console.warn(`AI Index: Extraction dispatch failed for "${fileName}" (HTTP ${dlRes.status})`);
                continue;
            }

            const encryptedBuffer = await dlRes.arrayBuffer();

            // Step B: Cryptographic layer decryption
            let decryptedBuffer;
            try {
                // Tries localized decryption utility first, switches to global window reference fallback
                if (typeof decryptVaultFile === 'function') {
                    decryptedBuffer = await decryptVaultFile(encryptedBuffer);
                } else if (typeof indexAI === 'function') {
                    // Fallback redirect hook if alternate helper wrapper indexAI architecture operates execution
                    await indexAI(fileEntry.url || filePath, fileName);
                    doneCount++;
                    continue; 
                } else {
                    throw new Error("Missing decryption library mapping runtime components.");
                }
            } catch (decruptErr) {
                console.warn(`AI Index: Decryption failed for target "${fileName}" — Skipping node loop.`, decruptErr);
                continue;
            }

            // Step C: Content string conversion extraction (with OCR mechanics)
            const fullText = await extractFullPDFText(decryptedBuffer);
            if (!fullText || fullText.length < 50) {
                console.warn(`AI Index: Document element "${fileName}" evaluated as zero length raw string content. Skipping...`);
                continue;
            }

            console.log(`AI Index: Document string parse complete "${fileName}" — (${fullText.length} characters parsed)`);

            // Step D: Calculate mathematical content overlaps mapping (800 window size / 100 char overlap)
            const CHUNK_SIZE = 800;
            const OVERLAP    = 100;
            const chunks = [];
            for (let i = 0; i < fullText.length; i += (CHUNK_SIZE - OVERLAP)) {
                chunks.push(fullText.slice(i, i + CHUNK_SIZE));
                if (i + CHUNK_SIZE >= fullText.length) break;
            }

            console.log(`AI Index: Array split processing completed. Transferring ${chunks.length} blocks to matrix database...`);

            // Step E: Stream individual index segments to Cloudflare vector worker
            let uploadedChunksCount = 0;
            for (let i = 0; i < chunks.length; i++) {
                try {
                    const chunkRes = await fetch("https://backend.shinumaths989.workers.dev/ai-index", {
                        method: "POST",
                        headers: { 
                            "Content-Type": "application/json", 
                            "Authorization": `Bearer ${token}` 
                        },
                        body: JSON.stringify({
                            fileName:     `${fileName} [chunk ${i + 1}/${chunks.length}]`,
                            baseFileName: fileName,
                            chunkText:    chunks[i],
                            chunkIndex:   i,
                            totalChunks:  chunks.length
                        })
                    });
                    if (chunkRes.ok) uploadedChunksCount++;
                } catch (chunkErr) {
                    console.warn(`AI Index: Serialization delivery failure on segment chunk index block: ${i + 1}`, chunkErr);
                }

                // Internal Throttling Layer: Every 10 iterations pause loop for 300ms to preserve thread execution capacity
                if (i % 10 === 9) {
                    await new Promise(r => setTimeout(r, 300));
                }
            }

            console.log(`AI Index: Storage save loop verified "${fileName}" — ${uploadedChunksCount}/${chunks.length} matrix slices updated.`);

            // Step F: Fire sync event payload tracking completion milestone status to persistence records
            await fetch('https://backend.shinumaths989.workers.dev/ai-file-indexed', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ fileName: fileName })
            });

            doneCount++;
            updateAIBtn('indexing', `✦ ${doneCount}/${pdfFiles.length}`);

        } catch (innerLoopErr) {
            console.error(`AI Index: Operational failure encountered handling item payload reference context: "${fileName}"`, innerLoopErr);
        }
    }

    // ── 5. FINALIZATION STATE WRITEOUT AND REGISTRATION ──────────────────
    try {
        await fetch('https://backend.shinumaths989.workers.dev/ai-index-status', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ indexed: true })
        });
    } catch(statusUpdateErr) {
        console.warn("AI Index: Global status bit update error.", statusUpdateErr);
    }

    updateAIBtn('ready');
    console.log('✦ Vault AI: All repository structures completely mapped. System execution thread finished!');
}

async function decryptVaultFile(arrayBuffer) {
  // If masterPassword isn't set yet, wait for the trusted session restore
  if (!window.masterPassword && window._trustSessionReady) {
    await window._trustSessionReady;
  }
  // Read settings length (first 4 bytes)
  const settingsLength = new Uint32Array(arrayBuffer.slice(0, 4))[0];

  // Read settings JSON
  const settingsBytes = arrayBuffer.slice(4, 4 + settingsLength);
  const settings = JSON.parse(new TextDecoder().decode(settingsBytes));

  // Read salt (16 bytes) and IV (12 bytes)
  const saltStart = 4 + settingsLength;
  const salt = arrayBuffer.slice(saltStart, saltStart + 16);
  const ivStart = saltStart + 16;
  const iv = arrayBuffer.slice(ivStart, ivStart + 12);
  const encryptedData = arrayBuffer.slice(ivStart + 12);

  // Hash master password (same as sha256Bytes used in the viewer)
  const passwordHash = await sha256Bytes(window.masterPassword);

  // Import key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw", passwordHash, "PBKDF2", false, ["deriveKey"]
  );

  // Derive AES-GCM key
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(salt),
      iterations: settings.iterations,
      hash: settings.hash
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // Decrypt and return
  return await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    key,
    encryptedData
  );
}

// After successfully deleting the file from storage, also remove its chunks:
async function deleteFileChunks(fileName) {
  const token = sessionStorage.getItem('vaultSessionToken') ||
                sessionStorage.getItem('vaultSession') || '';
  try {
    await fetch('https://backend.shinumaths989.workers.dev/ai-chunk-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ fileName })
    });
    console.log(`✦ Chunks deleted for: ${fileName}`);
  } catch (e) {
    console.warn('Failed to delete chunks:', e);
  }
       }

async function indexAI(fileUrl, fileName) {
  const token = sessionStorage.getItem('vaultSessionToken') ||
                sessionStorage.getItem('vaultSession') || '';

  // ── Check if this file's chunks already exist ──
  try {
    const checkRes = await fetch(
      'https://backend.shinumaths989.workers.dev/ai-chunk-status',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ fileName })  // checks by baseFileName
      }
    );
    const checkData = await checkRes.json();
    if (checkData.exists) {
      console.log(`✦ "${fileName}" already in Firestore — skipping.`);
      return;
    }
  } catch (e) {
    console.warn('Chunk status check failed, will re-index:', e);
  }

  // ── Fetch and decrypt the file ─────────────────
  const response = await fetch(fileUrl, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const encryptedBuffer = await response.arrayBuffer();

  let decryptedBuffer;
  try {
    decryptedBuffer = await decryptVaultFile(encryptedBuffer);
  } catch (e) {
    console.warn(`✦ Could not decrypt "${fileName}" — skipping.`, e);
    return;
  }

  // ── Extract text ───────────────────────────────
  const file = new File([decryptedBuffer], fileName, { type: 'application/pdf' });
  const fullText = await extractPDFText(file);

  if (!fullText || fullText.trim().length < 20) {
    console.warn(`✦ No text extracted from "${fileName}" — may be a scanned image.`);
    // Still save a placeholder so AI knows the file exists
    await fetch('https://backend.shinumaths989.workers.dev/ai-index', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        fileName:     `${fileName} (chunk 1/1)`,
        baseFileName: fileName,               // ← key field
        chunkText:    `Document: ${fileName}\nNote: This document appears to be a scanned image. Text could not be extracted automatically. Please check this document manually.`,
        chunkIndex:   0,
        totalChunks:  1
      })
    });
    return;
  }

  // ── Split into chunks WITH overlap ────────────
  const CHUNK_SIZE    = 600;   // smaller = more precise
  const CHUNK_OVERLAP = 150;   // overlap keeps dates/names from being cut
  const chunks        = [];
  let start           = 0;

  while (start < fullText.length) {
    const end   = Math.min(start + CHUNK_SIZE, fullText.length);
    const chunk = fullText.slice(start, end).trim();

    if (chunk.length > 30) {        // skip near-empty chunks
      chunks.push(chunk);
    }

    if (end === fullText.length) break;
    start += CHUNK_SIZE - CHUNK_OVERLAP;
  }

  console.log(`✦ "${fileName}" → ${chunks.length} chunks to index`);

  // ── Send each chunk to backend ─────────────────
  for (let i = 0; i < chunks.length; i++) {
    try {
      const res = await fetch(
        'https://backend.shinumaths989.workers.dev/ai-index',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            fileName:     `${fileName} (chunk ${i + 1}/${chunks.length})`,
            baseFileName: fileName,       // ← used for chunk-status checks
            chunkText:    chunks[i],
            chunkIndex:   i,              // ← used for ordering
            totalChunks:  chunks.length   // ← used for progress
          })
        }
      );

      const data = await res.json();
      if (data.success) { console.log(`✦ chunk ${i + 1}/${chunks.length} indexed`); }

    } catch (e) {
      console.warn(`✦ chunk ${i + 1} failed:`, e);
    }
  }

  console.log(`✦ "${fileName}" fully indexed (${chunks.length} chunks).`);
}

function updateAIBtn(state, label) {
  const btn = document.getElementById('ai-fab');
  if (!btn) return;
  const sparkleIcon = '<i data-lucide="sparkles" style="width:24px;height:24px;"></i>';
  if (state === 'ready') {
    btn.innerHTML = sparkleIcon;
    btn.style.background = 'linear-gradient(135deg,#4285f4,#9b5de5,#f72585)';
    btn.style.animation = 'none';
  } else {
    btn.innerHTML = label ? '<span style="font-size:12px;font-weight:800;">'+label+'</span>' : sparkleIcon;
    btn.style.background = 'linear-gradient(135deg,#f59e0b,#d97706)';
    btn.style.animation = 'none';
  }
  if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] });
}

let aiChatHistory = [];

function openAIChat() {
  document.getElementById('ai-chat-overlay').classList.add('open');
  aiChatHistory = []; // fresh session each open
  setTimeout(() => document.getElementById('ai-input').focus(), 450);
}

function closeAIChat() {
  document.getElementById('ai-chat-overlay').classList.remove('open');
}

function chipAsk(q) {
  document.getElementById('ai-input').value = q;
  sendAIMessage();
}

function addSpeakButton(messageElement) {
    const btn = document.createElement("button");
    btn.innerHTML = '<i data-lucide="volume-2" style="width:14px;height:14px;vertical-align:middle;"></i> Listen';
    btn.style.cssText = `
        margin-top: 8px;
        background: none;
        border: 1px solid var(--accent, #6ee7f7);
        color: var(--accent, #6ee7f7);
        border-radius: 20px;
        padding: 4px 12px;
        font-size: 11px;
        cursor: pointer;
        display: block;
    `;
    btn.onclick = () => {
        const text = messageElement.innerText.replace(/\*\*/g, "");
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = "en-IN";
        utterance.rate = 0.95;
        utterance.pitch = 1;
        if (speechSynthesis.speaking) {
            speechSynthesis.cancel();
btn.innerHTML = '<i data-lucide="volume-2" style="width:14px;height:14px;vertical-align:middle;"></i> Listen';
            if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] });
            return;
        }
        utterance.onstart = () => btn.textContent = "⏹ Stop";
        utterance.onend = () => { btn.innerHTML = '<i data-lucide="volume-2" style="width:14px;height:14px;vertical-align:middle;"></i> Listen'; if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [btn] }); };
        speechSynthesis.speak(utterance);
    };
    messageElement.parentElement.appendChild(btn);
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

let _aiMessageInFlight = false;

async function sendAIMessage() {
  // Guard against duplicate fires (Enter + click, or rapid repeat Enter)
  // stacking multiple error bubbles for a single question.
  if (_aiMessageInFlight) return;

  const input = document.getElementById('ai-input');
  const question = input.value.trim();
  if (!question) return;
  input.value = '';

  // Hide welcome screen on first message
  const welcome = document.getElementById('ai-welcome');
  if (welcome) welcome.remove();

  appendUserBubble(question);
  aiChatHistory.push({ role: 'user', parts: [{ text: question }] });

  showAITyping(true);
  _aiMessageInFlight = true;
  const sendBtn = document.getElementById('ai-send-btn');
  if (sendBtn) sendBtn.disabled = true;

  // ── Helper: show answer with word-by-word animation ──
  function _showAIReply(replyText, source) {
    const msgs = document.getElementById('ai-messages');
    const wrap = document.createElement('div');
    wrap.className = 'ai-msg-ai-wrap';
    const sourceTag = source === 'offline'
      ? '<div style="font-size:10px;color:#94a3b8;margin-bottom:4px;font-weight:600;"><i data-lucide="wifi-off" style="width:10px;height:10px;vertical-align:middle;"></i> Offline AI</div>'
      : '';
    wrap.innerHTML = `<div class="ai-gem-avatar"><i data-lucide="sparkles" style="width:18px;height:18px;"></i></div><div class="ai-msg-ai">${sourceTag}<div id="ai-reply-target-${Date.now()}"></div></div>`;
    msgs.appendChild(wrap);
    if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [wrap] });
    msgs.scrollTop = msgs.scrollHeight;

    const replyTarget = wrap.querySelector('[id^="ai-reply-target-"]');
    const rawReply = escHtml(replyText)
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n/g, '<br>');

    const words = rawReply.split(/(\s+)/);
    let wordIndex = 0;
    function printWordByWord() {
      if (wordIndex < words.length) {
        const span = document.createElement("span");
        span.innerHTML = words[wordIndex];
        span.style.opacity = "0";
        span.style.filter = "blur(3px)";
        span.style.transition = "opacity 0.2s ease-out, filter 0.2s ease-out";
        span.style.display = "inline-block";
        span.style.whiteSpace = "pre-wrap";
        replyTarget.appendChild(span);
        requestAnimationFrame(() => {
          span.style.opacity = "1";
          span.style.filter = "blur(0px)";
        });
        wordIndex++;
        msgs.scrollTop = msgs.scrollHeight;
        setTimeout(printWordByWord, 25);
      } else {
        addSpeakButton(replyTarget);
      }
    }
    printWordByWord();
  }

  try {
    // ── Step 1: Try online AI via backend ─────────────────────────────────
    let onlineSucceeded = false;
    let token = sessionStorage.getItem('vaultSessionToken') ||
                  sessionStorage.getItem('vaultSession') || '';

    // If token is an offline placeholder, try silent re-auth for a real one
    if (token.startsWith('offline-') && typeof _silentReAuth === 'function') {
      const fresh = await _silentReAuth();
      if (fresh && !fresh.startsWith('offline-')) {
        token = fresh;
        sessionStorage.setItem('vaultSessionToken', fresh);
        sessionStorage.setItem('vaultSession', fresh);
      }
    }

    // Only attempt online if we have a real token
    if (!token.startsWith('offline-')) {
      try {
        let res = await fetch('https://backend.shinumaths989.workers.dev/ai-search', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ question })
        });

        // If server says unauthorized, try silent re-auth and retry once
        if (res.status === 401 && typeof _silentReAuth === 'function') {
          const fresh = await _silentReAuth();
          if (fresh && !fresh.startsWith('offline-')) {
            token = fresh;
            sessionStorage.setItem('vaultSessionToken', fresh);
            sessionStorage.setItem('vaultSession', fresh);
            res = await fetch('https://backend.shinumaths989.workers.dev/ai-search', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
              },
              body: JSON.stringify({ question })
            });
          }
        }

        const data = await res.json();
        if (data.success && data.reply) {
          showAITyping(false);
          _showAIReply(data.reply, 'online');
          onlineSucceeded = true;
        }
      } catch (onlineErr) {
        console.warn('[AI Chat] Online request failed:', onlineErr.message);
      }
    }

    // ── Step 2: If online failed, fall back to offline AI ──────────────────
    if (!onlineSucceeded) {
      if (window.OfflineAI) {
        try {
          const offlineResult = await window.OfflineAI.ask(question, { offline: true });
          showAITyping(false);
          if (offlineResult && offlineResult.success && offlineResult.answer) {
            _showAIReply(offlineResult.answer, 'offline');
          } else {
            appendAIBubble('No answer could be generated from cached documents. Try rephrasing your question.');
          }
        } catch (offlineErr) {
          console.error('[AI Chat] Offline AI error:', offlineErr);
          showAITyping(false);
          appendAIBubble('AI Chat is currently unavailable. The online service is unreachable and the offline AI model has not been loaded yet. Please connect to the internet and log in to download the AI model.');
        }
      } else {
        showAITyping(false);
        appendAIBubble('AI Chat is currently unavailable. The online service is unreachable and the offline AI module is not loaded. Please check your connection and try again.');
      }
    }

  } catch (e) {
    console.error(e);
    showAITyping(false);
    appendAIBubble('An unexpected error occurred. Please try again.');

  } finally {
    _aiMessageInFlight = false;
    if (sendBtn) sendBtn.disabled = false;
  }

}

function appendUserBubble(text) {
  const msgs = document.getElementById('ai-messages');
  const div = document.createElement('div');
  div.className = 'ai-msg-user';
  div.textContent = text;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

function appendAIBubble(text) {
  const msgs = document.getElementById('ai-messages');
  const wrap = document.createElement('div');
  wrap.className = 'ai-msg-ai-wrap';
  wrap.innerHTML = `
    <div class="ai-gem-avatar"><i data-lucide="sparkles" style="width:18px;height:18px;"></i></div>
    <div class="ai-msg-ai">${escHtml(text).replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>')}</div>
  `;
  msgs.appendChild(wrap);
  if (typeof lucide !== 'undefined') lucide.createIcons({ nodes: [wrap] });
  msgs.scrollTop = msgs.scrollHeight;
}

function showAITyping(show) {
  document.getElementById('ai-typing').style.display = show ? 'block' : 'none';
  document.getElementById('ai-send-btn').disabled = show;
  const msgs = document.getElementById('ai-messages');
  msgs.scrollTop = msgs.scrollHeight;
         }

/* ========================= STEP 1 ========================= */
async function hashPassword(password, useSlowKdf = false) {
  const normalized = password
    .trim()
    .normalize("NFKC");

  const encoder = new TextEncoder();

  if (useSlowKdf) {
    // PBKDF2 + SHA-256 for stronger protection
    const salt = new TextEncoder().encode('vault-pbkdf2-v1');
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(normalized), 'PBKDF2', false, ['deriveBits']);
    const keyBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 200000 },
      keyMaterial, 256
    );
    const hashBuffer = await crypto.subtle.digest("SHA-256", new Uint8Array(keyBits));
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Legacy SHA-256 only (backward compatibility)
  const data = encoder.encode(normalized);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Try PBKDF2+SHA-256 first, fall back to legacy SHA-256
async function hashPasswordWithFallback(password) {
  const slowHash = await hashPassword(password, true);
  // Return an array: [newHash, legacyHash]
  const legacyHash = await hashPassword(password, false);
  return { slowHash, legacyHash };
}
   
/* ==========================================================
   FIXED STEP 1 AUTHENTICATION GATEWAY WITH CARD TARGETS
========================================================== */
async function showStep2() {

    clearTimeout(inactivityTimer);

    const now = Date.now();

    if (now < lockUntil) {
        const remaining = Math.ceil((lockUntil - now) / 1000);
        showNotification('Too Many Attempts', 'Try again in '+remaining+' seconds.', {type:'warning'});
        return;
    }

    // Capture responsive field values
    const visitorName = document.getElementById("user-name").value.trim();
    const pass = document.getElementById("vault-pass").value.trim();
    const purpose = document.getElementById("user-purpose").value.trim();

    if (!visitorName || !purpose || !pass) {
        toastNotify('Username, Access Context, and Access Matrix Pin are required.', 'error');
        return;
    }

    // ── DEVICE INTEGRITY CHECK ─────────────────────────────────────
    if (window.__deviceIntegrity) {
        const risk = window.__deviceIntegrity.getRiskScore();
        const highFlags = risk.flags.filter(f => f.severity === 'high');
        if (highFlags.length > 0) {
            const report = window.__deviceIntegrity.getDeviceReport();
            const flagDetails = highFlags.map(f => f.rule + ': ' + f.detail).join('\n');
            console.warn('[DeviceIntegrity] High-risk flags:', highFlags);
            sendSecurityAlert(
                'Suspicious device detected\n' + flagDetails +
                '\nRisk score: ' + risk.score +
                '\nTrusted: ' + report.trusted +
                '\nUA: ' + report.userAgent.slice(0, 120)
            );
            // Trusted devices get a pass; untrusted devices get blocked on ANY high flag
            if (!window.__deviceIntegrity.isTrusted()) {
                try { sendSecurityAlert('Blocked - ' + flagDetails); } catch(e) {}
                window.location.href = 'https://72oe-v2sx.shine-ministry.com/blocked.html';
                return;
            }
        }
    }

    // Acquire primary action node buttons
    const loginBtn = document.getElementById('submitBtn');
    const originalBtnText = loginBtn ? loginBtn.textContent : '';
    if (loginBtn) {
        loginBtn.innerHTML = '<i data-lucide="lock" style="width:14px;height:14px;vertical-align:middle;"></i> Connecting Secure Server...';
        if (typeof lucide !== 'undefined') lucide.createIcons();
        loginBtn.disabled = true;
        loginBtn.style.opacity = '0.7';
    }

    const restoreLoginBtn = () => {
        if (loginBtn) {
            loginBtn.textContent = originalBtnText;
            loginBtn.disabled = false;
            loginBtn.style.opacity = '1';
        }
    };

    const showLoginError = (title, detail) => {
        const existing = document.getElementById('login-error-box');
        if (existing) existing.remove();
        const box = document.createElement('div');
        box.id = 'login-error-box';
        box.style.cssText = `
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--danger);
            border-radius: 12px;
            padding: 14px;
            margin-top: 16px;
            text-align: left;
            animation: fadeInUp .3s ease;
        `;
        box.innerHTML = `
            <div style="font-weight:800;color:var(--danger);font-size:13px;margin-bottom:4px;"><i data-lucide="alert-triangle" style="width:14px;height:14px;vertical-align:middle;"></i> ${escHtml(title)}</div>
            <div style="font-size:12px;color:#fff;line-height:1.5;">${escHtml(detail)}</div>
            <button onclick="this.parentElement.remove()" style="
                margin-top:10px;border:none;background:var(--danger);color:white;
                border-radius:6px;padding:6px 12px;font-size:11px;font-weight:700;cursor:pointer;">
                Dismiss
            </button>
        `;
        
        // CORRECTION: Target .login-wrapper container instead of obsolete .step-card
        const card = document.querySelector('#step1 .login-wrapper');
        if (card) { card.appendChild(box); if (typeof lucide !== 'undefined') lucide.createIcons(); }
        else toastNotify(title + ': ' + detail, 'error');
    };

    const fetchWithTimeout = (url, options, ms = 12000) => {
        const controller = new AbortController();
        const tid = setTimeout(() => controller.abort(), ms);
        return fetch(url, { ...options, signal: controller.signal })
            .finally(() => clearTimeout(tid));
    };

    try {
        masterPassword = pass;
        const hashPair = await hashPasswordWithFallback(pass);
        const hash = hashPair.slowHash; // Try PBKDF2+SHA-256 first

        // =================================
        // OFFLINE LOGIN — navigator.onLine is unreliable so we always
        // attempt the network first and fall back on failure (handled
        // in the fetchErr catch block below). Skip the hard onLine gate.
        // =================================
        // END OFFLINE LOGIN
        // =================================

        let res;
        try {
            res = await fetchWithTimeout(
                "https://backend.shinumaths989.workers.dev/get-secret",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ hash })
                },
                12000
            );
        } catch (fetchErr) {
            // Network failed — try offline login with cached credentials
            if (typeof offlineLogin === 'function') {
                // Simple: one call, offlineLogin reads the username from the form itself
                const ok = await offlineLogin(null, pass);
                if (ok) {
                    // Load cached file list so the dashboard has data
                    const cachedMeta = await idbGetVaultMeta();
                    if (cachedMeta) {
                        window.allFilesData = cachedMeta;
                    } else {
                        console.warn('[OfflineAuth] No cached file list — dashboard will open empty.');
                    }

                    // Mark button as offline mode
                    if (loginBtn) { loginBtn.textContent = '✓ Offline Mode'; loginBtn.style.background = 'linear-gradient(135deg,#10b981,#059669)'; loginBtn.style.opacity = '1'; }

                    // Flag offline mode — showStep3() uses this to skip captcha
                    window._offlineMode = true;

                    // Store the dashboard init function for showStep3 to call
                    window._offlineShowDashboard = () => {
                        const step2 = document.getElementById('step2');
                        if (step2) { step2.style.display = 'none'; }
                        const dash = document.getElementById('vault-dashboard');
                        if (dash) { dash.style.display = 'flex'; dash.classList.add('dashboard-enter'); }

                        // initVault() reads allFilesData from IDB (already loaded above)
                        // and renders both the left-nav category list and the file list.
                        if (typeof initVault === 'function') {
                            initVault().catch(err => {
                                console.warn('[OfflineAuth] initVault failed in offline mode:', err);
                                // Fallback: if initVault can't run, render directly from allFilesData
                                if (window.allFilesData && Object.keys(window.allFilesData).length) {
                                    const firstCat = Object.keys(window.allFilesData)[0];
                                    if (typeof renderFiles === 'function' && firstCat) {
                                        renderFiles(window.allFilesData[firstCat], firstCat);
                                    }
                                }
                            });
                        } else if (window.allFilesData && Object.keys(window.allFilesData).length) {
                            // Last-resort fallback if vault-data.js isn't loaded yet
                            const firstCat = Object.keys(window.allFilesData)[0];
                            if (typeof renderFiles === 'function' && firstCat) {
                                renderFiles(window.allFilesData[firstCat], firstCat);
                            }
                        }
                       // Set vaultUser for notification targeting in offline mode
const _omUserMap = {
    SHINEIL: 'shineil', KEVIN: 'brother', OFFICIAL: 'official',
    PARENTS: 'father', SHINEIL_PARENTS: 'shineil',
    KEVIN_PARENTS: 'brother', ADMIN: 'shineil'
};
const _omMode = sessionStorage.getItem('vaultMode') || '';
if (!sessionStorage.getItem('vaultUser')) {
    sessionStorage.setItem('vaultUser', _omUserMap[_omMode] || 'all');
}
                        vaultPostInit();
                        startSessionTimer();
                        startInactivityMonitor();
                        if (typeof listenForForceLogout === 'function') listenForForceLogout();
                        // Init offline AI (auto-download model for offline path)
                        if (window.OfflineAI) {
                            window.OfflineAI.init({ downloadModel: true }).catch(function(e) {
                                console.warn('[OfflineAI] Init failed:', e);
                            });
                        }
                        console.log('[OfflineAuth] Dashboard ready — offline mode active.');
                    };

                    // Transition: step1 → step2 (Legal Declaration)
                    // After declaration, showStep3() sees _offlineMode and goes straight to dashboard
                    const step1 = document.getElementById('step1');
                    const step2 = document.getElementById('step2');
                    showCurtain();
                    if (step1) {
                        step1.style.opacity = '0';
                        step1.style.transition = 'opacity 0.3s ease';
                        setTimeout(() => {
                            step1.style.display = 'none';
                            if (step2) { step2.style.display = 'flex'; step2.style.opacity = '1'; }
                            window.scrollTo({ top: 0, behavior: 'smooth' });
                            hideCurtain(150);
                        }, 300);
                    } else if (step2) {
                        step2.style.display = 'flex';
                        step2.style.opacity = '1';
                        hideCurtain(150);
                    }
                    return;
                }

                // Wrong password offline — error already shown by offlineLogin/_showOfflineError
                restoreLoginBtn();
                return;
            }
            restoreLoginBtn();
            if (fetchErr.name === 'AbortError') {
                showLoginError('Connection Timed Out', 'The secure server took too long to respond.');
            } else {
                showLoginError('Server Unreachable', 'Your network may be blocking connection points.');
            }
            return;
        }

        if (res.status >= 500) {
            restoreLoginBtn();
            showLoginError('Server Error', 'Secure node returned an error state (HTTP ' + res.status + ').');
            return;
        }

        if (!res.ok && (res.headers.get("content-type") || "").includes("text/html")) {
            restoreLoginBtn();
            showLoginError('Access Blocked', 'The vault firewall rejected this identity node link.');
            return;
        }

        let result = {};
        try { result = await res.json(); } catch {
            restoreLoginBtn();
            showLoginError('Response Fault', 'The server returned an unreadable payload pattern.');
            return;
        }

        if (!res.ok || !result.success || !result.authorized) {
            // Try legacy SHA-256 hash as fallback (backward compatibility)
            if (hash !== hashPair.legacyHash) {
                try {
                    const legacyRes = await fetchWithTimeout(
                        "https://backend.shinumaths989.workers.dev/get-secret",
                        {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ hash: hashPair.legacyHash })
                        }, 12000
                    );
                    if (legacyRes.ok) {
                        try { result = await legacyRes.json(); } catch {}
                        if (result && result.success && result.authorized) {
                            hashPair.slowHash = hashPair.legacyHash; // use legacy hash for TOTP
                            // Clear failed attempts since legacy worked
                            failedAttempts = 0;
                            // Fall through to AUTHORIZED block below
                            res = legacyRes;
                        }
                    }
                } catch (e) {
                    console.warn('[Auth] Legacy hash fallback also failed:', e.message);
                }
            }

            if (!res.ok || !result.success || !result.authorized) {
                restoreLoginBtn();
                failedAttempts++;

                if (failedAttempts >= 5) {
                    sendSecurityAlert("Multiple failed password attempts");
                    lockUntil = Date.now() + 300000;
                    failedAttempts = 0;
                    showLoginError('Vault Locked', 'Too many unauthorized access requests. Security freeze for 5 minutes.');
                } else {
                    showLoginError('Authentication Failure', `Incorrect access token matrix sequence. ${5 - failedAttempts} attempts remain.`);
                }
                return;
            }
        }

        // AUTHORIZED — stash result and proceed
        if (loginBtn) {
            loginBtn.textContent = '✓ Identity Verified';
            loginBtn.style.background = 'linear-gradient(135deg, #10b981, #059669)';
            loginBtn.style.opacity = '1';
        }

        failedAttempts = 0;

        // Stash auth data — applied fully only after TOTP passes (or immediately if OTP skipped)
        window._pendingAuthResult = result;
        window._pendingAuthPass   = pass;
        window._pendingAuthHash   = hash; // use the hash that worked (slow or legacy fallback)

        const otpRequested = window._otpRequested === true;

        const step1 = document.getElementById("step1");

        if (otpRequested) {
            // Route to TOTP step — session applied only after TOTP verification
            if (step1) {
                step1.style.pointerEvents = "none";
                step1.style.opacity = "0";
                step1.style.transition = "opacity 0.3s ease";
                setTimeout(() => {
                    step1.style.display = "none";
                    startTOTPStep(window._pendingAuthHash);
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                }, 300);
            } else {
                startTOTPStep(window._pendingAuthHash);
            }
        } else {
            // Skip TOTP — apply session immediately and go to Step 2 (Declaration)
            sessionStorage.setItem("vaultSessionToken", result.sessionToken);
            sessionStorage.setItem("vaultSession",       result.sessionToken);

            window.masterPassword = result.secret ? String(result.secret) : String(pass || "");

            window.VAULT_MODE = result.mode;
            sessionStorage.setItem("vaultMode", result.mode);

            // Successful ADMIN auth is a real, backend-verified credential check —
            // safe to auto-trust this device on it (no separate secret needed).
            if (result.mode === "ADMIN" && window.__deviceIntegrity) {
                window.__deviceIntegrity.markTrusted();
            }

            resetInactivityTimer();

           // Derive vaultUser from mode for notification targeting
const _modeUserMap = {
    SHINEIL: 'shineil', KEVIN: 'brother', OFFICIAL: 'official',
    PARENTS: 'father', SHINEIL_PARENTS: 'shineil',
    KEVIN_PARENTS: 'brother', ADMIN: 'shineil'
};
sessionStorage.setItem('vaultUser', _modeUserMap[result.mode] || 'all');

            if (window.VAULT_MODE !== "ADMIN") {
                const shareGear = document.getElementById("share-gear");
                if (shareGear) shareGear.style.display = "none";
            }

            masterPassword = window.masterPassword;
            sessionStartTime = new Date();

            // Sync all member password hashes for offline login
            if (typeof syncOfflineAuth === 'function') await syncOfflineAuth();

            // Clean up temp storage
            window._pendingAuthResult = null;
            window._pendingAuthPass   = null;
            window._pendingAuthHash   = null;

            // Transition to Step 2 (Legal Declaration)
            showCurtain();
            if (step1) {
                step1.style.pointerEvents = "none";
                step1.style.opacity = "0";
                step1.style.transition = "opacity 0.3s ease";
                setTimeout(() => {
                    step1.style.display = "none";
                    const step2 = document.getElementById("step2");
                    if (step2) { step2.style.display = "flex"; step2.style.opacity = "1"; }
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                    hideCurtain(150);
                }, 300);
            } else {
                const step2 = document.getElementById("step2");
                if (step2) { step2.style.display = "flex"; step2.style.opacity = "1"; }
                hideCurtain(150);
            }
        }

    } catch (e) {
        restoreLoginBtn();
        console.error(e);
        showLoginError('Connection Error', e.message || 'Fatal data stream pipeline disruption.');
    }
}
/* =========================
   STEP 2
========================= */

function showStep3(){

    if(!document.getElementById('terms-tick').checked){
        toastNotify('You must agree to the declaration.', 'error');
        return;
    }

    // Offline mode: skip reCAPTCHA and go directly to dashboard
    if (window._offlineMode && typeof window._offlineShowDashboard === 'function') {
        const step2 = document.getElementById('step2');
        if (step2) {
            step2.style.pointerEvents = 'none';
            step2.classList.add('slide-up-exit');
            setTimeout(() => {
                step2.style.display = 'none';
                window._offlineShowDashboard();
            }, 500);
        } else {
            window._offlineShowDashboard();
        }
        return;
    }

    // Online mode: proceed to reCAPTCHA (step3)
    showCurtain();
    const step2 = document.getElementById('step2');
    step2.style.pointerEvents = "none";
    step2.classList.add('slide-up-exit');
    setTimeout(()=>{
        step2.style.display = 'none';
        const step3 = document.getElementById('step3');
        step3.style.display = 'flex';
        hideCurtain(150);
        // Re-render reCAPTCHA now that the container is visible
        if (typeof grecaptcha !== 'undefined' && step3.querySelector('.g-recaptcha') && !step3.querySelector('.g-recaptcha iframe')) {
            try { grecaptcha.render(step3.querySelector('.g-recaptcha')); } catch(e) {}
        }
    }, 700);

}

/* =========================
   CAPTCHA
========================= */

function onCaptchaSuccess(){
    showCurtain();
    document.getElementById('loading-msg').style.display = 'block';

    // Start loading immediately — parallel with the exit animation
    const vaultLoad = initVault().then(() => {
        vaultPostInit();
        runAIIndexingOnLogin();
        if (window.OfflineAI) {
            window.OfflineAI.init({ downloadModel: true }).catch(function(e) {
                console.warn('[OfflineAI] Init failed:', e);
            });
        }
    }).catch(e => {
        console.error('initVault failed:', e);
        vaultPostInit();
        runAIIndexingOnLogin();
        if (window.OfflineAI) {
            window.OfflineAI.init({ downloadModel: true }).catch(function(e2) {
                console.warn('[OfflineAI] Init failed:', e2);
            });
        }
    });

    setTimeout(() => {
        document.getElementById('step3').classList.add('slide-up-exit');
        setTimeout(async () => {
            document.getElementById('step3').style.display = 'none';

            // Show loading overlay while we wait (may already be done)
            const loadingEl = document.getElementById('trusted-loading');
            const loadingBar = document.getElementById('trusted-loading-bar');
            const loadingStatus = document.getElementById('trusted-loading-status');
            if (loadingEl) loadingEl.style.display = 'flex';
            const setProgress = (pct, msg) => {
                if (loadingBar) loadingBar.style.width = pct + '%';
                if (loadingStatus) loadingStatus.textContent = msg;
            };
            setProgress(40, 'Finalizing setup...');

            await vaultLoad;

            setProgress(80, 'Opening vault...');
            const dash = document.getElementById('vault-dashboard');
            dash.style.display = 'flex';
            dash.classList.add('dashboard-enter');
            hideCurtain(200);
            saveAccessLog();
            registerActiveSession();
            saveVisitorLog({
                visitorName: document.getElementById('user-name').value,
                purpose: document.getElementById('user-purpose').value,
                loginTime: new Date().toLocaleString(),
                device: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                browser: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                platform: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                screen: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
            });
            sendLoginEmail();
            startSessionTimer();
            startInactivityMonitor();
            listenForForceLogout();
            setProgress(100, 'Ready!');
            setTimeout(() => { if (loadingEl) loadingEl.style.display = 'none'; }, 400);
        }, 700);
    }, 1200);
}

   async function sendLoginEmail() {
    try {
        const name = (document.getElementById('user-name') || {}).value || 'Unknown';
        const email = (document.getElementById('user-email') || {}).value || '';
        const purpose = (document.getElementById('user-purpose') || {}).value || '';
        const ipRes = await fetch('https://ipapi.co/json/').catch(() => null);
        let ip = 'Unknown', location = 'Unknown';
        if (ipRes && ipRes.ok) {
            const info = await ipRes.json();
            ip = info.ip || 'Unknown';
            location = `${info.city || ''}, ${info.region || ''}, ${info.country_name || ''}`;
        }
        await fetch('https://backend.shinumaths989.workers.dev/login-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email, name, purpose,
                loginTime: new Date().toLocaleString(),
                ip, location,
                device: /Mobi|Android/i.test(navigator.userAgent) ? 'Mobile' : 'Desktop',
                browser: /Mobi|Android/i.test(navigator.userAgent) ? 'Mobile' : 'Desktop'
            })
        }).catch(() => {});
    } catch(e) { console.warn('sendLoginEmail error:', e); }
}

   async function saveVisitorLog(data){

    let ip = "Unknown";

    let location = "Unknown";

    try{

        const res =
        await fetch(
        "https://ipapi.co/json/"
        );

        const info =
        await res.json();

        ip =
        info.ip || "Unknown";

        location =
        `${info.city}, ${info.region}, ${info.country_name}`;

    }catch(e){

        console.log(
        "IP fetch failed",
        e
        );

    }

    try{

        await fetch(
            "https://backend.shinumaths989.workers.dev/save-visitor-log",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    visitorName: data.visitorName,
                    purpose: data.purpose,
                    loginTime: new Date().toLocaleString(),
                    device: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                    browser: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                    platform: /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                    screen: `${screen.width}x${screen.height}`,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    ipAddress: ip,
                    location: location,
                    deviceIntegrity: window.__deviceIntegrity
                        ? JSON.stringify({
                            flags: window.__deviceIntegrity.getFlags().map(f => f.rule),
                            behaviors: window.__deviceIntegrity.getBehaviorLog()
                          })
                        : undefined
                })
            }
        );

    }catch(err){

        console.error(
        "Visitor log error:",
        err
        );

    }

}

   async function sendSecurityAlert(reason){

    try{

        const visitorName =
        document.getElementById(
        'user-name'
        ).value || "Unknown";

        const purpose =
        document.getElementById(
        'user-purpose'
        ).value || "Unknown";

        let ip = "Unknown";
        let location = "Unknown";

        try{

            const res =
            await fetch(
            "https://ipapi.co/json/"
            );

            const info =
            await res.json();

            ip =
            info.ip || "Unknown";

            location =
            `${info.city}, ${info.country_name}`;

        }catch(e){}

        await fetch(
        "https://backend.shinumaths989.workers.dev/security-alert",
        {

            method:"POST",

            headers:{
                "Content-Type":"application/json"
            },

            body:JSON.stringify({

                embeds:[{

                    title:
                    "<i data-lucide='alert-triangle' style='width:14px;height:14px;vertical-align:middle;'></i> SUSPICIOUS VAULT ACTIVITY",

                    color:16711680,

                    fields:[

                        {
                            name:"Visitor",
                            value:visitorName,
                            inline:true
                        },

                        {
                            name:"Purpose",
                            value:purpose,
                            inline:true
                        },

                        {
                            name:"Reason",
                            value:reason,
                            inline:false
                        },

                        {
                            name:"IP Address",
                            value:ip,
                            inline:true
                        },

                        {
                            name:"Location",
                            value:location,
                            inline:true
                        },

                        {
                            name:"Device",
                            value:
                            /Mobi|Android/i.test(navigator.userAgent) ? "Mobile" : "Desktop",
                            inline:false
                        }

                    ],

                    timestamp:
                    new Date().toISOString()

                }]

            })

        });

    }catch(err){

        console.error(
        "Discord alert failed",
        err
        );

    }

}

   async function registerActiveSession(){

    try{

        await fetch(
            "https://backend.shinumaths989.workers.dev/register-session",
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sessionId: sessionId,
                    visitor: document.getElementById('user-name').value,
                    active: true,
                    createdAt: new Date().toISOString()
                })
            }
        );

    }catch(e){

        console.log(e);

    }

}

let _forceLogoutInterval = null;

      async function listenForForceLogout(){
    if (_forceLogoutInterval) return;

    // Poll the Worker every 15 seconds to check if admin force-logged this session out
    _forceLogoutInterval = setInterval(async ()=>{

        try{

            const res = await fetch(
                "https://backend.shinumaths989.workers.dev/check-session",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ sessionId: sessionId })
                }
            );

            if(!res.ok) return;

            const data = await res.json();

            if(data.forceLogout){

                showNotification('Session Terminated', 'An administrator has ended your session.', {type:'error'});

                location.reload();

            }

        }catch(e){

            // Silently fail - don't disrupt the session on network hiccup

        }

    }, 15000);

}

// ═══════════════════════════════════════════════════════════════════════
//  AI INDEXING — Full PDF → chunks → Firestore (global, forever)
// ═══════════════════════════════════════════════════════════════════════

async function extractFullPDFText(arrayBuffer) {
  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  let fullText = "";

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    console.log(`extractFullPDFText: processing page ${i}/${pdf.numPages}`);

    // ── PASS 1: Native text layer ──────────────────────────────────────────
    let layerText = "";
    try {
      const content = await page.getTextContent();
      layerText = content.items
        .map(item => item.str)
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
    } catch (e) {
      console.warn(`extractFullPDFText: text layer failed page ${i}:`, e);
    }

    if (layerText.length > 50) {
      console.log(`extractFullPDFText: page ${i} native text (${layerText.length} chars)`);
      fullText += layerText + "\n";
      continue;
    }

    // ── PASS 2: OCR (scanned / image-based pages) ──────────────────────────
    try {
      const baseViewport = page.getViewport({ scale: 1.0 });

      // Scale to ~300 DPI equivalent (2480px wide for A4) for maximum accuracy
      const TARGET_WIDTH = 2480;
      const scaleNeeded  = Math.max(
        3.0,
        TARGET_WIDTH / baseViewport.width
      );

      const viewport = page.getViewport({ scale: scaleNeeded });
      const canvas   = document.createElement("canvas");
      canvas.width   = Math.ceil(viewport.width);
      canvas.height  = Math.ceil(viewport.height);

      console.log(`extractFullPDFText: page ${i} OCR canvas = ${canvas.width}×${canvas.height}px (scale ${scaleNeeded.toFixed(2)}×)`);

      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      await page.render({ canvasContext: ctx, viewport }).promise;

      if (canvas.width < 10 || canvas.height < 10) {
        console.warn(`extractFullPDFText: page ${i} canvas too small — skipping`);
        continue;
      }

      // ── Contrast enhancement (greyscale + contrast boost) ─────────────
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const d = imgData.data;
      for (let p = 0; p < d.length; p += 4) {
        const grey = 0.299 * d[p] + 0.587 * d[p + 1] + 0.114 * d[p + 2];
        const enhanced = grey < 128
          ? Math.max(0,   grey * 0.75)
          : Math.min(255, 128 + (grey - 128) * 1.4);
        d[p] = d[p + 1] = d[p + 2] = enhanced;
        d[p + 3] = 255;
      }
      ctx.putImageData(imgData, 0, 0);

      // ── Tesseract with strict settings ────────────────────────────────
      const { data: { text } } = await Tesseract.recognize(canvas, "eng", {
        logger: () => {},
        tessedit_pageseg_mode:     "6",
        tessedit_ocr_engine_mode:  "1",
        preserve_interword_spaces: "1",
        tessedit_char_whitelist:   "",
        min_characters_to_try:     "1",
      });

      const ocrText = (text || "").replace(/\s+/g, " ").trim();
      console.log(`extractFullPDFText: page ${i} OCR extracted ${ocrText.length} chars`);

      if (ocrText.length < 10 && layerText.length > 0) {
        console.warn(`extractFullPDFText: page ${i} OCR thin — using native layer fallback`);
        fullText += layerText + "\n";
      } else {
        fullText += ocrText + "\n";
      }

    } catch (ocrErr) {
      console.warn(`extractFullPDFText: OCR failed page ${i}:`, ocrErr);
      if (layerText.length > 0) {
        fullText += layerText + "\n";
      }
    }
  }

  return fullText.trim();
}
