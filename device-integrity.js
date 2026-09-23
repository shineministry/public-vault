/* =========================
   DEVICE INTEGRITY & BEHAVIORAL DETECTION
   Maximally aggressive — whitelist admin devices
   ========================= */
window.__deviceIntegrity = (function () {

  const CHECKS = [];
  const FLAGS  = [];
  const BEHAVIOR_LOG = [];
  var PAGE_LOAD_TIME = Date.now();

  function flag(rule, detail, severity) {
    FLAGS.push({ rule, detail, severity: severity || 'high', ts: Date.now() });
  }

  function check(name, fn) {
    CHECKS.push({ name, fn });
  }

  function testUA(regex) {
    return regex.test((navigator.userAgent || '').toLowerCase());
  }

  // ── TRUSTED DEVICE SYSTEM ────────────────────────────────────────
  var TRUSTED_KEY = 'vault-trusted-device';

  function isTrusted() {
    return localStorage.getItem(TRUSTED_KEY) === 'true';
  }

  function markTrusted() {
    localStorage.setItem(TRUSTED_KEY, 'true');
  }

  function unmarkTrusted() {
    localStorage.removeItem(TRUSTED_KEY);
  }

  // ── SECRET-GATED MANUAL TRUST TOGGLE ─────────────────────────────
  // Previously Ctrl+Shift+D flipped trust instantly with NO authentication —
  // anyone with keyboard access to the login page could self-trust and
  // bypass every bot/automation check below. Now the gesture only OPENS
  // a prompt; trust is granted only if the entered secret's SHA-256 hash
  // matches TRUST_SECRET_HASH.
  //
  // ⚠️ Set your own secret before relying on this:
  //   1. Open password-hash.html (already in this project)
  //   2. Type a secret phrase only you know (not your vault password)
  //   3. Copy the resulting SHA-256 hash and paste it below.
  var TRUST_SECRET_HASH = '19c18a3da28f4aa226c42a8d2679f27ec6dbdfe2bc7642694fdb724c70b4f46d';

  async function _sha256(text) {
    if (window.sha256) return window.sha256(text);
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  function tryUnlockTrust(secret) {
    if (!secret) return Promise.resolve(false);
    return _sha256(secret.trim()).then(function (hash) {
      if (TRUST_SECRET_HASH === 'REPLACE_WITH_YOUR_OWN_SHA256_HASH') {
        toastNotify('Trust secret not configured yet. Set TRUST_SECRET_HASH in device-integrity.js first.', 'warning');

        return false;
      }
      if (hash === TRUST_SECRET_HASH) {
        if (isTrusted()) {
          unmarkTrusted();
          toastNotify('Trusted device removed. Aggressive checks active.', 'warning');
        } else {
          markTrusted();
          toastNotify('Device trusted. Checks bypassed.', 'success');
        }
        return true;
      }
      toastNotify('Incorrect secret.', 'error');
      return false;
    });
  }

  function openTrustPrompt() {
    if (document.getElementById('__diTrustModal')) return;

    var overlay = document.createElement('div');
    overlay.id = '__diTrustModal';
    overlay.style.cssText =
      'position:fixed;inset:0;z-index:999999;background:rgba(0,0,0,.65);' +
      'display:flex;align-items:center;justify-content:center;padding:20px;';

    overlay.innerHTML =
      '<div style="background:#111827;border:1px solid #2563eb;border-radius:14px;' +
      'padding:22px;max-width:320px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,.5);font-family:inherit;">' +
        '<div style="font-weight:800;color:#fff;font-size:15px;margin-bottom:6px;">🔒 Device Trust</div>' +
        '<div style="font-size:12px;color:#94a3b8;margin-bottom:14px;line-height:1.5;">' +
          'Enter your device-trust secret to mark or unmark this device as trusted.</div>' +
        '<input id="__diTrustInput" type="password" placeholder="Trust secret" ' +
          'style="width:100%;padding:10px;border-radius:8px;border:1px solid #374151;' +
          'background:#0b1220;color:#fff;font-size:14px;box-sizing:border-box;margin-bottom:12px;" autocomplete="off">' +
        '<div style="display:flex;gap:8px;">' +
          '<button id="__diTrustCancel" style="flex:1;padding:10px;border-radius:8px;border:none;' +
            'background:#374151;color:#fff;font-weight:700;font-size:13px;cursor:pointer;">Cancel</button>' +
          '<button id="__diTrustSubmit" style="flex:1;padding:10px;border-radius:8px;border:none;' +
            'background:#2563eb;color:#fff;font-weight:700;font-size:13px;cursor:pointer;">Confirm</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    var input = document.getElementById('__diTrustInput');
    input.focus();

    function close() { overlay.remove(); }

    document.getElementById('__diTrustCancel').addEventListener('click', close);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });

    function submit() {
      var val = input.value;
      close();
      tryUnlockTrust(val);
    }

    document.getElementById('__diTrustSubmit').addEventListener('click', submit);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') submit();
      if (e.key === 'Escape') close();
    });
  }

  // ── 1. AUTOMATION / BOT ──────────────────────────────────────────
  check('webdriver', function () {
    if (navigator.webdriver === true)
      flag('webdriver', 'navigator.webdriver is true');
  });

  check('chrome-automation', function () {
    if (window.chrome && window.chrome.automation)
      flag('chrome-automation', 'chrome.automation exposed');
  });

  check('automation-globals', function () {
    if (window.callPhantom || window._phantom || window.__nightmare || window.domAutomation || window.domAutomationController)
      flag('automation-globals', 'Automation framework global detected');
  });

  check('no-plugins', function () {
    if (!navigator.plugins || navigator.plugins.length === 0)
      flag('no-plugins', 'navigator.plugins empty/missing', 'medium');
  });

  check('no-mimetypes', function () {
    if (!navigator.mimeTypes || navigator.mimeTypes.length === 0)
      flag('no-mimetypes', 'navigator.mimeTypes empty/missing', 'medium');
  });

  check('no-languages', function () {
    if (!navigator.languages || navigator.languages.length === 0)
      flag('no-languages', 'navigator.languages empty', 'medium');
  });

  check('headless-ua', function () {
    if (testUA(/headless|phantom|puppet|selenium|playwright|pyppeteer|Cypress|webdriver/))
      flag('headless-ua', 'UA contains headless/automation marker');
  });

  check('pdf-viewer-disabled', function () {
    if (navigator.pdfViewerEnabled === false)
      flag('pdf-viewer-disabled', 'navigator.pdfViewerEnabled is false', 'medium');
  });

  check('webdriver-nav', function () {
    if (navigator.webdriver !== undefined && navigator.webdriver !== null)
      flag('webdriver-nav', 'navigator.webdriver property present', 'medium');
  });

  check('modified-prototypes', function () {
    try {
      if (document.__proto__.toString().indexOf('Document') === -1)
        flag('modified-prototypes', 'Document prototype modified', 'medium');
    } catch (e) {}
  });

  check('performance-memory', function () {
    if (performance.memory === undefined && testUA(/chrome|chromium|crios/))
      flag('performance-memory', 'performance.memory missing in Chrome', 'medium');
  });

  // ── 2. EMULATOR ──────────────────────────────────────────────────
  check('emulator-ua', function () {
    if (testUA(/android sdk|genymotion|Android.*Emulator|BlueStacks|Nox Player|MEmu|LeapDroid|AndyOS|Remix OS/i))
      flag('emulator-ua', 'UA indicates emulator');
  });

  check('emulator-build', function () {
    if (testUA(/sdk_gphone|emu64|generic_x86|generic_arm64|vsemu|goldfish|ranchu/))
      flag('emulator-build', 'UA has emulator build fingerprint');
  });

  check('ua-platform-mismatch', function () {
    try {
      var ua = (navigator.userAgent || '').toLowerCase();
      var plat = (navigator.platform || '').toLowerCase();
      if (testUA(/iphone|ipad|ipod/) && plat.indexOf('mac') === -1 && plat.indexOf('iphone') === -1)
        flag('ua-platform-mismatch', 'iOS UA but platform is not iOS', 'medium');
      if (testUA(/android/) && plat.indexOf('win') !== -1)
        flag('ua-platform-mismatch', 'Android UA but platform is Windows', 'medium');
      if (testUA(/mobile|android/) && plat.indexOf('linux') !== -1 && !testUA(/android/))
        flag('ua-platform-mismatch', 'Mobile UA but platform is Linux', 'medium');
    } catch (e) {}
  });

  check('subsystem-android', function () {
    if (testUA(/subsystem for android|wsa/i))
      flag('subsystem-android', 'Windows Subsystem for Android detected', 'medium');
  });

  // ── 3. DEBUGGER ──────────────────────────────────────────────────
  check('devtools-docked', function () {
    if (window.outerWidth - window.innerWidth > 200 || window.outerHeight - window.innerHeight > 200)
      flag('devtools-docked', 'DevTools docked');
  });

  check('devtools-element-trick', function () {
    try {
      if (document.body) {
        var e = document.createElement('div');
        e.style.cssText = 'position:fixed;width:1px;height:1px;top:-999px;left:-999px';
        document.body.appendChild(e);
        var base = e.offsetWidth;
        document.body.removeChild(e);
        if (Math.abs(window.outerWidth - window.innerWidth - base) > 50)
          flag('devtools-element', 'DevTools open (element size mismatch)');
      }
    } catch (e) {}
  });

  check('debugger-statement', function () {
    var start = Date.now();
    try {
      (function () {
        for (var i = 0; i < 50; i++) new Function('debugger')();
      })();
    } catch (e) {}
    if (Date.now() - start > 200)
      flag('debugger-statement', 'Debugger paused execution (' + (Date.now() - start) + 'ms)');
  });

  check('console-command-line', function () {
    try {
      if (console._commandLineAPI !== undefined)
        flag('console-command-line', 'console._commandLineAPI exposed');
    } catch (e) {}
  });

  check('firebug', function () {
    try {
      if (window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized)
        flag('firebug', 'Firebug detected');
    } catch (e) {}
  });

  // ── 4. VM / ENVIRONMENT ──────────────────────────────────────────
  check('cores-undefined', function () {
    if (navigator.hardwareConcurrency === undefined)
      flag('cores-undefined', 'hardwareConcurrency undefined', 'medium');
  });

  check('cores-power-of-two', function () {
    var c = navigator.hardwareConcurrency;
    if (c !== undefined && c > 0 && (c & (c - 1)) === 0 && c <= 4)
      flag('cores-power-of-two', 'Cores is power-of-two (' + c + ') — common VM allocation', 'medium');
  });

  check('memory-undefined', function () {
    if (navigator.deviceMemory === undefined)
      flag('memory-undefined', 'deviceMemory undefined', 'medium');
  });

  check('vm-resolution', function () {
    var w = screen.width, h = screen.height;
    if ((w === 1024 && h === 768) || (w === 800 && h === 600) || (w === 1152 && h === 864))
      flag('vm-resolution', w + 'x' + h + ' — typical VM resolution', 'medium');
  });

  check('screen-avail-ratio', function () {
    if (screen.availWidth && screen.width && (screen.availWidth / screen.width) > 0.98)
      flag('screen-avail-ratio', 'Taskbar unobtrusive — VM pattern', 'medium');
  });

  check('product-sub', function () {
    try {
      if (navigator.productSub && navigator.productSub !== '20030107')
        flag('product-sub', 'navigator.productSub is not 20030107', 'medium');
    } catch (e) {}
  });

  // ── 5. BEHAVIORAL: TYPING ────────────────────────────────────────
  var _typingData = { timestamps: [], fieldId: null };
  var _typingMonitorActive = false;

  function startTypingMonitor(fieldId) {
    if (_typingMonitorActive) return;
    _typingMonitorActive = true;
    _typingData.fieldId = fieldId;
    var field = document.getElementById(fieldId);
    if (!field) return;

    field.addEventListener('keydown', function _onKey(e) {
      if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta' ||
          e.key === 'CapsLock' || e.key === 'Tab' || e.key === 'Escape') return;
      _typingData.timestamps.push(Date.now());
      if (_typingData.timestamps.length > 30) _typingData.timestamps.shift();
    }, { passive: true });

    _typingData.check = function () {
      if (this.timestamps.length < 5) return null;
      var intervals = [];
      for (var i = 1; i < this.timestamps.length; i++)
        intervals.push(this.timestamps[i] - this.timestamps[i - 1]);
      var avg = intervals.reduce(function (a, b) { return a + b; }, 0) / intervals.length;
      var zeroGaps = intervals.filter(function (v) { return v < 20; }).length;
      return { avg: avg, zeroGaps: zeroGaps, count: this.timestamps.length };
    };
  }

  // ── 6. BEHAVIORAL: PASTE ─────────────────────────────────────────
  // Removed: pasting into a password field is completely normal
  // (password managers, notes app, older users who copy their PIN)
  // and was wrongly treated as a bot signal, blocking real people.
  function startPasteMonitor(fieldId) {
    // intentionally a no-op now — kept as a stub so any external
    // calls to startPasteMonitor() elsewhere don't break.
  }

  // ── 7. BEHAVIORAL: MOUSE ─────────────────────────────────────────
  var _mousePositions = [];
  var _mouseMonitorActive = false;
  var _mouseMoved = false;

  function startMouseMonitor() {
    if (_mouseMonitorActive) return;
    _mouseMonitorActive = true;
    document.addEventListener('mousemove', function (e) {
      _mouseMoved = true;
      _mousePositions.push({ x: e.clientX, y: e.clientY, t: Date.now() });
      if (_mousePositions.length > 100) _mousePositions.shift();
    }, { passive: true });
  }

  function analyzeMousePattern() {
    var result = { samples: _mousePositions.length };
    if (!_mouseMoved) { result.noMovement = true; return result; }
    if (_mousePositions.length < 10) return result;
    var teleports = [];
    for (var i = 1; i < _mousePositions.length; i++) {
      var dx = _mousePositions[i].x - _mousePositions[i - 1].x;
      var dy = _mousePositions[i].y - _mousePositions[i - 1].y;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dist > 500 && (_mousePositions[i].t - _mousePositions[i - 1].t) < 200)
        teleports.push(dist);
    }
    result.teleports = teleports.length;
    return result;
  }

  // ── 8. BEHAVIORAL: TAB / FOCUS ───────────────────────────────────
  check('hidden-tab', function () {
    if (document.visibilityState === 'hidden')
      flag('hidden-tab', 'Tab is hidden during login attempt', 'medium');
  });

  check('no-focus', function () {
    if (document.hasFocus && !document.hasFocus())
      flag('no-focus', 'Window does not have focus during login', 'medium');
  });

  check('instant-interaction', function () {
    try {
      var field = document.getElementById('vault-pass');
      if (field) {
        field.addEventListener('focus', function instantFocus() {
          if (Date.now() - PAGE_LOAD_TIME < 300)
            flag('instant-interaction', 'Password field focused <300ms after page load');
          field.removeEventListener('focus', instantFocus);
        }, { once: true });
      }
    } catch (e) {}
  });

  // ── RUN ──────────────────────────────────────────────────────────
  function runChecks() {
    FLAGS.length = 0;
    for (var i = 0; i < CHECKS.length; i++) {
      try { CHECKS[i].fn(); } catch (e) {}
    }
    return FLAGS;
  }

  function getRiskScore() {
    var flags = runChecks();
    var score = flags.length * 5;

    var td = _typingData.check ? _typingData.check() : null;
    if (td) {
      BEHAVIOR_LOG.push('typing avg ' + td.avg.toFixed(0) + 'ms, ' + td.zeroGaps + ' zero-gaps');
      if (td.avg < 150 && td.count >= 5)
        flag('auto-typing', 'Avg keystroke ' + td.avg.toFixed(0) + 'ms');
      if (td.zeroGaps >= 3)
        flag('typing-zero-gaps', td.zeroGaps + ' near-zero keystroke gaps');
    }

    var md = analyzeMousePattern();
    if (md) {
      if (md.noMovement)
        flag('no-mouse-movement', 'Zero mouse movement before login', 'medium');
      else if (md.teleports > 1)
        flag('mouse-teleport', md.teleports + ' mouse teleports');
      BEHAVIOR_LOG.push('mouse samples=' + md.samples + ' teleports=' + (md.teleports || 0) + ' noMove=' + (md.noMovement || false));
    }

    // Paste check removed — see startPasteMonitor() note above.

    return { score: score, flags: FLAGS };
  }

  function startBehavioralMonitoring() {
    startMouseMonitor();
    startTypingMonitor('vault-pass');
    startPasteMonitor('vault-pass');
  }

  function getDeviceReport() {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      cores: navigator.hardwareConcurrency,
      memory: navigator.deviceMemory,
      screen: screen.width + 'x' + screen.height,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      webdriver: navigator.webdriver,
      pluginsLen: navigator.plugins ? navigator.plugins.length : -1,
      languages: navigator.languages,
      pdfViewer: navigator.pdfViewerEnabled,
      maxTouchPoints: navigator.maxTouchPoints,
      productSub: navigator.productSub,
      trusted: isTrusted(),
      flags: FLAGS
    };
  }

  return {
    startBehavioralMonitoring: startBehavioralMonitoring,
    getRiskScore: getRiskScore,
    getDeviceReport: getDeviceReport,
    isTrusted: isTrusted,
    markTrusted: markTrusted,
    unmarkTrusted: unmarkTrusted,
    openTrustPrompt: openTrustPrompt,
    getFlags: function () { return FLAGS.slice(); },
    getBehaviorLog: function () { return BEHAVIOR_LOG.slice(); }
  };

})();

// Auto-start
document.addEventListener('DOMContentLoaded', function () {
  var di = window.__deviceIntegrity;
  if (!di) return;
  di.startBehavioralMonitoring();

  // Ctrl+Shift+D (desktop) — opens the secret-gated trust prompt.
  // No longer toggles trust instantly; see openTrustPrompt() above.
  document.addEventListener('keydown', function (e) {
    if (e.ctrlKey && e.shiftKey && (e.key === 'D' || e.key === 'd')) {
      e.preventDefault();
      di.openTrustPrompt();
    }
  });

  // Mobile equivalent — 5 taps on the vault logo within 2 seconds.
  // Ctrl+Shift+D doesn't exist on a touchscreen, so this hidden tap
  // gesture opens the same secret-gated prompt instead.
  (function setupMobileTrustGesture() {
    var logo = document.querySelector('.main-logo-container');
    if (!logo) return;

    var tapCount = 0;
    var tapResetTimer = null;

    logo.addEventListener('click', function () {
      tapCount++;
      clearTimeout(tapResetTimer);
      tapResetTimer = setTimeout(function () { tapCount = 0; }, 2000);

      if (tapCount >= 5) {
        tapCount = 0;
        clearTimeout(tapResetTimer);
        di.openTrustPrompt();
      }
    });
  })();
});
