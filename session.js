/* =========================
    START SESSION (idempotent)
======================== */
let _sessionTimerInterval = null;

function startSessionTimer(){
    if (_sessionTimerInterval) return;
    if (window.VAULT_MODE === 'ADMIN') {
        const timer = document.getElementById('session-timer');
        if (timer) timer.style.display = 'none';
        return;
    }

    const timer =
    document.getElementById(
    'session-timer');

    _sessionTimerInterval = setInterval(()=>{

        sessionSeconds--;

        const mins =
        Math.floor(
        sessionSeconds / 60);

        const secs =
        sessionSeconds % 60;

        if (timer) timer.textContent =
        `${mins}:${secs<10?'0':''}${secs}`;

        if(sessionSeconds<=0){

            logoutVault("Session Expired.")

        }

    },1000);

}

/* =========================
   INACTIVITY (idempotent, uses addEventListener)
   Consolidated from auth.js resetInactivityTimer + session.js startInactivityMonitor
======================== */
let _inactivityMonitorAttached = false;
let inactivityTimer;

function resetInactivityTimer() {
    clearTimeout(inactivityTimer);
    if (window.VAULT_MODE === 'ADMIN') return;
    inactivityTimer = setTimeout(() => {
        logoutVault("Your session has expired.");
    }, 120000);
}

function startInactivityMonitor(){
    if (_inactivityMonitorAttached) return;

    // Merge events from both legacy implementations
    ["click","mousemove","mousedown","keydown","keypress","touchstart","scroll"].forEach(evt =>
        document.addEventListener(evt, resetInactivityTimer, { passive: true })
    );

    _inactivityMonitorAttached = true;
    resetInactivityTimer();
}

/* ========================= LOGOUT ========================= */
async function logout(message="") {
 clearTimeout(inactivityTimer);
 if (typeof _sessionTimerInterval !== 'undefined' && _sessionTimerInterval) {
     clearInterval(_sessionTimerInterval);
     _sessionTimerInterval = null;
 }
 _inactivityMonitorAttached = false;

 if (message) {
 showNotification('Session Ended', message, {type:'warning'});
 }
 notifyBackendLogout(message || "Logged out.");
 try {
 await fetch(
 "https://lively-star-38ef.shinumaths989.workers.dev/save-visitor-log",
 {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify({
 visitorName: document.getElementById( 'user-name' ).value,
 logoutTime: new Date() .toLocaleString(),
 status: "Logged Out"
 })
 }
 );
 } catch(e) { console.error( "Logout log error:", e ); }

 // Wipe session storage entirely
 sessionStorage.clear(); 

// On logout, call:
await fetch('https://lively-star-38ef.shinumaths989.workers.dev/logout', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ sessionId: window.currentSessionId }) // must be stored at login
});
   
 // Clear memory password
 window.masterPassword = null;
 masterPassword = null;

 // FIX: Clear DOM states to prevent input caching bugs
 if (document.getElementById("user-name")) document.getElementById("user-name").value = "";
 if (document.getElementById("user-purpose")) document.getElementById("user-purpose").value = "";
 if (document.getElementById("vault-pass")) document.getElementById("vault-pass").value = "";
 if (document.getElementById("terms-tick")) document.getElementById("terms-tick").checked = false;

 try {
     if (typeof grecaptcha !== 'undefined') {
         grecaptcha.reset();
     }
 } catch(e) {}

 location.reload(true);
}
