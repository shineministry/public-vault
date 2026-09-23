/* =========================
   NOTE: Notification panel (toggleNotifications, renderNotifications,
   markAllNotifsRead, dismissNotifBubble, etc.) lives in features.js,
   which owns the real IndexedDB-backed vault_notifications store.
   A duplicate legacy "adminNotifications" localStorage-based system
   used to live here and, because this script loads after features.js,
   silently overrode the real toggleNotifications/renderNotifications —
   that's why the bell showed "No notifications" until "Mark all read"
   (which only existed in features.js) revealed the real list. Removed.
========================= */

document.addEventListener('visibilitychange', () => {

    const dash =
    document.getElementById(
    'vault-dashboard');

    if(!dash) return;

    if(document.hidden){

        dash.style.filter =
        "blur(18px)";

    }else{

        dash.style.filter =
        "blur(0px)";
    }

});

   function saveAccessLog(){

    const logs =
    JSON.parse(
    localStorage.getItem(
    'vaultLogs'
    ) || '[]');

    const visitorName =
    document.getElementById(
    'user-name').value;

    const purpose =
    document.getElementById(
    'user-purpose').value;

    const loginTime =
    new Date().toLocaleString();

    const device =
    /Mobi|Android/i.test(
    navigator.userAgent)
    ? "Mobile"
    : "Desktop";

    const screenSize =
    `${screen.width}x${screen.height}`;

    const timezone =
    Intl.DateTimeFormat()
    .resolvedOptions()
    .timeZone;

    logs.push({

        visitorName,
        purpose,
        loginTime,
        device,
        platform: device,
        screenSize,
        timezone

    });

    localStorage.setItem(
    'vaultLogs',
    JSON.stringify(logs)
    );

}

async function openLogs(){

    document.getElementById(
    'logModal'
    ).style.display =
    'block';

    const body =
    document.getElementById(
    'logBody'
    );

    body.innerHTML = '<tr><td colspan="9" style="padding:20px;text-align:center;color:#94a3b8;"><i data-lucide="loader" style="width:16px;height:16px;vertical-align:middle;"></i> Loading logs...</td></tr>';
    if (window.lucide) lucide.createIcons({node: body});

    try{

const token = sessionStorage.getItem('vaultSession') || '';
const res = await fetch(
    "https://lively-star-38ef.shinumaths989.workers.dev/get-logs",
    {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
        body: JSON.stringify({})
    }
);

if(!res.ok) throw new Error("Failed to load logs");

const logs = await res.json();

if (!Array.isArray(logs) || logs.length === 0) {
    body.innerHTML = '<tr><td colspan="9" style="padding:20px;text-align:center;color:#94a3b8;">No access logs found.</td></tr>';
    return;
}

        var rows = logs.map(function(log){
            return '<tr>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.visitorName || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.purpose || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.loginTime || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.device || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.platform || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.screen || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.timezone || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.ipAddress || '-') + '</td>' +
                '<td style="padding:10px;border:1px solid #ddd;">' + escHtml(log.location || '-') + '</td>' +
                '</tr>';
        }).join('');
        body.innerHTML = rows;

    }catch(e){

        console.error(e);
        body.innerHTML = '<tr><td colspan="9" style="padding:20px;text-align:center;color:#ef4444;">Failed to load logs. ' + escHtml(e.message || 'Unknown error') + '</td></tr>';

    }

}

function closeLogs(){

    document.getElementById(
    'logModal').style.display =
    'none';

}

/* =========================
   PASSKEY ACCESS
========================= */

/* ========================= MODE B: PASSKEY FLOW ========================= */
async function requestPasskeyAccess() {
    const visitorName = document.getElementById('user-name').value.trim();
    const purpose = document.getElementById('user-purpose').value.trim();

    if (!visitorName || !purpose) {
        toastNotify('Please enter your Full Name and Purpose of Access.', 'warning');
        return;
    }

    document.getElementById('step1').style.display = 'none';
    document.getElementById('passkey-wait').style.display = 'flex';

    let trackingId = "";

    // 1. Submit the initial request payload to generate a Firestore document tracking track
    try {
        const initRes = await fetch("https://lively-star-38ef.shinumaths989.workers.dev/request-passkey", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                visitorName: visitorName,
                purposeOfAccess: purpose,
                timestamp: new Date().toISOString()
            })
        });

        const initData = await initRes.json();
        if (initData && initData.requestId) {
            trackingId = initData.requestId;
        } else {
            throw new Error("Failed to allocate an administrative tracking request payload identifier.");
        }
    } catch (err) {
        toastNotify('Failed to register: ' + err.message, 'error');
        document.getElementById('passkey-wait').style.display = 'none';
        document.getElementById('step1').style.display = 'flex';
        return;
    }

    // 2. Poll the worker securely using the allocated document identifier
    const checkInterval = setInterval(async () => {
        try {
            const pollRes = await fetch("https://lively-star-38ef.shinumaths989.workers.dev/check-passkey", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    requestId: trackingId
                })
            });

            const data = await pollRes.json().catch(() => ({}));

            if (pollRes.status === 200 || data.status === 'approved') {
                if (data.sessionToken) {
                    clearInterval(checkInterval);
                    sessionStorage.setItem('vaultSessionToken', data.sessionToken);
                    sessionStorage.setItem('vaultSession', data.sessionToken);
                    document.getElementById('passkey-wait').style.display = 'none';
                    document.getElementById('step2').style.display = 'flex';
                } else if (data.success && data.status === 'approved') {
                    clearInterval(checkInterval);
                    toastNotify('Your request was approved. Please login again.', 'success');
                    location.reload();
                }
            } else if (pollRes.status === 403 || data.error) {
                if (data.error && data.error.includes("denied")) {
                    clearInterval(checkInterval);
                    toastNotify('Your request was declined.', 'error');
                    location.reload();
                }
            }
        } catch (e) {
            console.log("Polling connection drop, retrying...", e);
        }
    }, 3000);
}
