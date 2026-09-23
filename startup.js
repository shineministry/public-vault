/* =========================
   STARTUP SITE
========================= */

document.addEventListener('DOMContentLoaded', () => {

    /* LOAD SAVED SETTINGS */

    const savedVaultName =
    localStorage.getItem('vault-name');

    if(savedVaultName){

        const brand =
        document.querySelector('.brand-title');

        if(brand)
        brand.textContent = savedVaultName;
    }

    const savedTabTitle =
    localStorage.getItem('vault-tab-title');

    if(savedTabTitle){

        document.title = savedTabTitle;
    }

});
// ---- ADVANCED SETTINGS LOGIC ----

function toggleTrustedDevice(enabled) {
    if (!window.__deviceIntegrity) return;
    if (enabled) {
        window.__deviceIntegrity.markTrusted();
        toastNotify('Device trusted. Security checks will not block login.', 'success');
    } else {
        window.__deviceIntegrity.unmarkTrusted();
        toastNotify('Trust status removed. Aggressive security checks are active.', 'warning');
    }
}

document.getElementById('share-gear').onclick = () => {
    document.getElementById('advSettingsModal').classList.add('show');
    document.getElementById('lastSyncTime').textContent = 'Last synced: ' + new Date().toLocaleTimeString();
    const lt = document.getElementById('liteModeToggle');
    if(lt) lt.checked = window.LITE_MODE === true;
    // Sync trusted device toggle state
    const td = document.getElementById('trustedDeviceToggle');
    if (td && window.__deviceIntegrity) {
        td.checked = window.__deviceIntegrity.isTrusted();
    }
    const fp = document.getElementById('deviceFingerprintDisplay');
    if (fp && window.__deviceIntegrity) {
        fp.textContent = navigator.userAgent.slice(0, 80) + '...';
    }
};

function closeAdvSettings(){
    if (typeof window.animateCloseModal === 'function') {
        window.animateCloseModal('advSettingsModal');
    } else {
        document.getElementById('advSettingsModal').classList.remove('show');
    }
}

function switchAdvPanel(id){
    document.querySelectorAll('.adv-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.adv-menu-item').forEach(m => m.classList.remove('active'));
    const panel = document.getElementById('panel-' + id);
    if(panel) panel.classList.add('active');
    event.currentTarget.classList.add('active');
}

function applyVaultName(){

    const name =
    document.getElementById(
        'vaultNameInput'
    ).value.trim();

    const tab =
    document.getElementById(
        'tabTitleInput'
    ).value.trim();

    if(name){

        const brand =
        document.querySelector(
            '.brand-title'
        );

        if(brand)
        brand.textContent = name;

        localStorage.setItem(
            'vault-name',
            name
        );
    }

    if(tab){

        document.title = tab;

        localStorage.setItem(
            'vault-tab-title',
            tab
        );
    }

    const btn =
    event.currentTarget;

    btn.textContent =
    '✓ Applied!';

    setTimeout(() => {

        btn.textContent =
        '💾 Apply Name';

    }, 2000);
}
function setAccent(hex, el){
    document.documentElement.style.setProperty('--accent', hex);
    document.documentElement.style.setProperty('--accent2', hex);
    document.querySelectorAll('.adv-swatch').forEach(s => s.classList.remove('selected'));
    el.classList.add('selected');
    document.getElementById('accentColorPicker').value = hex;
}

function setAccentCustom(hex){
    document.documentElement.style.setProperty('--accent', hex);
    document.documentElement.style.setProperty('--accent2', hex);
    document.querySelectorAll('.adv-swatch').forEach(s => s.classList.remove('selected'));
}

function checkVaultHealth(){
    const bs = document.getElementById('backendStatus');
    const ts = document.getElementById('tokenStatus');
    bs.textContent = 'Checking...';
    fetch('https://lively-star-38ef.shinumaths989.workers.dev/get-secret', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hash:'healthcheck'})})
    .then(() => { bs.textContent = '✓ Backend reachable'; })
    .catch(() => { bs.textContent = '✗ Backend unreachable'; });
    const tok = sessionStorage.getItem('vaultSession');
    ts.textContent = tok ? '✓ Token present (' + tok.slice(0,12) + '...)' : '✗ No token found';
}

function revealToken(){
    const tok = sessionStorage.getItem('vaultSession') || sessionStorage.getItem('vaultSessionToken') || 'No token found';
    const masked = tok.length > 8 ? tok.slice(0, 4) + '****' + tok.slice(-4) : '****';
    document.getElementById('tokenDisplayBox').textContent = masked;
}

function runDupeScan(){
    const result = document.getElementById('dupeScanResult');
    result.style.display = 'block';
    const files = Object.values(window.allFilesData || {}).flat();
    const keys = files.map(f => f.file);
    const dupes = keys.filter((k,i) => keys.indexOf(k) !== i);
    result.textContent = dupes.length ? '⚠️ Duplicates found: ' + [...new Set(dupes)].join(', ') : '✓ No duplicates found';
}

function exportVaultConfig(){
    const cfg = {
        exportedAt: new Date().toISOString(),
        vaultName: (function(){ const el = document.querySelector('.brand-title'); return el ? el.textContent : ''; })() || 'FORTRESS ONLINE VAULT',
        tabTitle: document.title,
        accentColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(),
        liteMode: window.LITE_MODE,
        settings: {
            rememberMember: (document.getElementById('rememberMemberToggle') || {}).checked,
            autoSync: (document.getElementById('autoSyncToggle') || {}).checked,
            devMode: (document.getElementById('devModeToggle') || {}).checked
        }
    };
    const blob = new Blob([JSON.stringify(cfg, null, 2)], {type:'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vaultconfig.json';
    a.click();
}

function importVaultConfig(input){
    const file = input.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const cfg = JSON.parse(e.target.result);
            if(cfg.vaultName){ const b = document.querySelector('.brand-title'); if(b) b.textContent = cfg.vaultName; }
            if(cfg.tabTitle) document.title = cfg.tabTitle;
            toastNotify('Config imported successfully!', 'success');
        } catch(err) {
            toastNotify('Invalid config file.', 'error');
        }
    };
    reader.readAsText(file);
}

function advJsonRepair(){
    const raw = prompt('Paste JSON to validate:');
    if(!raw) return;
    try { JSON.parse(raw); toastNotify('Valid JSON!', 'success'); }
    catch(e) { toastNotify('Invalid JSON: ' + e.message, 'error'); }
}

function toggleStealthMode(on){
    const brand = document.querySelector('.brand-title');
    if(brand) brand.textContent = on ? 'Document Manager' : (document.getElementById('vaultNameInput').value || 'FORTRESS ONLINE VAULT');
}

// Panic Lock keyboard shortcut
document.addEventListener('keydown', (e) => {
    if(e.ctrlKey && e.shiftKey && e.key === 'L'){
        const tog = document.getElementById('panicShortcutToggle');
        if(tog && tog.checked){
            if(typeof logoutVault === 'function') logoutVault('🔴 Panic Lock triggered via keyboard.', true);
        }
    }
});

// Close modal on backdrop click
document.getElementById('advSettingsModal').addEventListener('click', (e) => {
    if(e.target === document.getElementById('advSettingsModal')) closeAdvSettings();
});

/* =========================
   MOBILE NAV MENU
========================= */
function toggleMobileMenu(){
    const menu = document.getElementById('mobile-nav-menu');
    menu.classList.toggle('open');
}

// Close mobile menu when tapping outside
document.addEventListener('click', (e) => {
    const menu = document.getElementById('mobile-nav-menu');
    const btn   = document.getElementById('mobileMenuBtn');
    if (menu && btn && !menu.contains(e.target) && !btn.contains(e.target)) {
        menu.classList.remove('open');
    }
});

   // Sidebar and file grid are populated by initVault() after login.
// initVault() handles both flat-array and category-object formats from the backend.
