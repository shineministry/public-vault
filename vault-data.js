/* =========================
   INIT VAULT
========================= */

async function initVault() {
try {

    // GET TEMP SESSION TOKEN
    const sessionToken =
        sessionStorage.getItem("vaultSession");

    // check login
    if (!sessionToken) {
        throw new Error(
            "No active secure session. Please login again."
        );
    }

    // Try network first; fall back to IndexedDB (vault_meta) when offline
    let data = {};
    try {
        const res = await fetch(
            "https://backend.shinumaths989.workers.dev/files.json?_t=" + Date.now(),
            { headers: { "Authorization": "Bearer " + sessionToken }, cache: "no-store" }
        );

        // Firewall / backend errors
        if (!res.ok) {
            const contentType = res.headers.get('content-type') || '';
            if (contentType.includes('text/html')) {
                throw new Error("Security Exception: Domain rejected by Gateway Firewall.");
            }
            throw new Error(`Server returned HTTP status ${res.status}`);
        }

        const raw = await res.json();
        // Normalise: backend may return either
        //   a) category-keyed object  { "Passport": [{...}], "ID": [{...}] }
        //   b) flat array             [ {name, file, member, category}, ... ]
        if (Array.isArray(raw)) {
            raw.forEach(file => {
                const cat = file.category || file.type || "Documents";
                if (!data[cat]) data[cat] = [];
                data[cat].push(file);
            });
        } else if (raw && typeof raw === 'object') {
            data = raw;
        } else {
            throw new Error("Unexpected response format from files.json");
        }

        // Cache file list for offline use
        if (typeof idbSetVaultMeta === 'function') {
            idbSetVaultMeta(data).catch(() => {});
        }

    } catch (netErr) {
        // Network failed - try cached file list from IndexedDB
        if (typeof idbGetVaultMeta === 'function') {
            const cached = await idbGetVaultMeta();
            if (cached) {
                data = cached;
                console.log('[initVault] Using cached file list (offline mode).');
            } else {
                throw new Error('No internet and no cached file list. Log in online first.');
            }
        } else {
            throw netErr;
        }
    }

    allFilesData = data;

    const list = document.getElementById('cat-list');
const _buildMode = window.VAULT_MODE || sessionStorage.getItem("vaultMode") || "VIEWER";
list.innerHTML = `
  <li id="nav-home" onclick="selectVaultCategory('HOME')" style="font-weight:700;">
    <span style="font-size:15px;"><i data-lucide="home" style="width:15px;height:15px;"></i></span><span>HOME</span>
  </li>
  ${_buildMode !== 'OFFICIAL' ? `
  <li id="nav-profile" onclick="selectVaultCategory('PROFILE')" style="font-weight:700;">
    <span style="font-size:15px;"><i data-lucide="user" style="width:15px;height:15px;"></i></span><span>PROFILE</span>
  </li>` : ''}
  <li id="nav-photos" onclick="selectVaultCategory('PHOTOS')" style="font-weight:700;">
    <span style="font-size:15px;"><i data-lucide="camera" style="width:15px;height:15px;"></i></span><span>PHOTOS</span>
  </li>
  <li id="nav-checklist" onclick="selectVaultCategory('CHECKLIST')" style="font-weight:700;">
    <span style="font-size:15px;"><i data-lucide="check-circle" style="width:15px;height:15px;"></i></span><span>CHECKLIST</span>
  </li>
`;

    const mode = window.VAULT_MODE || sessionStorage.getItem("vaultMode") || "VIEWER";

    // Backend already filters by mode - show ALL returned categories.
    // The frontend should NOT re-filter here; trust the backend.
    const categories = Object.keys(data);

    if (categories.length === 0) {
        list.innerHTML = '<li style="color:var(--muted);font-size:12px;pointer-events:none;font-weight:normal;">No documents found</li>';
        return;
    }

    // Category icon map for dark sidebar
    const CAT_ICONS = {
        'HOME': 'home', 'PROFILE': 'user', 'Guardian': 'users', 'Visa': 'plane', 'Finance': 'wallet',
        'School': 'graduation-cap', 'Personal': 'user', 'Residence': 'home', 'Church': 'cross',
        'Education': 'book-open', 'Identity': 'contact', 'Legal': 'scale', 'Financial': 'credit-card',
        'Ministry': 'bird', 'Medical': 'stethoscope', 'Insurance': 'shield', 'Tax': 'clipboard-list',
        'Property': 'home', 'Vehicle': 'car', 'Travel': 'globe', 'Work': 'briefcase',
        'Bank': 'landmark', 'Documents': 'file-text', 'Certificates': 'award'
    };
    function getCatIcon(cat) {
        return CAT_ICONS[cat] || CAT_ICONS[Object.keys(CAT_ICONS).find(k => cat.toLowerCase().includes(k.toLowerCase()))] || 'folder';
    }

    categories.forEach(cat => {
    if (cat === 'HOME' || cat === 'PROFILE' || cat === 'PHOTOS') return;
    const li = document.createElement('li');
    const icon = getCatIcon(cat);
    li.innerHTML = `<span style="font-size:15px;"><i data-lucide="${icon}" style="width:15px;height:15px;"></i></span><span>${escHtml(cat)}</span>`;
    li.onclick = () => {
    if (typeof selectVaultCategory === 'function') {
        selectVaultCategory(cat);
    }
    };
       
list.appendChild(li);

});

// Auto-click HOME first
if (typeof lucide !== 'undefined') lucide.createIcons();
const homeLi = [...list.querySelectorAll('li')].find(li => li.innerText.trim().includes('HOME'));
if (homeLi) homeLi.click();
else if (list.querySelector('li')) list.querySelector('li').click();

} catch (e) {

    console.error("initVault error:", e);

    document.getElementById('cat-title').textContent = "Vault System Locked";

    const grid = document.getElementById('file-grid');
    grid.innerHTML = `
    <div style="
        grid-column:1/-1;
        padding:30px;
        text-align:center;
        color:var(--danger);
        font-weight:700;
    ">
        <i data-lucide="alert-triangle" style="width:24px;height:24px;color:var(--danger);"></i> ${escHtml(e.message) || "Failed to load secure database."}
    </div>`;
}
}

/* =========================
   PROFILES DATA (module scope)
========================= */
const profiles = {

shineil:{
image:"profile.png",
name:"SHINEIL KEITH MATHIAS",
role:"Founder of SHINE MINISTRY - Student - Public Speaker - Digital Creator",

personal:`
<b>Full Name:</b> Shineil Keith Mathias<br>
<b>Date of Birth:</b> 7 March 2010<br>
<b>Gender:</b> Male<br>
<b>Nationality:</b> Indian<br>
<b>Location:</b> Khandala, Pune
`,

contact:`
<b>Contact via vault support portal</b>
`,

education:`
Don Bosco High School<br>
2020-2026<br>
Secondary Education
`,

skills:`
- Public Speaking<br>
- Leadership<br>
- Mathematics<br>
- Web Editing
`,

languages:`
English - Fluent<br>
Hindi - Fluent<br>
German - Basic
`,

achievements:`
- Green House Captain<br>
- Debate Awards<br>
- Student Recognition
`,

experience:`
Founder - SHINE MINISTRY<br>
Digital Projects<br>
Leadership Activities
`,

projects:`
Secure Vault<br>
SHINE MINISTRY<br>
PDF Systems
`,

goals:`
Technology<br>
Education<br>
Leadership
`,

faith:`
Founder of SHINE MINISTRY<br>
Christian Service
`,

about:`
Student with strong communication,
leadership and ministry interests.
`,

hobbies:`
Debating, technology,
public speaking, reading
`
},



brother:{

image:"ProfileK.png",
name:"KEVIN SHREESH MATHIAS",
role:"Bartender - Hospitality",

personal:`
<b>Name:</b> Kevin Shreesh Mathias<br>
<b>Location:</b> Pune<br>
<b>Industry:</b> Hospitality
`,

contact:`
Add Number<br>
Add Email
`,

education:`
Guardian School - SSC<br>
IHM Mumbai<br>
Flair Mania Bartending Academy
`,

skills:`
- Bartending<br>
- Customer Service<br>
- POS<br>
- Inventory
`,

languages:`
English<br>
Hindi
`,

achievements:`
Assistant Bartender - Bombay Cartel<br>
Assistant Bartender - Janwani
`,

experience:`
2023-2025 Bombay Cartel<br>
Present - Janwani
`,

projects:`
Hospitality Training<br>
Service Experience
`,

goals:`
Career Growth<br>
Hospitality Industry
`,

faith:`-`,

about:`
Hospitality professional with
bartending and customer service experience.
`,

hobbies:`
Service industry,
teamwork,
food & beverage
`
},



father:{
image:"ProfileSt.png",
name:"STEPHEN CONDRAD MATHIAS",
role:"Father",
personal:`Add`,
contact:`+91 99216 68744, +91 93707 50143`,
education:`Add`,
skills:`Add`,
languages:`English, Hindi, Konkani, Tulu, Kannada`,
achievements:`Add`,
experience:`Add`,
projects:`Add`,
goals:`Add`,
faith:`Roman Catholic`,
about:`Add`,
hobbies:`Add`
},



mother:{
image:"ProfileKa.png",
name:"KANCHAN MATHIAS",
role:"Mother",
personal:`Add`,
contact:`Add`,
education:`Add`,
skills:`Add`,
languages:`Add`,
achievements:`Add`,
experience:`Add`,
projects:`Add`,
goals:`Add`,
faith:`Add`,
about:`Add`,
hobbies:`Add`
}

};

// -- Category summaries (item 2): short blurb shown above each category's
// file grid so the user knows at a glance what the category contains. --
const CAT_SUMMARIES = {
    'Visa':         'Visa applications, approvals, and travel authorization documents.',
    'Guardian':     'Guardian access records and authorizations for trusted contacts.',
    'School':       'School admission, report cards, and academic records.',
    'Finance':      'Bank statements, financial records, and money-related documents.',
    'Financial':    'Bank statements, financial records, and money-related documents.',
    'Personal':     'Personal identification and miscellaneous personal records.',
    'Residence':    'Residence proofs, rental agreements, and address records.',
    'Church':       'Church and ministry related certificates and records.',
    'Education':    'Academic certificates, mark sheets, and education history.',
    'Identity':     'Government-issued identity documents (ID cards, passports, etc.).',
    'Legal':        'Legal declarations, agreements, and official legal paperwork.',
    'Ministry':     'Ministry activity records and related documentation.',
    'Medical':      'Medical reports, prescriptions, and health records.',
    'Insurance':    'Insurance policies, claims, and coverage documents.',
    'Tax':          'Tax filings, receipts, and related financial paperwork.',
    'Property':     'Property ownership, deeds, and related legal documents.',
    'Vehicle':      'Vehicle registration, insurance, and ownership documents.',
    'Travel':       'Travel itineraries, bookings, and trip-related documents.',
    'Work':         'Employment, work experience, and professional documents.',
    'Bank':         'Bank account statements and related financial documents.',
    'Certificates': 'Awards, certifications, and recognition documents.'
};

function getCatSummary(cat) {
    return CAT_SUMMARIES[cat]
        || CAT_SUMMARIES[Object.keys(CAT_SUMMARIES).find(k => cat.toLowerCase().includes(k.toLowerCase()))]
        || `Documents related to ${escHtml(cat)}.`;
}



function buildHomeDashboard(){

    const categories = Object.keys(allFilesData || {});
    let totalFiles = 0;
    categories.forEach(c => totalFiles += (allFilesData[c] || []).length);

    let recents = [];
    try{ recents = JSON.parse(localStorage.getItem('recentFiles') || '[]'); }catch(e){}

    const esc = window.escHtml;
    const historyHTML = recents.length
        ? recents.slice(0,8).map(r => `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;background:#f8fafc;border:1px solid var(--border);margin-bottom:8px;">
                <div style="overflow:hidden;">
                    <div style="font-weight:700;font-size:12.5px;color:var(--text-main, #0f172a);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><i data-lucide="file-text" style="width:14px;height:14px;vertical-align:middle;"></i> ${esc(r.name)}</div>
                    <div style="font-size:10.5px;color:var(--muted);margin-top:2px;">${esc(r.category || '')} - ${esc(r.date || '')}</div>
                </div>
            </div>`).join('')
        : `<div style="padding:16px;text-align:center;color:var(--muted);font-size:12px;">No files viewed yet</div>`;

    const categoriesHTML = categories.length
        ? categories.map(c => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-radius:12px;background:#f8fafc;border:1px solid var(--border);margin-bottom:8px;">
                <div style="font-weight:700;font-size:12.5px;color:var(--text-main, #0f172a);"><i data-lucide="folder" style="width:14px;height:14px;vertical-align:middle;"></i> ${esc(c)}</div>
                <div style="font-size:11px;font-weight:800;color:var(--accent);background:#eff6ff;padding:3px 10px;border-radius:999px;">${esc((allFilesData[c]||[]).length)}</div>
            </div>`).join('')
        : `<div style="padding:16px;text-align:center;color:var(--muted);font-size:12px;">No categories</div>`;

    return `
    <div style="grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:8px;">
        <div style="background:white;border:1px solid var(--border);border-radius:20px;padding:22px;display:flex;align-items:center;gap:16px;">
            <div style="font-size:30px;"><i data-lucide="folder-open" style="width:30px;height:30px;color:var(--accent);"></i></div>
            <div>
                <div style="font-size:11px;font-weight:800;letter-spacing:.5px;color:var(--muted);">NO. OF FILES IN VAULT</div>
                <div style="font-size:24px;font-weight:900;color:var(--accent);">${totalFiles}</div>
            </div>
        </div>
        <div style="background:white;border:1px solid var(--border);border-radius:20px;padding:22px;display:flex;align-items:center;gap:16px;">
            <div style="font-size:30px;"><i data-lucide="shield" style="width:30px;height:30px;color:var(--success,#16a34a);"></i></div>
            <div>
                <div style="font-size:11px;font-weight:800;letter-spacing:.5px;color:var(--muted);">SECURITY STATUS</div>
                <div style="font-size:18px;font-weight:900;color:var(--success,#16a34a);">Protected - AES-256</div>
            </div>
        </div>
    </div>

    <div style="grid-column:1/-1;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;margin-bottom:8px;">
        <div class="profile-box" style="text-align:left;">
            <h3><i data-lucide="clock" style="width:16px;height:16px;vertical-align:middle;"></i> Files History</h3>
            ${historyHTML}
        </div>
        <div class="profile-box" style="text-align:left;">
            <h3><i data-lucide="book-open" style="width:16px;height:16px;vertical-align:middle;"></i> Categories</h3>
            ${categoriesHTML}
        </div>
    </div>
    `;
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

/* =========================
   FILES
========================= */

function renderFiles(
files,
category){
   
    currentCategory = category;

    document.getElementById(
    'cat-title').textContent =
    category;

    const grid =
    document.getElementById(
    'file-grid');

    // Remove photo-grid class when showing regular files
    if (grid) grid.classList.remove('photo-grid');

   if(category==="HOME"){

// For non-admin modes the dropdown is hidden, so derive member from VAULT_MODE
const modeToMember = {
    "SHINEIL": "shineil",
    "KEVIN": "brother",
    "KEVIN_PARENTS": "brother",
    "SHINEIL_PARENTS": "shineil",
    "PARENTS": "father",
    "OFFICIAL": "shineil",
    "ADMIN": null
};

const _vaultMode = window.VAULT_MODE || sessionStorage.getItem("vaultMode") || "ADMIN";
const dropdownEl = document.getElementById("member-select"); const dropdownVal = (dropdownEl ? dropdownEl.value : '') || "shineil";
const member = (_vaultMode === "ADMIN")
    ? (dropdownVal || "shineil")
    : (modeToMember[_vaultMode] || dropdownVal || "shineil");

const profile =
profiles[member] || profiles.shineil;


grid.innerHTML=`

<div style="
grid-column:1/-1;
background:white;
border:1px solid var(--border);
border-radius:24px;
padding:35px;">

<div style="
display:flex;
gap:25px;
flex-wrap:wrap;
margin-bottom:30px;">

<img src="${profile.image}"
style="
width:150px;
height:150px;
border-radius:24px;
object-fit:cover;">

<div>

<h1 style="
color:var(--accent);">

${profile.name}

</h1>

<div style="
color:var(--muted);">

${profile.role}

</div>

</div>
</div>



<div style="
display:grid;
grid-template-columns:
repeat(auto-fit,minmax(260px,1fr));
gap:20px;">

<div class="profile-box">
<h3>Personal Details</h3>
${profile.personal}
</div>

<div class="profile-box">
<h3>Contact</h3>
${profile.contact}
</div>

<div class="profile-box">
<h3>Education</h3>
${profile.education}
</div>

<div class="profile-box">
<h3>Skills</h3>
${profile.skills}
</div>

<div class="profile-box">
<h3>Languages</h3>
${profile.languages}
</div>

<div class="profile-box">
<h3>Achievements</h3>
${profile.achievements}
</div>

<div class="profile-box">
<h3>Experience</h3>
${profile.experience}
</div>

<div class="profile-box">
<h3>Projects</h3>
${profile.projects}
</div>

<div class="profile-box">
<h3>Future Goals</h3>
${profile.goals}
</div>

<div class="profile-box">
<h3>Faith / Ministry</h3>
${profile.faith}
</div>

</div>



<div style="
margin-top:25px;
background:#eff6ff;
padding:24px;
border-radius:18px;">

<h3>About Me</h3>

${profile.about}

</div>



<div style="
margin-top:25px;
background:#f8fafc;
padding:24px;
border-radius:18px;">

<h3>Hobbies & Interests</h3>

${profile.hobbies}

</div>



<div style="
margin-top:25px;
background:#f8fafc;
padding:24px;
border-radius:18px;">

<h3>Timeline</h3>

2010 - Born<br>
2020 - Education<br>
2024 - Projects<br>
2025 - Present

</div>

</div>

`;

if (typeof lucide !== 'undefined') lucide.createIcons();
return;
}
   
    grid.innerHTML = `
       <div style="
    grid-column:1/-1;
    background:#f8fafc;
    border:1px solid var(--border);
    border-radius:16px;
    padding:14px 18px;
    margin-bottom:18px;
    color:#64748b;
    line-height:1.6;
    font-size:14px;">
    ${getCatSummary(category)}
</div>
   `;

    const visibleFiles =
window.LITE_MODE
? files.slice(0,20)
: files;

// -- Section grouping ------------------------------------------------------
// Group files by their `section` field. Files with no section render first,
// then each named section renders a coloured header above its files.
const _secMeta = (allFilesData && allFilesData['_meta']) ? allFilesData['_meta'] : {};
const _secDefs = Array.isArray(_secMeta[category]) ? _secMeta[category] : [];
const _secColorMap = {};
_secDefs.forEach(s => { _secColorMap[s.name] = s.color || '#1a73e8'; });

const _sectionGroups = {};
const _unsectioned = [];
visibleFiles.forEach(f => {
    const s = (f.section || '').trim();
    if (s) {
        if (!_sectionGroups[s]) _sectionGroups[s] = [];
        _sectionGroups[s].push(f);
    } else {
        _unsectioned.push(f);
    }
});

// Build ordered list: unsectioned first, then each section by definition order
const _orderedSections = _secDefs.map(s => s.name).filter(n => _sectionGroups[n]);
// Also include any sections found in files but not in _meta (edge case)
Object.keys(_sectionGroups).forEach(n => {
    if (_orderedSections.indexOf(n) === -1) _orderedSections.push(n);
});

const _driveViewMode = (localStorage.getItem('drive_view_mode') || 'grid');
    function _isDriveList(){ return document.getElementById('file-grid')?.classList.contains('drive-list'); }
    window.toggleDriveView = function(mode){
      localStorage.setItem('drive_view_mode', mode);
      const grid = document.getElementById('file-grid');
      if(!grid) return;
      grid.classList.toggle('drive-list', mode==='list');
      document.querySelectorAll('.drive-view-toggle button').forEach(b=> b.classList.toggle('active', b.dataset.mode===mode));
      // re-render current category to switch card structure
      if(currentCategory && allFilesData[currentCategory]) renderFiles(allFilesData[currentCategory], currentCategory);
    };

    const _renderFileCard = (file) => {

        const isList = _isDriveList();
        const card = document.createElement('div');
        if(isList){
          card.className = 'drive-list-row';
          const ext = (file.file||file.name||'').split('.').pop().toLowerCase();
          const isImg = ['jpg','jpeg','png','gif','webp','bmp'].includes(ext);
          card.innerHTML = `
            <div class="drive-list-name"><span class="li-icon ${isImg?'img':''}"><i data-lucide="${isImg?'image':'file-text'}" style="width:14px;height:14px;"></i></span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(file.name)}</span></div>
            <div class="drive-list-col hide-m">${escHtml(file.category||category)}</div>
            <div class="drive-list-col hide-m">${escHtml(file.date||file.expiry||'-')}</div>
            <button class="drive-more-btn" onclick="event.stopPropagation(); openDriveMenu(this, ${JSON.stringify(file).replace(/"/g,'&quot;')})" style="opacity:1;"><i data-lucide="more-vertical" style="width:16px;height:16px;"></i></button>
          `;
          card.onclick = ()=> openSecureFile((file.category === 'PHOTOS' ? "photos/" : "docs/") + file.file, file.name);
          grid.appendChild(card);
          return;
        }

        card.className = 'file-card drive-card';

        // EXPIRY BADGE
        let expiryBadge = '';
        if(file.expiry){
            const daysLeft = Math.ceil((new Date(file.expiry) - new Date()) / 86400000);
            if(daysLeft < 0){ expiryBadge = `<span class="expiry-badge expiry-danger" style="position:absolute;top:8px;right:36px;"><i data-lucide="triangle-alert" style="width:12px;height:12px;"></i> Expired</span>`; }
            else if(daysLeft <= 30){ expiryBadge = `<span class="expiry-badge expiry-warn" style="position:absolute;top:8px;right:36px;"><i data-lucide="clock" style="width:12px;height:12px;"></i> ${daysLeft}d</span>`; }
            else { expiryBadge = `<span class="expiry-badge expiry-ok" style="position:absolute;top:8px;right:36px;"><i data-lucide="check" style="width:12px;height:12px;"></i> ${daysLeft}d</span>`; }
        }
        const ext2 = (file.file||file.name||'').split('.').pop().toLowerCase();
        const isImg = ['jpg','jpeg','png','gif','webp','bmp'].includes(ext2);
        const isPinned = pinnedDocs.some(p => p.file === file.file);
        card.title = file.name;
        card.setAttribute('aria-label', file.name);

        card.innerHTML = `
        <label class="bulk-check-label" onclick="event.stopPropagation();" style="position:absolute;top:8px;left:8px;z-index:2;display:none;align-items:center;gap:4px;background:rgba(255,255,255,.92);padding:2px 6px 2px 4px;border-radius:6px;font-size:11px;cursor:pointer;box-shadow:0 1px 3px rgba(0,0,0,.18);">
          <input type="checkbox" class="bulk-check" data-file='${JSON.stringify({name:file.name,file:file.file,category:file.category||category}).replace(/'/g,"&#39;")}' onchange="updateBulkToolbar()" style="cursor:pointer;">
        </label>
        ${expiryBadge}
        <div class="drive-card-thumb" style="background:#f1f3f4; position:relative; overflow:hidden; display:flex; align-items:center; justify-content:center; padding:8px;">
          <canvas class="drive-thumb-canvas" style="max-width:100%; max-height:100%; width:auto; height:auto; background:#fff; box-shadow:0 2px 8px rgba(60,64,67,.12); border:1px solid #e8eaed; border-radius:4px; display:none;"></canvas>
          <div class="thumb-fallback" style="position:absolute; inset:0; display:flex; align-items:center; justify-content:center; background:#f8f9fa;"><i data-lucide="${isImg ? 'image' : 'file-text'}" style="width:42px;height:42px;color:${isImg ? '#34a853' : '#1967d2'};"></i></div>
          <div class="thumb-gradient" style="position:absolute; inset:0; pointer-events:none; background:linear-gradient(180deg, transparent 60%, rgba(60,64,67,.06));"></div>
          ${isPinned ? '<span style="position:absolute;top:8px;left:8px;color:#fbbc04;"><i data-lucide="star" style="width:16px;height:16px;fill:currentColor;"></i></span>' : ''}
        </div>
        <div class="drive-card-foot">
          <div class="doc-type-icon ${isImg?'img':''}"><i data-lucide="${isImg?'image':'file-text'}" style="width:16px;height:16px;"></i></div>
          <div style="flex:1;min-width:0;">
            <div class="drive-card-name" title="${escHtml(file.name)}">${escHtml(file.name)}</div>
            <div class="drive-card-meta">${escHtml(file.category||category)} - ${escHtml(file.date||'')}</div>
          </div>
          <button class="drive-more-btn" onclick="event.stopPropagation(); openDriveMenu(this, ${JSON.stringify(file).replace(/"/g,'&quot;')})"><i data-lucide="more-vertical" style="width:16px;height:16px;"></i></button>
        </div>
        <div class="drive-card-actions" style="display:flex; gap:6px; padding:8px 10px; border-top:1px solid #e8eaed; background:#f8fafc; justify-content:center; border-radius:0 0 12px 12px;">
          <button class="drive-action-btn ${isPinned ? 'pinned' : ''}" onclick="event.stopPropagation();togglePin(${JSON.stringify(file).replace(/"/g,'&quot;')},this)" title="Star"><i data-lucide="star" style="width:13px;height:13px;vertical-align:middle;${isPinned ? 'fill:currentColor;' : ''}"></i> Star</button>
          <button class="drive-action-btn" onclick="event.stopPropagation();openShareModal(${JSON.stringify(file).replace(/"/g,'&quot;')})" title="Share"><i data-lucide="link" style="width:13px;height:13px;vertical-align:middle;"></i> Share</button>
          <button class="drive-action-btn" onclick="event.stopPropagation();addToCompare(${JSON.stringify(file).replace(/"/g,'&quot;')})" title="Compare"><i data-lucide="scale" style="width:13px;height:13px;vertical-align:middle;"></i> Compare</button>
        </div>
        `;

        card.onclick = ()=>{
    openSecureFile(
        (file.category === 'PHOTOS' ? "photos/" : "docs/") + file.file,
        file.name
    );
};

        grid.appendChild(card);
        // Load preview image in thumb (instead of static icon) - async
        (function(){
          const canvas = card.querySelector('.drive-thumb-canvas');
          const fallback = card.querySelector('.thumb-fallback');
          if(!canvas || !fallback) return;
          const tryPreview = async () => {
            try {
              if(typeof getPreviewBitmap === 'function' && !window.LITE_MODE){
                const bmp = await getPreviewBitmap(file);
                if(bmp){
                  canvas.width = bmp.width;
                  canvas.height = bmp.height;
                  const ctx = canvas.getContext('2d');
                  if(ctx){ ctx.clearRect(0,0,canvas.width,canvas.height); ctx.drawImage(bmp,0,0); canvas.style.display='block'; fallback.style.display='none'; if(window.lucide) lucide.createIcons({node:card}); return; }
                }
              }
            } catch(e){}
          };
          if('requestIdleCallback' in window) requestIdleCallback(tryPreview, {timeout:2000}); else setTimeout(tryPreview, 150);
        })();
};

// -- Drive: apply saved view mode before rendering --
    if(localStorage.getItem('drive_view_mode')==='list') grid.classList.add('drive-list');
    else grid.classList.remove('drive-list');

    // -- Render unsectioned files first --
_unsectioned.forEach(f => _renderFileCard(f));

// -- Render each section with a Drive-style header --
_orderedSections.forEach(secName => {
    const color = _secColorMap[secName] || '#1a73e8';
    const hdr = document.createElement('div');
    const _r = parseInt(color.slice(1,3),16), _g = parseInt(color.slice(3,5),16), _b = parseInt(color.slice(5,7),16);
    hdr.style.cssText = `grid-column:1/-1;display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:10px;margin-top:14px;background:#fff;border:1px solid #dadce0;`;
    hdr.innerHTML = `
        <span style="width:28px;height:28px;border-radius:8px;background:${color};display:flex;align-items:center;justify-content:center;color:#fff;"><i data-lucide="folder" style="width:14px;height:14px;"></i></span>
        <div style="font-size:13px;font-weight:600;color:#202124;flex:1;">${escHtml(secName)}</div>
        <span style="font-size:11px;font-weight:600;color:#5f6368;background:#f1f3f4;padding:3px 8px;border-radius:12px;">${_sectionGroups[secName].length} items</span>
    `;
    grid.appendChild(hdr);
    _sectionGroups[secName].forEach(f => _renderFileCard(f));
});

    if (typeof lucide !== 'undefined') lucide.createIcons();
    // Drive: sync toolbar counts & chips after render
    if(typeof window._driveAfterRender === 'function') window._driveAfterRender(category, visibleFiles.length);
}

// -- Drive 3-dot contextual menu (matches Google Drive) --
window.openDriveMenu = function(btn, file){
  let menu = document.getElementById('driveCtxMenu');
  if(!menu){
    menu = document.createElement('div');
    menu.id = 'driveCtxMenu';
    menu.style.cssText = 'position:fixed;z-index:99999;background:#fff;border:1px solid #dadce0;border-radius:12px;box-shadow:0 4px 16px rgba(60,64,67,.25);padding:6px;min-width:190px;display:flex;flex-direction:column;gap:2px;';
    document.body.appendChild(menu);
    document.addEventListener('click', e=>{ if(!menu.contains(e.target) && !e.target.closest('.drive-more-btn')) menu.style.display='none'; });
    window.addEventListener('scroll', ()=> menu.style.display='none', true);
  }
  const r = btn.getBoundingClientRect();
  menu.innerHTML = `
    <button onclick="openSecureFile('${(file.category==='PHOTOS'?'photos/':'docs/')+file.file}','${(file.name||'').replace(/'/g,"\\'")}');document.getElementById('driveCtxMenu').style.display='none'" style="display:flex;gap:10px;align-items:center;padding:9px 12px;border:none;background:transparent;text-align:left;cursor:pointer;border-radius:8px;font-size:13px;color:#202124;"><i data-lucide="eye" style="width:16px;height:16px;"></i> Preview</button>
    <button onclick="openShareModal(${JSON.stringify(file).replace(/"/g,'&quot;')});document.getElementById('driveCtxMenu').style.display='none'" style="display:flex;gap:10px;align-items:center;padding:9px 12px;border:none;background:transparent;text-align:left;cursor:pointer;border-radius:8px;font-size:13px;color:#202124;"><i data-lucide="link" style="width:16px;height:16px;"></i> Share</button>
    <button onclick="togglePin(${JSON.stringify(file).replace(/"/g,'&quot;')},this);document.getElementById('driveCtxMenu').style.display='none'" style="display:flex;gap:10px;align-items:center;padding:9px 12px;border:none;background:transparent;text-align:left;cursor:pointer;border-radius:8px;font-size:13px;color:#202124;"><i data-lucide="star" style="width:16px;height:16px;"></i> Star</button>
    <button onclick="addToCompare(${JSON.stringify(file).replace(/"/g,'&quot;')});document.getElementById('driveCtxMenu').style.display='none'" style="display:flex;gap:10px;align-items:center;padding:9px 12px;border:none;background:transparent;text-align:left;cursor:pointer;border-radius:8px;font-size:13px;color:#202124;"><i data-lucide="scale" style="width:16px;height:16px;"></i> Compare</button>
    <div style="height:1px;background:#e8eaed;margin:4px 0;"></div>
    <button onclick="navigator.clipboard&&navigator.clipboard.writeText('${escHtml(file.file)}');toastNotify('File name copied','success');document.getElementById('driveCtxMenu').style.display='none'" style="display:flex;gap:10px;align-items:center;padding:9px 12px;border:none;background:transparent;text-align:left;cursor:pointer;border-radius:8px;font-size:13px;color:#5f6368;"><i data-lucide="info" style="width:16px;height:16px;"></i> Details</button>
  `;
  if(window.lucide) lucide.createIcons({node:menu});
  // position: flip if near right edge
  menu.style.display='flex';
  let left = r.right - 190;
  let top = r.bottom + 6;
  if(left < 8) left = 8;
  if(top + 180 > window.innerHeight) top = r.top - 180;
  menu.style.left = left+'px';
  menu.style.top = top+'px';
};

/* =========================
   PHOTOS GALLERY
   Scan all categories for image files and render a Google Photos-style grid
   with a lightbox viewer.
========================= */

const IMAGE_EXTS = ['jpg','jpeg','png','gif','webp','bmp'];

function isImageFile(file) {
    const name = (file.name || file.file || '').toLowerCase();
    return IMAGE_EXTS.some(ext => name.endsWith('.' + ext));
}

function getAllPhotos() {
    const photos = [];
    const data = window.allFilesData || {};
    Object.keys(data).forEach(cat => {
        const files = data[cat];
        if (!Array.isArray(files)) return;
        files.forEach(f => {
            if (cat === 'PHOTOS' || isImageFile(f)) {
                photos.push({ ...f, category: cat });
            }
        });
    });
    return photos;
}

function renderPhotos() {
    document.getElementById('cat-title').textContent = 'Photos';
    const grid = document.getElementById('photos-grid');
    if (!grid) { console.warn('[Photos] #photos-grid not found'); return; }
    grid.classList.add('photo-grid');
    let photos = [];
    try { photos = getAllPhotos(); } catch (e) { console.warn('[Photos] getAllPhotos error:', e); }
    const countEl = document.getElementById('photo-count');
    if (countEl) countEl.textContent = photos.length + ' photo(s)';

    grid.innerHTML = '';
    if (photos.length === 0) {
        grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:60px 20px;background:white;border-radius:20px;"><div style="margin-bottom:12px;"><i data-lucide="camera" style="width:48px;height:48px;color:var(--muted);"></i></div><div style="font-weight:700;font-size:16px;color:#64748b;">No photos found</div><div style="font-size:13px;color:#94a3b8;margin-top:6px;">Upload images to the vault to see them here.</div></div>';
        if (typeof lucide !== 'undefined') lucide.createIcons({node:grid});
        return;
    }

    // Build photo thumbnails - Google Photos style square grid
    photos.forEach((file, index) => {
        const card = document.createElement('div');
        card.className = 'photo-card';
        card.dataset.index = index;
        card.onclick = () => openPhotoViewer(photos, index);

        // If this photo was already decrypted (by a previous visit to this
        // page, the lightbox, or the eager loading-screen preload), paint it
        // instantly - no spinner, no re-fetch, no re-decrypt.
        const docKey = (file.file || '').replace(/^\/docs\/|^docs\//, '').replace(/^\/photos\/|^photos\//, '');
        const cached = window._photoDecryptedCache && window._photoDecryptedCache.get(docKey);
        if (cached) {
            card.innerHTML = `<div class="photo-thumb"><img class="photo-img" src="${escHtml(cached.url)}" loading="lazy" data-blob-url="${escHtml(cached.url)}"></div>`;
        } else {
            card.innerHTML = '<div class="photo-thumb"><div class="photo-loading"></div></div>';
            // Decrypt and render thumbnail on the fly (throttled + cached)
            renderPhotoThumb(card.querySelector('.photo-thumb'), file, index);
        }

        grid.appendChild(card);
    });

    // Store photos for lightbox
    window._galleryPhotos = photos;
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

async function renderPhotoThumb(container, file, index) {
    try {
        const result = typeof decryptPhotoShared === 'function'
            ? await decryptPhotoShared(file)
            : null;
        if (!result) {
            const docKey = (file.file || '').replace(/^\/docs\/|^docs\//, '').replace(/^\/photos\/|^photos\//, '');
            const reason = (window._photoDecryptErrors && window._photoDecryptErrors.get(docKey)) || 'Unknown error';
            container.innerHTML = '<div title="'+escHtml(reason)+'" style="display:flex;align-items:center;justify-content:center;height:100%;color:#94a3b8;font-size:12px;"><i data-lucide="triangle-alert" style="width:16px;height:16px;"></i></div>';
            if (window.lucide) lucide.createIcons({ node: container });
            return;
        }
        container.innerHTML = '';
        const img = document.createElement('img');
        img.className = 'photo-img';
        img.src = result.url;
        img.loading = 'lazy';
        img.dataset.blobUrl = result.url;
        container.appendChild(img);
    } catch (e) {
        container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#94a3b8;font-size:12px;"><i data-lucide="triangle-alert" style="width:16px;height:16px;"></i></div>';
        if (window.lucide) lucide.createIcons({ node: container });
    }
}

function getImageMime(file) {
    const name = (file.name || '').toLowerCase();
    if (name.endsWith('.png')) return 'image/png';
    if (name.endsWith('.gif')) return 'image/gif';
    if (name.endsWith('.webp')) return 'image/webp';
    if (name.endsWith('.bmp')) return 'image/bmp';
    return 'image/jpeg';
}

async function decryptBuffer(buffer) {
    try {
        // If masterPassword isn't set yet, wait for the trusted session restore
        if (!window.masterPassword && window._trustSessionReady) {
            await window._trustSessionReady;
        }
        const settingsLength = new Uint32Array(buffer.slice(0, 4))[0];
        if (settingsLength === 0 || settingsLength > buffer.byteLength - 32) return null;
        const settingsBytes = buffer.slice(4, 4 + settingsLength);
        const settings = JSON.parse(new TextDecoder().decode(settingsBytes));

        const salt = buffer.slice(4 + settingsLength, 4 + settingsLength + 16);
        const iv = buffer.slice(4 + settingsLength + 16, 4 + settingsLength + 16 + 12);
        const encryptedData = buffer.slice(4 + settingsLength + 16 + 12);

        const passwordHash = await sha256Bytes(window.masterPassword);
        const keyMaterial = await crypto.subtle.importKey('raw', passwordHash, 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: new Uint8Array(salt),
            iterations: settings.iterations,
            hash: settings.hash
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);

        return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, encryptedData);
    } catch (e) {
        return null;
    }
}

function sha256Bytes(str) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(h => new Uint8Array(h));
}

function renderProfile(memberKey) {
   memberKey = memberKey || "shineil";

    const profile =
    (typeof profiles !== 'undefined'
        ? profiles[memberKey]
        : null);
    if (!profile) {
  const card = document.getElementById('profile-card');
  if (card) card.innerHTML = `<div style="padding:30px;text-align:center;color:#64748b;">
    <div style="margin-bottom:12px;"><i data-lucide="user" style="width:48px;height:48px;color:var(--muted);"></i></div>
    <div style="font-weight:700;font-size:16px;">No profile data for "${escHtml(memberKey)}"</div>
    <div style="font-size:13px;margin-top:8px;">Add this member to the profiles object in vault-data.js</div>
  </div>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();
  return;
}

    const card = document.getElementById("profile-card");
    if (!card) return;

    card.innerHTML = `
    <div style="background:white;border:1px solid var(--border);border-radius:24px;padding:35px;color:#0f172a;">
      <div style="display:flex;gap:25px;flex-wrap:wrap;margin-bottom:30px;">
        <img src="${escHtml(profile.image)}" style="width:150px;height:150px;border-radius:24px;object-fit:cover;" onerror="this.style.display='none'">
        <div>
          <h1 style="color:var(--accent);margin:0 0 8px;">${escHtml(profile.name)}</h1>
          <div style="color:#64748b;">${escHtml(profile.role)}</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;">
        <div class="profile-box"><h3>Personal Details</h3>${profile.personal || '-'}</div>
        <div class="profile-box"><h3>Contact</h3>${profile.contact || '-'}</div>
        <div class="profile-box"><h3>Education</h3>${profile.education || '-'}</div>
        <div class="profile-box"><h3>Skills</h3>${profile.skills || '-'}</div>
        <div class="profile-box"><h3>Languages</h3>${profile.languages || '-'}</div>
        <div class="profile-box"><h3>Achievements</h3>${profile.achievements || '-'}</div>
        <div class="profile-box"><h3>Experience</h3>${profile.experience || '-'}</div>
        <div class="profile-box"><h3>Projects</h3>${profile.projects || '-'}</div>
        <div class="profile-box"><h3>Future Goals</h3>${profile.goals || '-'}</div>
        <div class="profile-box"><h3>Faith / Ministry</h3>${profile.faith || '-'}</div>
      </div>
      <div style="margin-top:25px;background:#eff6ff;padding:24px;border-radius:18px;"><h3>About Me</h3>${profile.about || '-'}</div>
      <div style="margin-top:25px;background:#f8fafc;padding:24px;border-radius:18px;"><h3>Hobbies &amp; Interests</h3>${profile.hobbies || '-'}</div>
    </div>`;
}
async function unifiedSearch(){

    const query =
    document.getElementById(
        'unified-search'
    ).value.toLowerCase().trim();

    if(!query){

        if(currentCategory &&
        allFilesData[currentCategory]){

            renderFiles(
                allFilesData[currentCategory],
                currentCategory
            );
        }

        return;
    }

    // Determine if query looks like a file type search: ".pdf", "pdf", "jpg", etc.
    const typeQuery = query.replace(/^\.+/, '');

    let results = [];

    Object.keys(allFilesData)
    .forEach(category=>{

        const files =
        allFilesData[category];

        if(!Array.isArray(files)) return;

        files.forEach(file=>{

            // Search by name, category, or file extension
            const name   = (file.name   || '').toLowerCase();
            const cat    = (category    || '').toLowerCase();
            const ext    = ((file.file  || file.name || '').split('.').pop() || '').toLowerCase();
            const source = [];

            if (name.includes(query))  source.push('Filename');
            if (cat.includes(query))   source.push('Category');
            if (ext.includes(typeQuery) && ext !== typeQuery) source.push('Type');

            if (source.length === 0) return;

            results.push({
                ...file,
                category,
                source: source.join(', ')
            });

        });

    });

    renderSearchResults(results);

}

   function renderSearchResults(results){

    document.getElementById(
        'cat-title'
    ).textContent =
    `Search Results (${results.length})`;

    const grid =
    document.getElementById(
        'file-grid'
    );

    grid.innerHTML = "";

    if(results.length === 0){

        grid.innerHTML = `
        <div style="
        grid-column:1/-1;
        text-align:center;
        padding:40px;
        background:white;
        border-radius:20px;">
            No matching files found.
        </div>
        `;

        return;
    }

    results.forEach(file=>{
        const isList = document.getElementById('file-grid')?.classList.contains('drive-list');
        if(isList){
          const card = document.createElement('div');
          card.className = 'drive-list-row';
          card.innerHTML = `<div class="drive-list-name"><span class="li-icon"><i data-lucide="file-text" style="width:14px;height:14px;"></i></span><span>${escHtml(file.name)}</span></div><div class="drive-list-col hide-m">${escHtml(file.category)}</div><div class="drive-list-col hide-m">${escHtml(file.source)}</div><button class="drive-more-btn" onclick="event.stopPropagation(); openDriveMenu(this, ${JSON.stringify(file).replace(/"/g,'&quot;')})" style="opacity:1;"><i data-lucide="more-vertical" style="width:16px;height:16px;"></i></button>`;
          card.onclick = ()=> openSecureFile((file.category === 'PHOTOS' ? "photos/" : "docs/") + file.file, file.name);
          grid.appendChild(card);
          return;
        }
        const card =
        document.createElement('div');

        card.className =
        'file-card drive-card';

        card.innerHTML = `
        <div class="drive-card-thumb" style="height:120px;"><i data-lucide="file-text" style="width:42px;height:42px;color:#1967d2;"></i><div class="thumb-gradient"></div></div>
        <div class="drive-card-foot"><div class="doc-type-icon"><i data-lucide="file-text" style="width:14px;height:14px;"></i></div><div style="flex:1;min-width:0;"><div class="drive-card-name">${escHtml(file.name)}</div><div class="drive-card-meta">${escHtml(file.category)} - ${escHtml(file.source)}</div></div><button class="drive-more-btn" onclick="event.stopPropagation(); openDriveMenu(this, ${JSON.stringify(file).replace(/"/g,'&quot;')})"><i data-lucide="more-vertical" style="width:16px;height:16px;"></i></button></div>
        <div style="display:none;">

        <div style="
        font-weight:800;
        line-height:1.5;">
            ${escHtml(file.name)}
        </div>

        <div style="
        margin-top:10px;
        color:var(--muted);
        font-size:.85rem;">
            ${escHtml(file.category)}
        </div>

        <div style="
        margin-top:6px;
        color:#2563eb;
        font-size:.75rem;
        font-weight:700;">
            ${escHtml(file.source)}
        </div>

        `;

        card.onclick = ()=>{
    openSecureFile(
        (file.category === 'PHOTOS' ? "photos/" : "docs/") + file.file,
        file.name
    );
};

        grid.appendChild(card);

    });

    if (typeof lucide !== 'undefined') lucide.createIcons();
}

// -- Mode -> allowed member keys (mirrors backend MODE_MEMBERS in worker.js) --
// Frontend member keys map to backend member ids as: shineil, brother, father, mother
const VAULT_MODE_ALLOWED_MEMBERS = {
    ADMIN:           ["shineil", "brother", "father", "mother"],
    OFFICIAL:        ["shineil", "brother", "father", "mother"],
    PARENTS:         ["father", "mother"],
    SHINEIL_PARENTS: ["shineil", "father", "mother"],
    KEVIN_PARENTS:   ["brother", "father", "mother"],
    KEVIN:           ["brother"],
    SHINEIL:         ["shineil"]
};

function getCurrentVaultMode() {
    return window.VAULT_MODE || sessionStorage.getItem("vaultMode") || "ADMIN";
}

function isMemberAllowedForCurrentMode(memberKey) {
    const mode = getCurrentVaultMode();
    const allowed = VAULT_MODE_ALLOWED_MEMBERS[mode] || [];
    return allowed.includes(memberKey);
}

// Called by the HOME page's "Family Members" shortcuts. Unlike the old
// inline onclick handlers, this checks authorization before opening any
// profile - closes the leak where a non-admin user could view another
// member's profile by clicking a HOME shortcut even with the dropdown hidden.
function openMemberProfileGuarded(memberKey) {
    const _guardMode = getCurrentVaultMode();
    if (_guardMode === 'OFFICIAL') return; // no-op in official mode (profile hidden)
    if (!isMemberAllowedForCurrentMode(memberKey)) {
        console.warn('[Vault] Blocked profile access for unauthorized member:', memberKey);
        return;
    }
    const sel = document.getElementById('member-select');
    if (sel) {
        sel.value = memberKey;
    }
    switchPage('files');
}

document.addEventListener("DOMContentLoaded", () => {
    const memberSelect = document.getElementById("member-select");
    if (!memberSelect) return;

    function getProfileMember() {

    if (typeof getCurrentVaultMember === 'function') {
        return getCurrentVaultMember() || 'shineil';
    }

    const mode =
        window.VAULT_MODE ||
        sessionStorage.getItem("vaultMode") ||
        "ADMIN";

    const modeMap = {
        SHINEIL: "shineil",
        KEVIN: "brother",
        PARENTS: "father",
        SHINEIL_PARENTS: "shineil",
        KEVIN_PARENTS: "brother",
        OFFICIAL: "shineil"
    };

    const sel = document.getElementById('member-select');

    if (sel && sel.value && sel.value.trim() && sel.value !== 'all') {
        return sel.value;
    }

    return modeMap[mode] || "shineil";
}

   renderProfile(getProfileMember());
}); // <-- THIS MUST EXIST

/* =========================
   DOCUMENT CHECKLIST (modern table)
   ========================= */
// Checklist is rendered as a modern card table in the vault (see index.html).
// Edit checklist.html standalone editor to add/modify checklist types and documents.
// Click DEPLOY in checklist.html to push data to localStorage for the vault to read.
// Both the vault and standalone page share the same localStorage key for statuses.
