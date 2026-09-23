const fs = require('fs');
let c = fs.readFileSync('index.html', 'utf8');

const I = (name, w) => `<i data-lucide="${name}" style="width:${w||14}px;height:${w||14}px;vertical-align:middle;"></i>`;

// All remaining replacements
const reps = [
  // Compare bar
  ['📂 Select 2 documents to compare', I('folder-open') + ' Select 2 documents to compare'],
  
  // Lightbox close
  ['class="lightbox-close" onclick="closePhotoViewer()">\u2715</button>', 'class="lightbox-close" onclick="closePhotoViewer()">' + I('x') + '</button>'],
  
  // Remaining adv panel titles
  ['adv-panel-title">\u{1F4C4} Vault Name', 'adv-panel-title">' + I('tag') + ' Vault Name'],
  ['adv-panel-title">\u{1F4C4} Default Opening Page', 'adv-panel-title">' + I('home') + ' Default Opening Page'],
  
  // Logo emoji default
  ['value="\u{1F510}" style', 'value="' + I('lock') + '" style'],
  
  // Upload button
  ['adv-btn-purple" onclick="document.getElementById(\'logoUploadInput\').click()">\u{1F4C1} Upl', 'adv-btn-purple" onclick="document.getElementById(\'logoUploadInput\').click()">' + I('upload') + ' Upl'],
  
  // Theme select options
  ['>☀️ Light</option>', '>' + I('sun') + ' Light</option>'],
  ['>🌙 Dark</option>', '>' + I('moon') + ' Dark</option>'],
  ['>🖥️ System Auto</option>', '>' + I('monitor') + ' System Auto</option>'],
  ['>🌑 Midnight Blue</option>', '>' + I('moon-star') + ' Midnight Blue</option>'],
  
  // Hint text
  ['⚡ badge', I('zap') + ' badge'],
  
  // Sync button
  ['lastSyncTime\').textContent=\'Synced\'', 'lastSyncTime\').textContent=\'Synced\''],
  
  // Log clear/delete buttons  
  ['getEl', 'getEl'],
  
  // Health check button
  ['>🏥 Run Check</button>', '>' + I('activity') + ' Run Check</button>'],
  
  // Status text
  ['>✓ Active</span>', '>' + I('check') + ' Active</span>'],
  
  // JSON repair
  ['>🔍 Validate</button>', '>' + I('search') + ' Validate</button>'],
  
  // Encryption status
  ['>✓ Secure</span>', '>' + I('check') + ' Secure</span>'],
  
  // Doc integrity button
  ['this.textContent=\'✓ All files verified\')">🧪 Run Scan</butt', 'this.textContent=\'' + I('check') + ' All files verified\')">' + I('flask-conical') + ' Run Scan</butt'],
  
  // Token viewer buttons
  ['revealToken()"', 'revealToken()"'],
  ['hideToken()"', 'hideToken()"'],
  
  // Cache cleaner button
  ['this.textContent=\'✓ Cache cleared\';sessionStorage.clear();">🧹', 'this.textContent=\'' + I('check') + ' Cache cleared\';sessionStorage.clear();">' + I('broom')],
  
  // Temp cleaner button
  ['this.textContent=\'✓ Done\';if(window.currentBlobUrl){URL.rev', 'this.textContent=\'' + I('check') + ' Done\';if(window.currentBlobUrl){URL.rev'],
  
  // Dupe scan button
  ['>🔎 Scan Now</button>', '>' + I('scan-search') + ' Scan Now</button>'],
  ['No duplicates found ✓', 'No duplicates found ' + I('check')],
  
  // Missing doc button
  ['this.textContent=\'✓ No missing docs found\')">🚨 Scan Now</butt', 'this.textContent=\'' + I('check') + ' No missing docs found\')">' + I('alert-triangle') + ' Scan Now</butt'],
  
  // Smart folder reset button
  ['this.textContent=\'✓ Reset done\')">↩️ Reset Order</button>', 'this.textContent=\'' + I('check') + ' Reset done\')">' + I('rotate-ccw') + ' Reset Order</button>'],
  
  // Emergency hints
  ['>⚠️ Disables all security', '>' + I('alert-triangle') + ' Disables all security'],
  ['>⚠️ May cause unexpected', '>' + I('alert-triangle') + ' May cause unexpected'],
  
  // Export/Import buttons
  ['>📤 Export</button>', '>' + I('upload') + ' Export</button>'],
  ['>📥 Ch', '>' + I('download') + ' Ch'],
  
  // Panic lock
  ['🔴 LOCK button', I('circle-dot') + ' LOCK button'],
  ['>🔴 TRIGGER PANIC LOCK NOW</div>', '>' + I('circle-dot') + ' TRIGGER PANIC LOCK NOW</div>'],
  ['>🔴</span> <span', '>' + I('circle-dot') + '</span> <span'],
  
  // About panel
  ['> ℹ️ About Fortress', '> ' + I('info') + ' About Fortress'],
  
  // AI Chat
  ['<div id="gem-orb" style="width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#4285f4,#9b5de5,#f72', '<div id="gem-orb" style="width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#4285f4,#9b5de5,#f72'],
  ['closeAIChat()" style="margin-left:auto;background:rgba(255,255,255,0.07);border:none;color:#aaa;', 'closeAIChat()" style="margin-left:auto;background:rgba(255,255,255,0.07);border:none;color:#aaa;'],
  
  // Password manager modals
  ['"font-size:20px;">👥</span> <strong>WHOSE PASSWORDS?</strong>', '"font-size:20px;">' + I('users', 20) + '</span> <strong>WHOSE PASSWORDS?</strong>'],
  ['"font-size:20px;">🔒</span> <strong id="pm-pin-modal-title">', '"font-size:20px;">' + I('lock', 20) + '</span> <strong id="pm-pin-modal-title">'],
  ['>✔ CONFIRM</button>', '>' + I('check') + ' CONFIRM</button>'],
  ['"font-size:20px;">🔑</span> <strong>PASSWORD MANAGER</strong>', '"font-size:20px;">' + I('key', 20) + '</span> <strong>PASSWORD MANAGER</strong>'],
  ['>➕ Add New Password</h4>', '>' + I('plus-circle') + ' Add New Password</h4>'],
  ['>💾 SAVE PASSWORD</button>', '>' + I('save') + ' SAVE PASSWORD</button>'],
  ['"pm-search-icon">🔍</span>', '"pm-search-icon">' + I('search') + '</span>'],
  
  // Vault modes
  ['"font-size:20px;">⚡</span> <strong>VAULT ACCESS MODES</strong>', '"font-size:20px;">' + I('zap', 20) + '</span> <strong>VAULT ACCESS MODES</strong>'],
  ['"font-size:24px;">🌐</span>', '"font-size:24px;">' + I('globe', 24) + '</span>'],
  
  // PM member picker
  ['">👤 ${PM_MEMBER_LABELS', '">' + I('user') + ' ${PM_MEMBER_LABELS'],
  
  // Error messages
  ['⚠️ Secure context required', I('alert-triangle') + ' Secure context required'],
  ['⚠️ Something went wrong', I('alert-triangle') + ' Something went wrong'],
  
  // Loading text
  ['btn.textContent = \'⏳ Loading...\'', 'btn.textContent = \'' + I('loader') + ' Loading...\''],
  ['closeBtn.textContent = \'✕ Dismiss\'', 'closeBtn.textContent = \'' + I('x') + ' Dismiss\''],
  
  // VAULT TIPS
  ['Use the Compare tool (⚖️) to view', 'Use the Compare tool (' + I('scale') + ') to view'],
  
  // Loading spinner icon list
  ["const icons = ['📄','📋','🗂️','📑','📃']", "const icons = ['" + I('file-text') + "','" + I('clipboard') + "','" + I('folder-open') + "','" + I('file') + "','" + I('file') + "']"],
  
  // Status check component icons (lines 4165-4193)
  ["icon:'🔐'", "icon:'" + I('lock') + "'"],
  ["icon:'📡'", "icon:'" + I('radio') + "'"],
  ["icon:'🤖'", "icon:'" + I('bot') + "'"],
  ["icon:'⏱️'", "icon:'" + I('timer') + "'"],
  ["icon:'🔑'", "icon:'" + I('key') + "'"],
  ["icon:'💾'", "icon:'" + I('hard-drive') + "'"],
  ["icon:'⭐'", "icon:'" + I('star') + "'"],
  ["icon:'⚖️'", "icon:'" + I('scale') + "'"],
  ["icon:'📋'", "icon:'" + I('clipboard-list') + "'"],
  ["icon:'🆘'", "icon:'" + I('siren') + "'"],
  ["icon:'💬'", "icon:'" + I('message-circle') + "'"],
  ["icon:'🔄'", "icon:'" + I('refresh-cw') + "'"],
  ["icon:'📄'", "icon:'" + I('file-text') + "'"],
  ["icon:'🚪'", "icon:'" + I('log-out') + "'"],
  ["icon:'⚡'", "icon:'" + I('zap') + "'"],
  ["icon:'🔗'", "icon:'" + I('link') + "'"],
  ["icon:'🔒'", "icon:'" + I('lock') + "'"],
  ["icon:'🛡️'", "icon:'" + I('shield') + "'"],
  ["icon:'🔔'", "icon:'" + I('bell') + "'"],
  ["icon:'📅'", "icon:'" + I('calendar') + "'"],
  ["icon:'📕'", "icon:'" + I('book-open') + "'"],
  ["icon:'🚀'", "icon:'" + I('rocket') + "'"],
  ["icon:'📴'", "icon:'" + I('wifi-off') + "'"],
  ["icon:'🎨'", "icon:'" + I('palette') + "'"],
  ["icon:'👁️'", "icon:'" + I('eye') + "'"],
  ["icon:'🔓'", "icon:'" + I('unlock') + "'"],
  ["icon:'📱'", "icon:'" + I('smartphone') + "'"],
  ["icon:'🧩'", "icon:'" + I('puzzle') + "'"],
  
  // Status badge emojis (lines 4370, 4414-4418, 4432-4433)
  ["operational:'🟢'", "operational:'" + I('circle-check') + "'"],
  ["degraded:'🟡'", "degraded:'" + I('alert-circle') + "'"],
  ["partial:'🟠'", "partial:'" + I('alert-triangle') + "'"],
  ["major:'🔴'", "major:'" + I('x-circle') + "'"],
  ["maintenance:'🔵'", "maintenance:'" + I('wrench') + "'"],
  ["|| '⚪'", "|| '" + I('circle') + "'"],
  ["e:'🟢'", "e:'" + I('circle-check') + "'"],
  ["e:'🟡'", "e:'" + I('alert-circle') + "'"],
  ["e:'🟠'", "e:'" + I('alert-triangle') + "'"],
  ["e:'🔴'", "e:'" + I('x-circle') + "'"],
  ["e:'🔵'", "e:'" + I('wrench') + "'"],
  
  // Location pin
  ["📍", I('map-pin')],
  
  // Loading spinner
  ["⏳ Checking all systems", I('loader') + " Checking all systems"],
  
  // Sidebar member fallback
  ["(trust.member || '👤')", "(trust.member || 'User')"],
  ["'🔓 Trusted Device", "' " + I('lock') + " Trusted Device"],
  
  // Login/logout button states
  ["btn.textContent = '⏳';", "btn.textContent = '" + I('loader') + "';"],
  ["btn.textContent = '🔄';", "btn.textContent = '" + I('refresh-cw') + "';"],
  
  // Error page emoji
  ['"font-size:48px;margin-bottom:10px;">⚠️</div>', '"font-size:48px;margin-bottom:10px;">' + I('alert-triangle', 48) + '</div>'],
];

let count = 0;
for (const [from, to] of reps) {
  if (c.includes(from)) {
    c = c.split(from).join(to);
    count++;
  }
}

fs.writeFileSync('index.html', c);
console.log('Applied', count, 'replacements');
