const fs = require('fs');
let c = fs.readFileSync('index.html', 'utf8');

const I = (name) => `<i data-lucide="${name}" style="width:16px;height:16px;vertical-align:middle;"></i>`;

const map = {
  '\u{1F4C4} Vault Name': I('tag') + ' Vault Name',
  '\u{1F4C4} Default Opening Page': I('home') + ' Default Opening Page',
  '\u{1F464} Default Selected Member': I('user') + ' Default Selected Member',
  '\u{1F501} Remember Last Member': I('repeat') + ' Remember Last Member',
  '\u{26A1} Quick Launch Category': I('zap') + ' Quick Launch Category',
  '\u{1F50D} Global Search Toggle': I('search') + ' Global Search Toggle',
  '\u{1F4C2} Recent Files on HOME': I('folder-open') + ' Recent Files on HOME',
  '\u{1F4CC} Pinned Documents': I('pin') + ' Pinned Documents',
  '\u{1F441}\u{FE0F} Document Preview Mode': I('eye') + ' Document Preview Mode',
  '\u{1F4DC} Auto Scroll Restore': I('scroll') + ' Auto Scroll Restore',
  '\u{1F4CB} Sidebar Behavior': I('clipboard-list') + ' Sidebar Behavior',
  '\u{2728} Animation Level': I('sparkles') + ' Animation Level',
  '\u{1F3A8} Theme Engine': I('palette') + ' Theme Engine',
  '\u{1F3AF} Accent Color': I('crosshair') + ' Accent Color',
  '\u{1F524} Font Size Control': I('type') + ' Font Size Control',
  '\u{1F680} Performance Mode': I('rocket') + ' Performance Mode',
  '\u{1F4BE} Cache Mode': I('hard-drive') + ' Cache Mode',
  '\u{1F504} Auto Sync Status': I('refresh-cw') + ' Auto Sync Status',
  '\u{1F6E0}\u{FE0F} Developer Mode': I('wrench') + ' Developer Mode',
  '\u{1F4CB} System Logs Viewer': I('scroll-text') + ' System Logs Viewer',
  '\u{2764}\u{FE0F} Vault Health Checker': I('heart-pulse') + ' Vault Health Checker',
  '\u{1F527} JSON Repair Tool': I('wrench') + ' JSON Repair Tool',
  '\u{1F510} Encryption Strength': I('lock') + ' Encryption Strength',
  '\u{1F9EA} Document Integrity': I('flask-conical') + ' Document Integrity',
  '\u{1F39F}\u{FE0F} Session Token Viewer': I('ticket') + ' Session Token Viewer',
  '\u{1F9F9} Auto Cache Cleaner': I('broom') + ' Auto Cache Cleaner',
  '\u{1F5D1}\u{FE0F} Temporary Files Cleaner': I('trash-2') + ' Temporary Files Cleaner',
  '\u{1F50E} Duplicate File Scanner': I('scan-search') + ' Duplicate File Scanner',
  '\u{1F6A8} Missing Document Detector': I('alert-triangle') + ' Missing Document Detector',
  '\u{1F6A8} Missing Doc Detector': I('alert-triangle') + ' Missing Doc Detector',
  '\u{1F4C1} Smart Folder Optimization': I('folder') + ' Smart Folder Optimization',
  '\u{2601}\u{FE0F} Background Sync Manager': I('cloud') + ' Background Sync Manager',
  '\u{1F4E1} Bandwidth Saver Mode': I('radio') + ' Bandwidth Saver Mode',
  '\u{1F4F4} Offline Vault Mode': I('wifi-off') + ' Offline Vault Mode',
  '\u{1F198} Emergency Recovery Mode': I('siren') + ' Emergency Recovery Mode',
  '\u{1F198} Emergency Recovery': I('siren') + ' Emergency Recovery',
  '\u{1F4E4} Export Vault Config': I('upload') + ' Export Vault Config',
  '\u{1F4E5} Import Vault Config': I('download') + ' Import Vault Config',
  '\u{1F9EC} Experimental Features Toggle': I('dna') + ' Experimental Features Toggle',
  '\u{1F977} Stealth Mode': I('eye-off') + ' Stealth Mode',
  '\u{1F534} Panic Lock Button': I('circle-dot') + ' Panic Lock Button',
  '\u{2705} Trusted Device': I('check-circle') + ' Trusted Device',
};

let count = 0;
for (const [emoji, replacement] of Object.entries(map)) {
  const re = new RegExp(emoji.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
  const before = c;
  c = c.replace(re, replacement);
  if (c !== before) count++;
}

fs.writeFileSync('index.html', c);
console.log('Replaced', count, 'panel titles');
