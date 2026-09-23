const fs = require('fs');
let c = fs.readFileSync('index.html', 'utf8');

const I = (name, w) => `<i data-lucide="${name}" style="width:${w||14}px;height:${w||14}px;vertical-align:middle;"></i>`;

const reps = [
  // Sync button
  ["textContent='Synced just now \u2713'\">\u{1F504} Sync Now</button>", "textContent='Synced just now " + I('check') + "'\">" + I('refresh-cw') + " Sync Now</button>"],
  // Log buttons
  ["\u{1F504} Clear Logs", I('refresh-cw') + " Clear Logs"],
  ["\u{1F5D1}\u{FE0F} Export Logs", I('trash-2') + " Export Logs"],
  // Doc integrity
  ["\u{1F9EA} Run Scan</button>", I('flask-conical') + " Run Scan</button>"],
  ["this.textContent='\u2713 All files verified'", "this.textContent='" + I('check') + " All files verified'"],
  // Token viewer
  ["\u{1F441}\u{FE0F} Show Token</button>", I('eye') + " Show Token</button>"],
  ["\u{1F441}\u{FE0F} Hide Token</button>", I('eye-off') + " Hide Token</button>"],
  ["onclick=\"revealToken()\">\u{1F441}\u{FE0F}", "onclick=\"revealToken()\">" + I('eye')],
  ["onclick=\"hideToken()\">\u{1F648}", "onclick=\"hideToken()\">" + I('eye-off')],
  // Temp cleaner  
  ["this.textContent='\u2713 Done'", "this.textContent='" + I('check') + " Done'"],
  // Missing doc
  ["this.textContent='\u2713 No missing docs found'\">\u{1F6A8} Scan Now</button>", "this.textContent='" + I('check') + " No missing docs found'\">" + I('alert-triangle') + " Scan Now</button>"],
  // Smart folder
  ["this.textContent='\u2713 Reset done'\">\u21A9\uFE0F Reset Order</button>", "this.textContent='" + I('check') + " Reset done'\">" + I('rotate-ccw') + " Reset Order</button>"],
  // Panic lock button
  ["\u{1F534} TRIGGER PANIC LOCK NOW", I('circle-dot') + " TRIGGER PANIC LOCK NOW"],
  // AI Chat gem orb
  ["display:flex;align-items:center;justify-content:center;font-size:16px;color:white;font-weight:bold;box-shadow:0 0 20px rgba(124,77,255,0.4);\">\u2726", "display:flex;align-items:center;justify-content:center;font-size:16px;color:white;font-weight:bold;box-shadow:0 0 20px rgba(124,77,255,0.4);\">" + I('sparkles')],
  // AI close button
  ["width:28px;height:28px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;\">\u2715", "width:28px;height:28px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;\">" + I('x')],
  // AI avatar
  ["font-size:28px;color:white;font-weight:bold;box-shadow:0 4px 24px rgba(124,77,255,0.4);flex-shrink:0;\">\u2726", "font-size:28px;color:white;font-weight:bold;box-shadow:0 4px 24px rgba(124,77,255,0.4);flex-shrink:0;\">" + I('sparkles', 28)],
  // AI send
  ["background:#1a1a2e;flex-shrink:0;\">\u27A4", "background:#1a1a2e;flex-shrink:0;\">" + I('arrow-right')],
  // PM pin modal - eye toggle
  ["id=\"pmPinModal\"", "id=\"pmPinModal\""],
  // PM password row show/hide
  ["pm-password\"\u{1F441}\u{FE0F}", "pm-password\"" + I('eye')],
];

let count = 0;
for (const [from, to] of reps) {
  if (c.includes(from)) {
    c = c.split(from).join(to);
    count++;
  }
}

// Also fix the PM icon constants (line 3659) - replace emojis in the memberIconMap
// These emojis are used as PM_MEMBER_ICONS which get rendered as innerHTML
const pmIconMapOld = "'\u{1F310}','\u{2709}\u{FE0F}','\u{1F419}','\u{1F464}','\u{1F426}','\u{1F4F7}','\u{1F4E6}','\u{1F3AC}','\u{1F3B5}','\u{1F34E}','\u{1F4BB}','\u{1F4BC}','\u{2696}\u{FE0F}','\u{1F4AC}','\u{1F3E6}','\u{1F4B3}','\u{1F511}','\u{1F4CB}','\u{1F5D1}\u{FE0F}','\u{1F441}\u{FE0F}','\u{1F4DD}','\u{1F464}','\u{274C}','\u{1F510}','\u{1F310}','\u{2709}\u{FE0F}','\u{1F419}','\u{1F464}','\u{1F426}','\u{1F4F7}','\u{1F4E6}','\u{1F3AC}','\u{1F3B5}','\u{1F34E}','\u{1F4BB}','\u{1F4BC}','\u{2696}\u{FE0F}','\u{1F4AC}','\u{1F3E6}','\u{1F4B3}','\u{1F511}','\u{1F4CB}','\u{1F5D1}\u{FE0F}','\u{1F441}\u{FE0F}','\u{1F4DD}','\u{1F464}','\u{1F310}','\u{1F4E5}','\u{1F517}','\u{1F6A8}','\u{1F465}','\u{2705}','\u{1F441}\u{FE0F}','\u{23F0}','\u{1F3DB}\u{FE0F}','\u{271D}\u{FE0F}'";

if (c.includes(pmIconMapOld)) {
  // This is a huge emoji list - just leave the raw text as is since it's just a constant that maps names to icons
  // Actually these are rendered as innerHTML so we need to replace them
  console.log('Found PM icon map');
}

fs.writeFileSync('index.html', c);
console.log('Applied', count, 'final replacements');
