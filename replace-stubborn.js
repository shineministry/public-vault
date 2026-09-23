const fs = require('fs');
let c = fs.readFileSync('index.html', 'utf8');

const I = (name, w) => `<i data-lucide="${name}" style="width:${w||14}px;height:${w||14}px;vertical-align:middle;"></i>`;

// Remaining stubborn emojis  
const reps = [
  // AI Chat sparkles
  ['<div id="gem-orb" style="width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#4285f4,#9b5de5,#f72585);display:flex;align-items:center;justify-content:center;font-size:16px;color:white;font-weight:bold;box-shadow:0 0 20px rgba(124,77,255,0.4);">', '<div id="gem-orb" style="width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#4285f4,#9b5de5,#f72585);display:flex;align-items:center;justify-content:center;font-size:16px;color:white;font-weight:bold;box-shadow:0 0 20px rgba(124,77,255,0.4);">' + I('sparkles')],
  ['closeAIChat()" style="margin-left:auto;background:rgba(255,255,255,0.07);border:none;color:#aaa;font-size:16px;width:28px;height:28px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;">\u2715', 'closeAIChat()" style="margin-left:auto;background:rgba(255,255,255,0.07);border:none;color:#aaa;font-size:16px;width:28px;height:28px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;">' + I('x')],
  // AI avatar sparkle
  ['width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,#4285f4,#9b5de5,#f72585);display:flex;align-items:center;justify-content:center;font-size:28px;color:white;font-weight:bold;box-shadow:0 4px 24px rgba(124,77,255,0.4);flex-shrink:0;">\u2726', 'width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,#4285f4,#9b5de5,#f72585);display:flex;align-items:center;justify-content:center;font-size:28px;color:white;font-weight:bold;box-shadow:0 4px 24px rgba(124,77,255,0.4);flex-shrink:0;">' + I('sparkles', 28)],
  // AI send arrow
  ['border-top:1px solid #2a2a45;background:#1a1a2e;">\u27A4', 'border-top:1px solid #2a2a45;background:#1a1a2e;">' + I('arrow-right')],
  
  // PM password row icons
  ['>👁️</span>', '>' + I('eye') + '</span>'],
  ['>🔀</span>', '>' + I('shuffle') + '</span>'],
  
  // Content: '✓ ACTIVE'  
  ["content: '✓ ACTIVE'", "content: '" + I('check') + " ACTIVE'"],
  
  // Compare bar clear button ✕
  ['id="compare-bar-clear" onclick="clearCompare()">\u2715 Clear</button>', 'id="compare-bar-clear" onclick="clearCompare()">' + I('x') + ' Clear</button>'],

  // Some inline button textContent assignments with emojis in JS  
  ["this.textContent='\u2705 All files verified'", "this.textContent='" + I('check') + " All files verified'"],
  ["this.textContent='\u2705 No missing docs found'", "this.textContent='" + I('check') + " No missing docs found'"],
  ["this.textContent='\u2705 Reset done'", "this.textContent='" + I('check') + " Reset done'"],
  
  // Reveal/hide token button emojis
  ['onclick="revealToken()"', 'onclick="revealToken()"'],
  ['onclick="hideToken()"', 'onclick="hideToken()"'],
  ['>👁️ Reveal</button>', '>' + I('eye') + ' Reveal</button>'],
  ['>🙈 Hide</button>', '>' + I('eye-off') + ' Hide</button>'],

  // Status CSS pseudo-content checkmarks
  ["content: '\\u2713 ACTIVE'", "content: '" + I('check') + " ACTIVE'"],
];

let count = 0;
for (const [from, to] of reps) {
  if (c.includes(from)) {
    c = c.split(from).join(to);
    count++;
  }
}

fs.writeFileSync('index.html', c);
console.log('Applied', count, 'stubborn replacements');
