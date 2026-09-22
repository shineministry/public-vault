// Public Vault — Plans & Pricing (Free 10GB is Cloudflare R2 free tier limit)
const VAULT_PLANS = {
  free:     { id:'free',     name:'Free',     storageGB:10,  price:{EUR:0, USD:0, INR:0},   trialDays:0,  cta:'Start Free — 10GB' },
  normal:   { id:'normal',   name:'Normal',   storageGB:50,  price:{EUR:3, USD:3, INR:299}, cta:'Normal — 50GB' },
  pro:      { id:'pro',      name:'Pro',      storageGB:100, price:{EUR:6, USD:6, INR:599}, cta:'Pro — 100GB' },
  family:   { id:'family',   name:'Family',   storageGB:500, price:{EUR:8, USD:8, INR:799}, cta:'Family — 500GB' },
  business: { id:'business', name:'Business', storageGB:1024,price:{EUR:10,USD:10,INR:999}, cta:'Business — 1TB' }
};

// Detect currency by locale/timezone fallback
function detectCurrency(){
  try{
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone||'';
    if(tz.includes('Kolkata')||tz.includes('Calcutta')) return 'INR';
    const lang = navigator.language||'en-US';
    if(lang==='en-IN'||lang==='hi-IN') return 'INR';
    if(lang.startsWith('en-GB')||lang.startsWith('de')||lang.startsWith('fr')||lang.startsWith('en-IE')) return 'EUR';
  }catch{}
  return 'EUR';
}
function formatPrice(plan, cur){
  const p = plan.price[cur] ?? plan.price.EUR;
  if(p===0) return 'Free';
  const sym = cur==='INR'?'₹':cur==='USD'?'$':'€';
  return `${sym}${p}/mo`;
}
let _selectedPlan='free';
let _selectedCurrency=detectCurrency();
function setPlan(id){ _selectedPlan=id; renderPricing(); }
function setCurrency(cur){ _selectedCurrency=cur; renderPricing(); }
function getSelectedPlan(){ return VAULT_PLANS[_selectedPlan]; }

function renderPricing(){
  const grid=document.getElementById('pricing-grid');
  if(!grid) return;
  grid.innerHTML = Object.values(VAULT_PLANS).map(p=>{
    const active = p.id===_selectedPlan;
    const price = formatPrice(p,_selectedCurrency);
    const isFree = p.id==='free';
    return `<div class="plan-card ${active?'active':''}" onclick="setPlan('${p.id}')" style="border:1px solid ${active?'#2563eb':'#e2e8f0'};border-radius:16px;padding:20px;background:${active?'#eff6ff':'#fff'};cursor:pointer;position:relative;">
      ${isFree?'<span style="position:absolute;top:12px;right:12px;background:#f59e0b;color:#fff;font-size:10px;font-weight:800;padding:4px 8px;border-radius:999px;">STRICT 10GB LIMIT</span>':''}
      <div style="font-weight:800;font-size:16px;color:#0f172a;">${p.name}</div>
      <div style="font-size:13px;color:#64748b;margin:6px 0;">${p.storageGB>=1024?'1TB':p.storageGB+'GB'} storage</div>
      <div style="font-weight:900;font-size:20px;color:${isFree?'#16a34a':'#2563eb'};">${price}</div>
      ${isFree?'<div style="margin-top:8px;font-size:11px;color:#dc2626;font-weight:700;"><i data-lucide="triangle-alert" style="width:11px;height:11px;"></i> Free only till 10GB — upgrade for more</div>':''}
      <div style="margin-top:12px;width:100%;text-align:center;padding:10px;border-radius:10px;background:${active?'#2563eb':'#f1f5f9'};color:${active?'#fff':'#0f172a'};font-weight:800;font-size:13px;">${active?'✓ Selected':'Select'}</div>
    </div>`;
  }).join('');
  if(window.lucide) lucide.createIcons({node:grid});
  // sync header
  const sel=VAULT_PLANS[_selectedPlan];
  const selEl=document.getElementById('selected-plan-label');
  if(selEl) selEl.textContent = `${sel.name} — ${sel.storageGB>=1024?'1TB':sel.storageGB+'GB'} — ${formatPrice(sel,_selectedCurrency)}`;
}

function enforceStorageGate(usedGB){
  const plan = getSelectedPlan() || VAULT_PLANS.free;
  const curPlan = JSON.parse(localStorage.getItem('vaultPlan')||'null') || plan;
  const limit = curPlan.storageGB;
  if(usedGB >= limit){
    showNotification('Storage Full', `You have used ${usedGB.toFixed(1)}GB / ${limit}GB (${curPlan.name}). Free is strictly 10GB. Upgrade to ${Object.values(VAULT_PLANS).filter(p=>p.storageGB>limit)[0]?.name||'higher'} to continue uploads.`, {type:'error'});
    return false;
  }
  if(usedGB/limit > 0.8){
    toastNotify(`Warning: ${usedGB.toFixed(1)}GB / ${limit}GB used — upgrade soon (Free strictly 10GB).`,`warning`);
  }
  return true;
}
