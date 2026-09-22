// Public Vault — Self-registration + Terms + Payment gating
// Free = 10GB (R2 free tier). Paid tiers require successful payment before vault access.

async function handleRegister(){
  const nameEl=document.getElementById('reg-name');
  const emailEl=document.getElementById('reg-email');
  const passEl=document.getElementById('reg-pass');
  const termsEl=document.getElementById('reg-terms');
  const plan = (typeof getSelectedPlan==='function'?getSelectedPlan():null) || VAULT_PLANS.free;
  const currency = (typeof _selectedCurrency!=='undefined'?_selectedCurrency:'EUR');

  if(!nameEl.value.trim()||!emailEl.value.trim()||!passEl.value.trim()){
    toastNotify('Fill name, email and password.','warning'); return;
  }
  if(!termsEl.checked){
    toastNotify('You must tick Terms & Conditions to continue.','warning'); return;
  }
  if(passEl.value.length<8){ toastNotify('Password must be at least 8 characters.','warning'); return; }

  const btn=document.getElementById('reg-btn');
  if(btn){ btn.disabled=true; btn.textContent='Creating account...'; }

  try{
    const backend = (window.PUBLIC_WORKER_URL || 'https://__PUBLIC_WORKER_URL__').replace(/\/$/,'');
    // 1) Register
    const res = await fetch(`${backend}/public/register`,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name:nameEl.value.trim(), email:emailEl.value.trim().toLowerCase(), password:passEl.value, plan:plan.id, currency })
    });
    const data = await res.json().catch(()=>({}));
    if(!res.ok || !data.success){
      throw new Error(data.error||`Registration failed (${res.status})`);
    }
    // Persist plan locally for gate
    localStorage.setItem('vaultPlan', JSON.stringify(plan));
    localStorage.setItem('vaultCurrency', currency);
    localStorage.setItem('vaultEmail', emailEl.value.trim().toLowerCase());

    // 2) Free plan → direct login
    if(plan.id==='free'){
      toastNotify('Free account created — strictly 10GB limit.','success');
      if(data.sessionToken){
        sessionStorage.setItem('vaultSession', data.sessionToken);
        sessionStorage.setItem('vaultSessionToken', data.sessionToken);
      }
      showNotification('Welcome — Free 10GB', 'Your Free vault is strictly 10GB (R2 free tier). Cross it and uploads are blocked until you upgrade to Normal/Pro/Family/Business (€3–10/mo).', {type:'info'});
      setTimeout(()=>location.reload(), 900);
      return;
    }

    // 3) Paid plan → require payment before any vault use
    toastNotify(`${plan.name} requires payment — redirecting to checkout...`,'info');
    const chk = await fetch(`${backend}/public/create-checkout`,{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ email:emailEl.value.trim().toLowerCase(), plan:plan.id, currency })
    });
    const chkData = await chk.json().catch(()=>({}));
    if(chk.ok && chkData.url){
      window.location.href = chkData.url; // Stripe Checkout
    } else {
      throw new Error(chkData.error||'Could not create checkout session. Configure Stripe in Worker.');
    }
  }catch(e){
    console.error(e);
    showNotification('Registration failed', e.message, {type:'error'});
    if(btn){ btn.disabled=false; btn.textContent='Create Account & Continue'; }
  }
}

function openRegister(){
  const m=document.getElementById('register-modal');
  if(m){ m.style.display='flex'; renderPricing(); if(window.lucide) lucide.createIcons({node:m}); }
}
function closeRegister(){ const m=document.getElementById('register-modal'); if(m) m.style.display='none'; }

// ── DEMO mode — admin only, hidden. Not shown to users. ──────────────
// Trigger: triple-click the lock icon + URL ?demo=1 or localStorage admin flag
async function enterDemoMode(){
  const secret = prompt('Admin demo secret:');
  if(!secret) return;
  try{
    const backend=(window.PUBLIC_WORKER_URL||'https://__PUBLIC_WORKER_URL__').replace(/\/$/,'');
    const r=await fetch(`${backend}/public/demo-login`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok||!j.success) throw new Error(j.error||'Demo login failed');
    sessionStorage.setItem('vaultSession', j.sessionToken);
    sessionStorage.setItem('vaultSessionToken', j.sessionToken);
    sessionStorage.setItem('vaultMode','DEMO');
    localStorage.setItem('vaultDemo','1');
    sessionStorage.setItem('vaultDemo','1');
    showNotification('Demo Mode — Admin Only','Demo active: unlimited storage, no payment gate, hidden from users.',{type:'success'});
    setTimeout(()=>location.reload(),700);
  }catch(e){ showNotification('Demo failed', e.message,{type:'error'}); }
}
function exitDemoMode(){
  localStorage.removeItem('vaultDemo'); sessionStorage.removeItem('vaultDemo'); sessionStorage.removeItem('vaultMode');
  // keep session but reload will enforce normal plan gate
  location.reload();
}
// Show demo badge when active
function renderDemoBadge(){
  if(!isDemoMode()) return;
  const h=document.getElementById('landHeader');
  if(h && !document.getElementById('demo-badge')){
    const b=document.createElement('div');
    b.id='demo-badge'; b.style.cssText='background:#0f172a;color:#f59e0b;padding:6px 12px;border-radius:999px;font-size:11px;font-weight:800;display:flex;align-items:center;gap:6px;margin-left:12px;cursor:pointer;';
    b.innerHTML='DEMO — Admin Only <span onclick="exitDemoMode()" style="background:#f59e0b;color:#0f172a;padding:2px 8px;border-radius:999px;cursor:pointer;">Exit</span>';
    b.title='Demo mode — unlimited, no payment. Hidden from normal users.';
    h.querySelector('.land-title')?.appendChild(b);
  }
}

// Hook login button to offer register alternative
document.addEventListener('DOMContentLoaded', ()=>{
  renderDemoBadge();
  // Auto-enter demo if ?demo=1 and admin secret in hash (hidden path)
  if(new URLSearchParams(location.search).has('demo') || location.hash.includes('admin-demo')){
    // don't auto-login, just reveal trigger
    const t=document.querySelector('.land-title');
    if(t){ t.style.cursor='pointer'; t.title='Triple-click for admin demo'; let c=0; t.addEventListener('click',()=>{ c++; if(c>=3){ c=0; enterDemoMode(); } setTimeout(()=>c=0,1200); }); }
  }
  // If user not logged in, show Register as primary on landing CTA
  const cta=document.querySelector('.land-cta');
  if(cta && !sessionStorage.getItem('vaultSession')){
    // keep Register as primary — demo is hidden via title triple-click only
  }
});
