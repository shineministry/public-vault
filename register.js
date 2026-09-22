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

// Hook login button to offer register alternative
document.addEventListener('DOMContentLoaded', ()=>{
  // If user not logged in, show Register as primary on landing CTA
  const cta=document.querySelector('.land-cta');
  if(cta && !sessionStorage.getItem('vaultSession')){
    cta.textContent='Create Free Account →';
    cta.setAttribute('onclick','openRegister()');
  }
});
