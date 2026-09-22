# Public Vault Architecture — Isolated from Private SOV

Private SOV: https://72oe-v2sx.shine-ministry.com (CNAME in SOV repo) — stays private, single MY_BUCKET + files.json
Public Vault: this repo — new R2 bucket (you will put) + new Worker + tenants/{uid}/ prefix

Hard isolation: different Worker, different R2, different JWT secret, Firestore tenants/{uid} namespace, separate ALLOWED_ORIGINS.

Tiers: €3 Starter 10GB / €6 Plus 100GB / €10 Family 500GB — Stripe Checkout + webhook quota enforcement. Client-side AES-256-GCM, server never sees plaintext.

Deploy: wrangler deploy → attach custom domain in Cloudflare Workers → Domains & Routes. Frontend GitHub Pages custom domain via repo Settings → Pages.
