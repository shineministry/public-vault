# Public Document Vault — Secure File Portal (SaaS)

Standalone repo — **no link to private SOV**. Deploy this repo alone.

Pricing: Starter €3 (10GB) / Plus €6 (100GB) / Family €10 (500GB)

## Deploy
1. `cp wrangler.toml.example wrangler.toml` → fill secrets via `wrangler secret put`
2. `wrangler r2 bucket create public-vault-bucket` — you said you will put R2, create empty bucket yourself
3. `wrangler deploy` → `https://public-vault.<subdomain>.workers.dev`
4. Attach custom domain in Cloudflare Dashboard → Workers & Pages → Domains & Routes
5. Frontend: GitHub Pages from this repo → Settings → Pages → Custom domain

See `docs/ARCHITECTURE.md` for isolation guarantees.
