/**
 * Public Vault Worker — TENANT-ISOLATED template
 * - NO family MODE_MEMBERS, NO shared MY_BUCKET, every R2 key = tenants/{uid}/
 * - JWT signed with PUBLIC_JWT_SECRET (not SOV MASTER_PASSWORD)
 * Grep must show 0 hits for MY_BUCKET / MASTER_PASSWORD / MODE_MEMBERS before deploy.
 */
export default {
  async fetch(request, env) {
    return new Response("Public Vault worker template — implement tenant-scoped handlers before deploy.", { status: 501 });
  }
};
