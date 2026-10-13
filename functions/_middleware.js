// Routes requests by address. The admin address serves the admin app and its
// API, behind sign-in. Every other address serves the public site and cannot
// reach anything under /admin or /api/admin.
import { ensureSchema } from '../lib/db.js';
import { currentUser } from '../lib/auth.js';

function adminHosts(env) {
  return String(env.ADMIN_HOSTS || 'admin.limitedseries.net').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
}

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
};

function withHeaders(res, extra = {}) {
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries({ ...SECURITY_HEADERS, ...extra })) r.headers.set(k, v);
  return r;
}

function page(status, title, text) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><title>${title}</title>` +
    `<style>body{margin:0;font:16px/1.6 Georgia,serif;background:#16120e;color:#f2e8d7;display:grid;place-items:center;min-height:100vh;padding:16px}main{max-width:520px}h1{font:700 1.6rem Arial Narrow,sans-serif;text-transform:uppercase;letter-spacing:.02em}</style></head>` +
    `<body><main><h1>${title}</h1><p>${text}</p></main></body></html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const host = url.hostname.toLowerCase();
  const isAdminHost = adminHosts(env).includes(host);
  const path = url.pathname;

  if (!isAdminHost) {
    if (path === '/admin' || path.startsWith('/admin/') || path.startsWith('/api/admin')) {
      return withHeaders(page(404, 'Not found', 'There is nothing at this address.'));
    }
    if (path.startsWith('/api/')) {
      if (!env.DB) return withHeaders(new Response(JSON.stringify({ error: 'Storage is not connected yet.' }), { status: 503, headers: { 'content-type': 'application/json' } }));
      await ensureSchema(env);
    }
    return withHeaders(await next());
  }

  // Admin address: everything requires a signed-in, approved user.
  if (!env.DB) return withHeaders(page(503, 'Not ready', 'The admin database is not connected yet.'));
  await ensureSchema(env);
  const user = await currentUser(request, env);
  if (!user) return withHeaders(page(401, 'Sign in required', 'Sign in through the Untold Stories admin sign-in page to continue.'));
  if (!user.role) {
    return withHeaders(page(403, 'Not approved', `You signed in as ${user.email.replace(/[<>&"]/g, '')}, but this address has not been given access. Ask the administrator to add you.`));
  }
  context.data.user = user;

  if (path.startsWith('/api/admin')) return withHeaders(await next());
  if (path.startsWith('/api/')) return withHeaders(page(404, 'Not found', 'There is nothing at this address.'));

  // Any other path on the admin address serves the admin app.
  const res = await env.ASSETS.fetch(new URL('/admin/', url));
  return withHeaders(res, { 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' });
}
