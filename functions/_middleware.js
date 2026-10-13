// Routes requests by address. The admin address serves the admin app and its
// API, behind sign-in. Every other address serves the public site and cannot
// reach anything under /admin or /api/admin.
import { ensureSchema } from '../lib/db.js';
import { addEvent } from '../lib/db.js';
import { currentUser, login, logout, sessionCookie, clearCookie, checkPassword, passwordProblem, setPassword, endSessions, sessionToken } from '../lib/auth.js';

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

  // Admin address.
  if (!env.DB) return withHeaders(page(503, 'Not ready', 'The admin database is not connected yet.'));
  await ensureSchema(env);
  const secure = url.protocol === 'https:';
  const json = (data, status = 200, extra = {}) => withHeaders(new Response(JSON.stringify(data), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  }));

  // Requests that change something must come from this site.
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) return json({ error: 'Request blocked.' }, 403);
  }

  if (path === '/login') {
    return withHeaders(new Response(LOGIN_PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' } }));
  }
  if (path === '/api/auth/login' && request.method === 'POST') {
    let b = {};
    try { b = await request.json(); } catch {}
    const r = await login(env, b.email, b.password);
    if (r.error) return json({ error: r.error }, 401);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(r.token, secure) });
  }
  if (path === '/api/auth/logout' && request.method === 'POST') {
    await logout(request, env);
    return json({ ok: true }, 200, { 'set-cookie': clearCookie(secure) });
  }

  const user = await currentUser(request, env);
  if (!user) {
    if (path.startsWith('/api/')) return json({ error: 'Your session has ended. Sign in again.' }, 401);
    return withHeaders(Response.redirect(new URL('/login', url).toString(), 302));
  }
  context.data.user = user;

  if (path === '/api/auth/password' && request.method === 'POST') {
    let b = {};
    try { b = await request.json(); } catch {}
    const acct = await env.DB.prepare('SELECT pass_hash FROM accounts WHERE email = ?1').bind(user.email).first();
    if (!acct || !(await checkPassword(String(b.current || ''), acct.pass_hash))) return json({ error: 'Your current password is not correct.' }, 400);
    const problem = passwordProblem(b.next);
    if (problem) return json({ error: problem }, 400);
    if (b.next === b.current) return json({ error: 'Choose a password different from the current one.' }, 400);
    await setPassword(env, user.email, b.next, false);
    await endSessions(env, user.email, sessionToken(request));
    await addEvent(env, { actor: user.email, action: 'password_changed', detail: null });
    return json({ ok: true });
  }
  if (user.mustChange && path.startsWith('/api/admin') && path !== '/api/admin/me') {
    return json({ error: 'Change your temporary password first.' }, 403);
  }

  if (path.startsWith('/api/admin')) return withHeaders(await next());
  if (path.startsWith('/api/')) return json({ error: 'Not found.' }, 404);

  // Any other path on the admin address serves the admin app.
  const res = await env.ASSETS.fetch(new URL('/admin/', url));
  return withHeaders(res, { 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' });
}

const LOGIN_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow">
<title>Sign In</title>
<style>
:root{--ink:#16120e;--stage:#211b15;--line:#3b3229;--paper:#f2e8d7;--dust:#ab9c89;--amber:#e8a948;--amber-ink:#1a1206;--bad:#e38b7a;color-scheme:dark}
@media (prefers-color-scheme: light){:root{--ink:#f4f1ea;--stage:#fff;--line:#d6cbb8;--paper:#1d1711;--dust:#5f5347;--amber:#9a5c0b;--amber-ink:#fff8ec;--bad:#a23a28;color-scheme:light}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--ink);color:var(--paper);font:16px/1.5 Georgia,serif}
form{width:100%;max-width:380px;background:var(--stage);border:1px solid var(--line);border-radius:12px;padding:28px}
.brand{font:700 20px "Arial Narrow",Arial,sans-serif;text-transform:uppercase;letter-spacing:.04em;margin:0 0 4px}
.brand span{color:var(--amber)}
p.sub{color:var(--dust);margin:0 0 18px;font-size:15px}
label{display:block;font-size:14px;color:var(--dust);margin:14px 0 4px}
input{width:100%;font:inherit;color:var(--paper);background:var(--ink);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
input:focus{outline:2px solid var(--amber);outline-offset:1px}
button{width:100%;margin-top:20px;font:700 15px "Arial Narrow",Arial,sans-serif;text-transform:uppercase;letter-spacing:.06em;background:var(--amber);color:var(--amber-ink);border:0;border-radius:6px;padding:12px;cursor:pointer}
button:disabled{opacity:.6}
.err{color:var(--bad);font-size:14px;margin:12px 0 0;min-height:1.2em}
</style></head>
<body>
<form id="f" novalidate>
  <p class="brand">Untold Unsung <span>Admin</span></p>
  <p class="sub">Sign in to manage story submissions.</p>
  <label for="email">Email</label><input id="email" type="email" autocomplete="username" required autofocus>
  <label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
  <p class="err" id="err" role="alert"></p>
</form>
<script>
document.getElementById('f').addEventListener('submit', async function(e){
  e.preventDefault();
  var b = this.querySelector('button'), err = document.getElementById('err');
  err.textContent = ''; b.disabled = true;
  try {
    var r = await fetch('/api/auth/login', {method:'POST', headers:{'content-type':'application/json'}, credentials:'same-origin',
      body: JSON.stringify({email: document.getElementById('email').value, password: document.getElementById('password').value})});
    var d = await r.json().catch(function(){ return {}; });
    if (r.ok) { location.href = '/'; return; }
    err.textContent = d.error || 'Sign in failed. Try again.';
  } catch (x) { err.textContent = 'Could not reach the server. Try again.'; }
  b.disabled = false;
});
</script>
</body></html>`;
