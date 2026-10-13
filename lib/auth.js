// Admin sign-in. Cloudflare Access (https://www.cloudflare.com/zero-trust/products/access/)
// stands in front of the admin address. Every request is checked again here by
// verifying the signed token Access attaches, so the server never trusts a
// header alone.
import { nowIso } from './util.js';

const certCache = { url: '', keys: null, at: 0 };

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function accessKeys(teamDomain) {
  const url = `https://${teamDomain}/cdn-cgi/access/certs`;
  if (certCache.url === url && certCache.keys && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Could not load sign-in keys');
  const { keys } = await res.json();
  certCache.url = url; certCache.keys = keys; certCache.at = Date.now();
  return keys;
}

async function verifyAccessToken(token, env) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  if (header.alg !== 'RS256') return null;
  const keys = await accessKeys(env.ACCESS_TEAM_DOMAIN);
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) return null;
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) return null;
  if (payload.nbf && payload.nbf > now + 60) return null;
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.ACCESS_AUD)) return null;
  if (payload.iss && payload.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;
  return payload.email ? String(payload.email).toLowerCase() : null;
}

// Returns { email, role, name } or null.
export async function currentUser(request, env) {
  let email = null;
  if (env.DEV_AUTH_EMAIL) {
    email = String(env.DEV_AUTH_EMAIL).toLowerCase();
  } else {
    if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
    const token = request.headers.get('cf-access-jwt-assertion');
    if (!token) return null;
    try { email = await verifyAccessToken(token, env); } catch { email = null; }
  }
  if (!email) return null;

  let user = await env.DB.prepare('SELECT email, name, role FROM users WHERE email = ?1').bind(email).first();
  const owners = String(env.OWNER_EMAIL || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  if (!user && owners.includes(email)) {
    await env.DB.prepare('INSERT OR IGNORE INTO users (email, name, role, added_at, added_by) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(email, '', 'admin', nowIso(), 'system').run();
    user = { email, name: '', role: 'admin' };
  }
  return user ? { email: user.email, name: user.name || '', role: user.role } : { email, role: null };
}

export const ROLES = ['admin', 'reviewer', 'legal', 'writer'];
