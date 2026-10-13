// Admin sign-in with email and password.
// Passwords are stored only as PBKDF2-SHA256 hashes. Sessions are random
// tokens in an HttpOnly cookie; the database keeps only the token's hash.
import { sha256Hex, nowIso } from './util.js';

export const ROLES = ['admin', 'reviewer', 'legal', 'writer'];
export const COOKIE = 'uu_session';
const SESSION_HOURS = 12;
const ITERATIONS = 100000;
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;

const b64 = bytes => btoa(String.fromCharCode(...bytes));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${b64(salt)}$${b64(hash)}`;
}

export async function checkPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const hash = await pbkdf2(password, unb64(parts[2]), Number(parts[1]));
  const want = unb64(parts[3]);
  if (hash.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash[i] ^ want[i];
  return diff === 0;
}

export function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return 'Use at least 8 characters.';
  if (pw.length > 200) return 'That password is too long.';
  return null;
}

function cookieValue(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

export function sessionCookie(token, secure) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}${secure ? '; Secure' : ''}`;
}
export function clearCookie(secure) {
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}`;
}

// Returns { email, name, role, mustChange } or null.
export async function currentUser(request, env) {
  if (env.DEV_AUTH_EMAIL) {
    const email = String(env.DEV_AUTH_EMAIL).toLowerCase();
    const u = await env.DB.prepare('SELECT email, name, role FROM users WHERE email = ?1').bind(email).first();
    return u ? { ...u, mustChange: false } : null;
  }
  const token = cookieValue(request, COOKIE);
  if (!token || token.length < 32) return null;
  const id = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT s.email, s.expires_at, u.name, u.role, a.must_change FROM sessions s
     JOIN users u ON u.email = s.email LEFT JOIN accounts a ON a.email = s.email WHERE s.id = ?1`
  ).bind(id).first();
  if (!row) return null;
  if (row.expires_at < nowIso()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?1').bind(id).run();
    return null;
  }
  return { email: row.email, name: row.name || '', role: row.role, mustChange: Boolean(row.must_change) };
}

// The first administrator's starting password comes from OWNER_PASSWORD_HASH
// until they sign in once; after that it lives in the accounts table.
async function ensureOwner(env, email) {
  const owners = String(env.OWNER_EMAIL || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  if (!owners.includes(email) || !env.OWNER_PASSWORD_HASH) return;
  const acct = await env.DB.prepare('SELECT email FROM accounts WHERE email = ?1').bind(email).first();
  if (acct) return;
  await env.DB.batch([
    env.DB.prepare('INSERT OR IGNORE INTO users (email, name, role, added_at, added_by) VALUES (?1, \'\', \'admin\', ?2, \'system\')').bind(email, nowIso()),
    env.DB.prepare('INSERT OR IGNORE INTO accounts (email, pass_hash, must_change, fails, updated_at) VALUES (?1, ?2, 0, 0, ?3)').bind(email, env.OWNER_PASSWORD_HASH, nowIso()),
  ]);
}

export async function login(env, email, password) {
  email = String(email || '').trim().toLowerCase();
  await ensureOwner(env, email);
  const acct = await env.DB.prepare(
    'SELECT a.email, a.pass_hash, a.fails, a.locked_until FROM accounts a JOIN users u ON u.email = a.email WHERE a.email = ?1'
  ).bind(email).first();
  if (!acct) {
    await checkPassword(String(password || ''), 'pbkdf2$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='); // even out timing
    return { error: 'That email and password do not match.' };
  }
  if (acct.locked_until && acct.locked_until > nowIso()) {
    return { error: `Too many failed attempts. Try again after ${LOCK_MINUTES} minutes.` };
  }
  const ok = await checkPassword(String(password || ''), acct.pass_hash);
  if (!ok) {
    const fails = (acct.fails || 0) + 1;
    const locked = fails >= MAX_FAILS ? new Date(Date.now() + LOCK_MINUTES * 60000).toISOString() : null;
    await env.DB.prepare('UPDATE accounts SET fails = ?1, locked_until = ?2 WHERE email = ?3').bind(locked ? 0 : fails, locked, email).run();
    return { error: 'That email and password do not match.' };
  }
  await env.DB.prepare('UPDATE accounts SET fails = 0, locked_until = NULL, last_login = ?1 WHERE email = ?2').bind(nowIso(), email).run();
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const expires = new Date(Date.now() + SESSION_HOURS * 3600000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (id, email, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(await sha256Hex(token), email, nowIso(), expires).run();
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?1').bind(nowIso()).run();
  return { token, email };
}

export async function logout(request, env) {
  const token = cookieValue(request, COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE id = ?1').bind(await sha256Hex(token)).run();
}

export async function setPassword(env, email, password, mustChange) {
  const hash = await hashPassword(password);
  await env.DB.prepare(
    `INSERT INTO accounts (email, pass_hash, must_change, fails, updated_at) VALUES (?1, ?2, ?3, 0, ?4)
     ON CONFLICT(email) DO UPDATE SET pass_hash = ?2, must_change = ?3, fails = 0, locked_until = NULL, updated_at = ?4`
  ).bind(email, hash, mustChange ? 1 : 0, nowIso()).run();
}

export async function endSessions(env, email, exceptToken) {
  if (exceptToken) {
    await env.DB.prepare('DELETE FROM sessions WHERE email = ?1 AND id <> ?2').bind(email, await sha256Hex(exceptToken)).run();
  } else {
    await env.DB.prepare('DELETE FROM sessions WHERE email = ?1').bind(email).run();
  }
}

export function sessionToken(request) {
  return cookieValue(request, COOKIE);
}
