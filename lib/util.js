// Shared helpers: fingerprints, canonical JSON, responses.

export async function sha256Hex(data) {
  let buf;
  if (typeof data === 'string') buf = new TextEncoder().encode(data);
  else if (data instanceof ArrayBuffer) buf = data;
  else if (ArrayBuffer.isView(data)) buf = data;
  else throw new Error('sha256Hex: unsupported input');
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Stable JSON: object keys sorted at every level, so the same record always
// produces the same fingerprint.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).filter(k => value[k] !== undefined).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}

export function fail(message, status = 400) {
  return json({ error: message }, status);
}

export function nowIso() {
  return new Date().toISOString();
}

export function clean(v, max = 2000) {
  if (v === null || v === undefined) return '';
  return String(v).replace(/\u0000/g, '').trim().slice(0, max);
}

export function safeName(name) {
  return clean(name, 200).replace(/[^\w.\- ()]+/g, '_') || 'file';
}

export const REG_PATTERN = /^(TX|TXU|PA|PAU|VA|VAU|SR|SRU)\s?\d{1,2}-\d{3}-\d{3}$/i;
export const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
