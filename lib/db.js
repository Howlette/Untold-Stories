// Database schema, receipt numbers, the event chain, and file storage.
import { sha256Hex, canonical, nowIso, safeName } from './util.js';

export const STAGES = [
  ['received', 'Received'],
  ['screening', 'Screening'],
  ['editorial', 'Editorial review'],
  ['legal', 'Legal review'],
  ['signoff', 'Sign off'],
  ['development', 'Development'],
  ['recipients', 'Agent selection'],
  ['tracking', 'Submission tracking'],
  ['closed', 'Closed'],
];
// Left menu sections and the statuses each one holds.
export const GROUPS = [
  ['processing', 'Story Processing', ['received', 'screening', 'editorial', 'closed']],
  ['legal', 'Legal Review', ['legal', 'signoff']],
  ['package', 'Proposal Package', ['development', 'recipients']],
  ['tracking', 'Submission Tracking', ['tracking']],
];
export const TRACKING_STATUSES = ['Sent', 'Returned', 'In Review', 'No Interest', 'Negotiating', 'Accepted', 'Rejected'];
export const STAGE_KEYS = STAGES.map(s => s[0]);
export const PACKAGE_ITEMS = ['Logline', 'Series bible', 'Pilot script', 'Pitch deck'];

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS counters (year INTEGER PRIMARY KEY, n INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt TEXT UNIQUE NOT NULL,
    received_at TEXT NOT NULL,
    name TEXT, email TEXT, phone TEXT, title TEXT, whose TEXT, living TEXT, era TEXT, place TEXT,
    summary TEXT, regno TEXT,
    story_sha256 TEXT, record_sha256 TEXT,
    stage TEXT NOT NULL DEFAULT 'received',
    outcome TEXT,
    is_test INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT)`,
  `CREATE INDEX IF NOT EXISTS submissions_stage ON submissions(stage)`,
  `CREATE INDEX IF NOT EXISTS submissions_story ON submissions(story_sha256)`,
  `CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    name TEXT, type TEXT, size INTEGER, sha256 TEXT,
    uploaded_by TEXT, uploaded_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    reviewer TEXT NOT NULL,
    step TEXT NOT NULL,
    scores TEXT, notes TEXT, decision TEXT,
    completed_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS agreements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    sent_at TEXT, signed_at TEXT,
    file_id INTEGER, signed_sha256 TEXT, signing_ref TEXT,
    UNIQUE(submission_id, kind))`,
  `CREATE TABLE IF NOT EXISTS package_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    item TEXT NOT NULL,
    owner TEXT, status TEXT, version TEXT, wga_reg TEXT, file_id INTEGER, updated_at TEXT,
    UNIQUE(submission_id, item))`,
  `CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT NOT NULL, contact_name TEXT, email TEXT, genres TEXT, rules TEXT,
    own_release INTEGER NOT NULL DEFAULT 0, source TEXT, created_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS sends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    package_version TEXT, sent_at TEXT, release_status TEXT, follow_up TEXT,
    response TEXT, response_date TEXT,
    UNIQUE(submission_id, recipient_id))`,
  `CREATE TABLE IF NOT EXISTS notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    kind TEXT NOT NULL, to_email TEXT, subject TEXT, body TEXT,
    sent_at TEXT, status TEXT, sent_by TEXT)`,
  `CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER,
    at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY, name TEXT, role TEXT NOT NULL, added_at TEXT, added_by TEXT)`,
  `CREATE TABLE IF NOT EXISTS accounts (
    email TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0,
    fails INTEGER NOT NULL DEFAULT 0, locked_until TEXT, last_login TEXT, updated_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, email TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS assignments (
    submission_id INTEGER NOT NULL, email TEXT NOT NULL, assigned_at TEXT,
    PRIMARY KEY (submission_id, email))`,
];

let ready = null;
export function ensureSchema(env) {
  if (!ready) {
    ready = env.DB.batch(SCHEMA.map(s => env.DB.prepare(s)))
      .then(() => env.DB.prepare('ALTER TABLE submissions ADD COLUMN tracking_status TEXT').run().catch(() => null))
      .then(() => env.DB.prepare("UPDATE submissions SET stage = 'legal' WHERE stage = 'selection'").run())
      .catch(e => { ready = null; throw e; });
  }
  return ready;
}

// Receipt numbers: UU-2026-000123, counting up within each year.
export async function nextReceipt(env, isoTime) {
  const year = Number(isoTime.slice(0, 4));
  const row = await env.DB.prepare(
    `INSERT INTO counters (year, n) VALUES (?1, 1)
     ON CONFLICT(year) DO UPDATE SET n = n + 1 RETURNING n`
  ).bind(year).first();
  return `UU-${year}-${String(row.n).padStart(6, '0')}`;
}

export const GENESIS = '0'.repeat(64);

// Every event carries the fingerprint of the event before it, so a changed or
// deleted entry breaks the chain.
export function eventHashInput(e) {
  return canonical({
    prev: e.prev_hash, at: e.at, actor: e.actor, action: e.action,
    submission_id: e.submission_id ?? null, detail: e.detail ?? null,
  });
}

export async function addEvent(env, { submission_id = null, actor, action, detail = null }) {
  const detailText = detail === null ? null : (typeof detail === 'string' ? detail : canonical(detail));
  // Retry on a race with another writer appending at the same moment.
  for (let attempt = 0; attempt < 5; attempt++) {
    const last = await env.DB.prepare('SELECT id, hash FROM events ORDER BY id DESC LIMIT 1').first();
    const prev_hash = last ? last.hash : GENESIS;
    const at = nowIso();
    const e = { submission_id, at, actor, action, detail: detailText, prev_hash };
    const hash = await sha256Hex(eventHashInput(e));
    const res = await env.DB.prepare(
      `INSERT INTO events (submission_id, at, actor, action, detail, prev_hash, hash)
       SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
       WHERE COALESCE((SELECT hash FROM events ORDER BY id DESC LIMIT 1), ?8) = ?6`
    ).bind(submission_id, at, actor, action, detailText, prev_hash, hash, GENESIS).run();
    if (res.meta && res.meta.changes === 1) return { ...e, hash };
  }
  throw new Error('Could not record the event. Try again.');
}

export async function verifyChain(env) {
  const { results } = await env.DB.prepare('SELECT * FROM events ORDER BY id ASC').all();
  let prev = GENESIS;
  for (const e of results) {
    if (e.prev_hash !== prev) return { ok: false, count: results.length, brokenAt: e.id, reason: 'Link to the previous entry does not match' };
    const h = await sha256Hex(eventHashInput(e));
    if (h !== e.hash) return { ok: false, count: results.length, brokenAt: e.id, reason: 'Entry contents do not match its fingerprint' };
    prev = e.hash;
  }
  return { ok: true, count: results.length, head: prev };
}

// Files are stored once under a unique key and never overwritten.
export async function storeFile(env, { submission_id, receipt, kind, file, uploaded_by }) {
  const buf = await file.arrayBuffer();
  const sha = await sha256Hex(buf);
  const key = `${receipt}/${kind}/${crypto.randomUUID()}-${safeName(file.name)}`;
  await env.FILES.put(key, buf, {
    httpMetadata: { contentType: file.type || 'application/octet-stream' },
    customMetadata: { sha256: sha, receipt, kind },
  });
  const row = await env.DB.prepare(
    `INSERT INTO files (submission_id, kind, storage_key, name, type, size, sha256, uploaded_by, uploaded_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) RETURNING id`
  ).bind(submission_id, kind, key, safeName(file.name), file.type || '', buf.byteLength, sha, uploaded_by, nowIso()).first();
  return { id: row.id, sha256: sha, size: buf.byteLength, name: safeName(file.name), key };
}
