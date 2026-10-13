// Admin API. The middleware has already verified sign-in and set context.data.user.
import { STAGES, STAGE_KEYS, PACKAGE_ITEMS, addEvent, verifyChain, storeFile } from '../../../lib/db.js';
import { json, fail, nowIso, clean, EMAIL_PATTERN } from '../../../lib/util.js';
import { sendMail, template, mailConfigured } from '../../../lib/mail.js';
import { ROLES, setPassword, passwordProblem, endSessions } from '../../../lib/auth.js';

const REVIEW_STEPS = ['screening', 'editorial', 'legal'];
const AGREEMENT_KINDS = ['acknowledgement', 'rights'];
const NOTICE_KINDS = ['receipt', 'not_selected', 'selected', 'signing_request', 'milestone', 'closing'];
const FILE_KINDS = ['story', 'record', 'package', 'agreement', 'other'];
const PACKAGE_STATUSES = ['Not started', 'Drafting', 'In review', 'Final'];
const SCORE_KEYS = ['true_documented', 'real_risk', 'turning_point', 'lasting_impact', 'message', 'screen_potential'];

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const deny = msg => { throw new HttpError(403, msg || 'You do not have permission to do that.'); };
const bad = msg => { throw new HttpError(400, msg); };

async function body(request) {
  try { return await request.json(); } catch { bad('The request could not be read.'); }
}

const isAdmin = u => u.role === 'admin';
const seesAll = u => u.role === 'admin' || u.role === 'legal';

async function loadSubmission(env, user, receipt) {
  const s = await env.DB.prepare('SELECT * FROM submissions WHERE receipt = ?1').bind(String(receipt).toUpperCase()).first();
  if (!s) throw new HttpError(404, 'No submission with that receipt number.');
  if (!seesAll(user)) {
    const a = await env.DB.prepare('SELECT 1 FROM assignments WHERE submission_id = ?1 AND email = ?2').bind(s.id, user.email).first();
    if (!a) throw new HttpError(404, 'No submission with that receipt number.');
  }
  return s;
}

async function agreementsSigned(env, id) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM agreements WHERE submission_id = ?1 AND signed_at IS NOT NULL AND kind IN (\'acknowledgement\', \'rights\')').bind(id).first();
  return r.n === 2;
}

async function touch(env, id) {
  await env.DB.prepare('UPDATE submissions SET updated_at = ?1 WHERE id = ?2').bind(nowIso(), id).run();
}

// ---------- handlers ----------

async function me(env, user) {
  return {
    user, stages: STAGES, roles: ROLES, reviewSteps: REVIEW_STEPS, packageItems: PACKAGE_ITEMS,
    packageStatuses: PACKAGE_STATUSES, scoreKeys: SCORE_KEYS, noticeKinds: NOTICE_KINDS,
    mailConfigured: mailConfigured(env), submissionsMode: String(env.SUBMISSIONS_MODE || 'closed'),
  };
}

async function listSubmissions(env, user, url) {
  const stage = url.searchParams.get('stage');
  const q = clean(url.searchParams.get('q'), 100);
  const where = [], args = [];
  if (!seesAll(user)) { where.push('s.id IN (SELECT submission_id FROM assignments WHERE email = ?)'); args.push(user.email); }
  if (stage && STAGE_KEYS.includes(stage)) { where.push('s.stage = ?'); args.push(stage); }
  if (q) { where.push('(s.receipt LIKE ? OR s.title LIKE ? OR s.name LIKE ? OR s.email LIKE ?)'); const like = `%${q}%`; args.push(like, like, like, like); }
  const sql = `SELECT s.id, s.receipt, s.received_at, s.name, s.title, s.era, s.place, s.stage, s.outcome, s.is_test, s.updated_at,
      (SELECT COUNT(*) FROM reviews r WHERE r.submission_id = s.id) AS review_count
    FROM submissions s ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY s.id DESC LIMIT 500`;
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  const countsSql = seesAll(user)
    ? env.DB.prepare('SELECT stage, COUNT(*) AS n FROM submissions GROUP BY stage')
    : env.DB.prepare('SELECT stage, COUNT(*) AS n FROM submissions WHERE id IN (SELECT submission_id FROM assignments WHERE email = ?1) GROUP BY stage').bind(user.email);
  const counts = Object.fromEntries((await countsSql.all()).results.map(r => [r.stage, r.n]));
  return { submissions: results, counts };
}

async function detail(env, user, s) {
  const id = s.id;
  const q = (sql, ...a) => env.DB.prepare(sql).bind(...a).all().then(r => r.results);
  const [files, reviewsAll, agreements, pkg, sends, notices, events, assignments] = await Promise.all([
    q('SELECT id, kind, name, type, size, sha256, uploaded_by, uploaded_at FROM files WHERE submission_id = ?1 ORDER BY id', id),
    q('SELECT * FROM reviews WHERE submission_id = ?1 ORDER BY id', id),
    q('SELECT * FROM agreements WHERE submission_id = ?1', id),
    q('SELECT * FROM package_items WHERE submission_id = ?1', id),
    q(`SELECT sd.*, r.company, r.contact_name, r.email AS recipient_email, r.own_release FROM sends sd
       JOIN recipients r ON r.id = sd.recipient_id WHERE sd.submission_id = ?1 ORDER BY r.company`, id),
    q('SELECT id, kind, to_email, subject, body, sent_at, status, sent_by FROM notices WHERE submission_id = ?1 ORDER BY id', id),
    q('SELECT id, at, actor, action, detail, prev_hash, hash FROM events WHERE submission_id = ?1 ORDER BY id', id),
    q('SELECT a.email, a.assigned_at, u.role, u.name FROM assignments a LEFT JOIN users u ON u.email = a.email WHERE a.submission_id = ?1', id),
  ]);
  // A reviewer sees other reviewers' scores for a step only after entering their own.
  let reviews = reviewsAll;
  if (user.role === 'reviewer' || user.role === 'writer') {
    const mine = new Set(reviewsAll.filter(r => r.reviewer === user.email).map(r => r.step));
    reviews = reviewsAll.filter(r => r.reviewer === user.email || mine.has(r.step));
  }
  const hidden = reviewsAll.length - reviews.length;
  const signed = await agreementsSigned(env, id);
  return { submission: s, files, reviews, hiddenReviews: hidden, agreements, packageItems: pkg, sends, notices, events, assignments, developmentUnlocked: signed };
}

async function moveStage(env, user, s, b) {
  const to = String(b.to || '');
  const note = clean(b.note, 2000);
  if (!STAGE_KEYS.includes(to)) bad('Unknown stage.');
  const from = s.stage;
  if (from === to) bad('The story is already at that stage.');
  const iFrom = STAGE_KEYS.indexOf(from), iTo = STAGE_KEYS.indexOf(to);
  const legalOK = user.role === 'legal' && from === 'legal' && (to === 'selection' || to === 'editorial');
  if (!isAdmin(user) && !legalOK) deny('Only the administrator can move a story between stages.');
  if (from === 'closed' && to !== 'received' && !isAdmin(user)) deny();

  let outcome = s.outcome;
  if (to === 'closed') {
    outcome = clean(b.outcome, 200);
    if (!outcome) bad('Say why the file is closing, for example Not selected, Withdrawn, or Finished.');
  } else if (iTo > iFrom) {
    if (from !== 'closed' && iTo !== iFrom + 1) bad('Stories move forward one stage at a time.');
    if (to === 'signoff') outcome = 'Selected';
    if (to === 'development' && !(await agreementsSigned(env, s.id))) bad('Development stays locked until the acknowledgement and the rights agreement are both signed and on file.');
    if (to === 'tracking') {
      const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM sends WHERE submission_id = ?1 AND approved = 1').bind(s.id).first();
      if (!r.n) bad('Approve at least one recipient before moving to submission tracking.');
    }
  }
  await env.DB.prepare('UPDATE submissions SET stage = ?1, outcome = ?2, updated_at = ?3 WHERE id = ?4').bind(to, outcome, nowIso(), s.id).run();
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'stage', detail: { from, to, note: note || null, outcome: to === 'closed' ? outcome : null } });
  return { ok: true };
}

async function addReview(env, user, s, b) {
  const step = String(b.step || '');
  if (!REVIEW_STEPS.includes(step)) bad('Choose screening, editorial, or legal.');
  if (step === 'legal' && !['admin', 'legal'].includes(user.role)) deny('Only legal counsel or the administrator can record a legal review.');
  if (user.role === 'writer') deny();
  const scores = {};
  if (step === 'editorial') {
    for (const k of SCORE_KEYS) {
      const v = Number(b.scores?.[k]);
      if (!(v >= 1 && v <= 5)) bad('Score every editorial question from 1 to 5.');
      scores[k] = v;
    }
  }
  const decision = clean(b.decision, 40);
  if (!['Pass', 'Hold', 'Decline'].includes(decision)) bad('Choose a recommendation: Pass, Hold, or Decline.');
  const notes = clean(b.notes, 20000);
  const at = nowIso();
  const row = await env.DB.prepare('INSERT INTO reviews (submission_id, reviewer, step, scores, notes, decision, completed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) RETURNING id')
    .bind(s.id, user.email, step, JSON.stringify(scores), notes, decision, at).first();
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'review', detail: { review_id: row.id, step, decision, scores } });
  await touch(env, s.id);
  return { ok: true };
}

async function addNote(env, user, s, b) {
  const text = clean(b.text, 5000);
  if (!text) bad('Write a note first.');
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'note', detail: { text } });
  return { ok: true };
}

async function assign(env, user, s, b, remove) {
  if (!isAdmin(user)) deny();
  const email = clean(b.email, 200).toLowerCase();
  const u = await env.DB.prepare('SELECT email FROM users WHERE email = ?1').bind(email).first();
  if (!u) bad('Add that person under Users first.');
  if (remove) await env.DB.prepare('DELETE FROM assignments WHERE submission_id = ?1 AND email = ?2').bind(s.id, email).run();
  else await env.DB.prepare('INSERT OR IGNORE INTO assignments (submission_id, email, assigned_at) VALUES (?1, ?2, ?3)').bind(s.id, email, nowIso()).run();
  await addEvent(env, { submission_id: s.id, actor: user.email, action: remove ? 'unassigned' : 'assigned', detail: { email } });
  return { ok: true };
}

async function uploadFile(env, user, s, request) {
  const form = await request.formData();
  const kind = String(form.get('kind') || 'other');
  if (!FILE_KINDS.includes(kind) || kind === 'story') bad('Choose a file kind.');
  if (user.role === 'reviewer') deny();
  if (kind === 'agreement' && !['admin', 'legal'].includes(user.role)) deny();
  if (kind === 'package' && !(await agreementsSigned(env, s.id))) bad('Development stays locked until both documents are signed.');
  const file = form.get('file');
  if (!(file instanceof File) || !file.size) bad('Choose a file.');
  if (file.size > 100 * 1024 * 1024) bad('The file is larger than 100 MB.');
  const f = await storeFile(env, { submission_id: s.id, receipt: s.receipt, kind, file, uploaded_by: user.email });
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'file', detail: { file_id: f.id, kind, name: f.name, sha256: f.sha256, size: f.size } });
  await touch(env, s.id);
  return { ok: true, file: f };
}

async function downloadFile(env, user, id) {
  const f = await env.DB.prepare('SELECT f.*, s.receipt FROM files f JOIN submissions s ON s.id = f.submission_id WHERE f.id = ?1').bind(Number(id)).first();
  if (!f) throw new HttpError(404, 'File not found.');
  await loadSubmission(env, user, f.receipt);
  const obj = await env.FILES.get(f.storage_key);
  if (!obj) throw new HttpError(404, 'File missing from storage.');
  await addEvent(env, { submission_id: f.submission_id, actor: user.email, action: 'file_opened', detail: { file_id: f.id, name: f.name } });
  return new Response(obj.body, {
    headers: {
      'content-type': f.type || 'application/octet-stream',
      'content-disposition': `attachment; filename="${f.name.replace(/"/g, '')}"`,
      'cache-control': 'no-store',
      'x-sha256': f.sha256,
    },
  });
}

async function agreement(env, user, s, b) {
  if (!['admin', 'legal'].includes(user.role)) deny();
  const kind = String(b.kind || '');
  if (!AGREEMENT_KINDS.includes(kind)) bad('Choose the acknowledgement or the rights agreement.');
  if (!['signoff', 'development', 'recipients', 'tracking'].includes(s.stage)) bad('Agreements are handled after the story is selected.');
  const action = String(b.action || '');
  const at = nowIso();
  await env.DB.prepare('INSERT OR IGNORE INTO agreements (submission_id, kind) VALUES (?1, ?2)').bind(s.id, kind).run();
  if (action === 'sent') {
    await env.DB.prepare('UPDATE agreements SET sent_at = ?1, signing_ref = ?2 WHERE submission_id = ?3 AND kind = ?4')
      .bind(at, clean(b.signing_ref, 300), s.id, kind).run();
  } else if (action === 'signed') {
    const fileId = Number(b.file_id);
    const f = await env.DB.prepare('SELECT id, sha256 FROM files WHERE id = ?1 AND submission_id = ?2 AND kind = \'agreement\'').bind(fileId, s.id).first();
    if (!f) bad('Upload the signed document first (file kind: Signed agreement), then choose it.');
    await env.DB.prepare('UPDATE agreements SET signed_at = ?1, file_id = ?2, signed_sha256 = ?3, signing_ref = COALESCE(NULLIF(?4, \'\'), signing_ref) WHERE submission_id = ?5 AND kind = ?6')
      .bind(at, f.id, f.sha256, clean(b.signing_ref, 300), s.id, kind).run();
  } else if (action === 'reset') {
    if (!isAdmin(user)) deny();
    await env.DB.prepare('UPDATE agreements SET sent_at = NULL, signed_at = NULL, file_id = NULL, signed_sha256 = NULL WHERE submission_id = ?1 AND kind = ?2').bind(s.id, kind).run();
  } else bad('Unknown action.');
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'agreement', detail: { kind, action, file_id: b.file_id || null } });
  await touch(env, s.id);
  return { ok: true };
}

async function packageItem(env, user, s, b) {
  if (!['admin', 'writer'].includes(user.role)) deny();
  if (!(await agreementsSigned(env, s.id))) bad('Development stays locked until both documents are signed.');
  const item = String(b.item || '');
  if (!PACKAGE_ITEMS.includes(item)) bad('Unknown package item.');
  const status = PACKAGE_STATUSES.includes(b.status) ? b.status : 'Not started';
  let fileId = b.file_id ? Number(b.file_id) : null;
  if (fileId) {
    const f = await env.DB.prepare('SELECT id FROM files WHERE id = ?1 AND submission_id = ?2').bind(fileId, s.id).first();
    if (!f) bad('That file is not on this submission.');
  }
  const vals = [clean(b.owner, 200), status, clean(b.version, 40), clean(b.wga_reg, 60), fileId, nowIso()];
  await env.DB.prepare(`INSERT INTO package_items (submission_id, item, owner, status, version, wga_reg, file_id, updated_at)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    ON CONFLICT(submission_id, item) DO UPDATE SET owner = ?3, status = ?4, version = ?5, wga_reg = ?6, file_id = ?7, updated_at = ?8`)
    .bind(s.id, item, ...vals).run();
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'package', detail: { item, owner: vals[0], status, version: vals[2], wga_reg: vals[3], file_id: fileId } });
  await touch(env, s.id);
  return { ok: true };
}

async function noticePreview(env, user, s, b) {
  const kind = String(b.kind || '');
  if (!NOTICE_KINDS.includes(kind)) bad('Unknown notice.');
  return { ...template(kind, s), to: s.email };
}

async function noticeSend(env, user, s, b) {
  const kind = String(b.kind || '');
  if (!NOTICE_KINDS.includes(kind)) bad('Unknown notice.');
  if (!isAdmin(user) && !(user.role === 'legal' && kind === 'signing_request')) deny();
  const subject = clean(b.subject, 300), text = clean(b.body, 20000);
  if (!subject || !text) bad('The notice needs a subject and a message.');
  if (/\[(Signing links|Milestone|Outcome)\]/.test(text)) bad('Replace the bracketed placeholder in the message before sending.');
  const mail = await sendMail(env, { to: s.email, subject, text });
  const at = nowIso();
  const row = await env.DB.prepare('INSERT INTO notices (submission_id, kind, to_email, subject, body, sent_at, status, sent_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING id')
    .bind(s.id, kind, s.email, subject, text, at, mail.status, user.email).first();
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'notice', detail: { notice_id: row.id, kind, status: mail.status } });
  return { ok: true, status: mail.status };
}

async function addSend(env, user, s, b) {
  if (!isAdmin(user)) deny();
  if (!['recipients', 'tracking'].includes(s.stage)) bad('Recipients are chosen at the recipient selection stage.');
  const rid = Number(b.recipient_id);
  const r = await env.DB.prepare('SELECT id, company FROM recipients WHERE id = ?1').bind(rid).first();
  if (!r) bad('Choose a recipient from the list.');
  await env.DB.prepare('INSERT OR IGNORE INTO sends (submission_id, recipient_id) VALUES (?1, ?2)').bind(s.id, rid).run();
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'recipient_added', detail: { recipient_id: rid, company: r.company } });
  return { ok: true };
}

async function updateSend(env, user, id, b, method) {
  if (!isAdmin(user)) deny();
  const sd = await env.DB.prepare('SELECT sd.*, r.company FROM sends sd JOIN recipients r ON r.id = sd.recipient_id WHERE sd.id = ?1').bind(Number(id)).first();
  if (!sd) throw new HttpError(404, 'Not found.');
  if (method === 'DELETE') {
    if (sd.sent_at) bad('This package was already sent; record the response instead of removing it.');
    await env.DB.prepare('DELETE FROM sends WHERE id = ?1').bind(sd.id).run();
    await addEvent(env, { submission_id: sd.submission_id, actor: user.email, action: 'recipient_removed', detail: { company: sd.company } });
    return { ok: true };
  }
  const v = {
    approved: b.approved === undefined ? sd.approved : (b.approved ? 1 : 0),
    package_version: b.package_version === undefined ? sd.package_version : clean(b.package_version, 40),
    sent_at: b.sent_at === undefined ? sd.sent_at : (clean(b.sent_at, 20) || null),
    release_status: b.release_status === undefined ? sd.release_status : clean(b.release_status, 60),
    follow_up: b.follow_up === undefined ? sd.follow_up : (clean(b.follow_up, 20) || null),
    response: b.response === undefined ? sd.response : clean(b.response, 2000),
    response_date: b.response_date === undefined ? sd.response_date : (clean(b.response_date, 20) || null),
  };
  if (v.sent_at && !v.approved) bad('Approve this recipient before recording a send.');
  await env.DB.prepare('UPDATE sends SET approved = ?1, package_version = ?2, sent_at = ?3, release_status = ?4, follow_up = ?5, response = ?6, response_date = ?7 WHERE id = ?8')
    .bind(v.approved, v.package_version, v.sent_at, v.release_status, v.follow_up, v.response, v.response_date, sd.id).run();
  await addEvent(env, { submission_id: sd.submission_id, actor: user.email, action: 'send_updated', detail: { company: sd.company, ...v } });
  await touch(env, sd.submission_id);
  return { ok: true };
}

async function recipients(env, user, method, id, b) {
  if (method === 'GET') {
    if (!isAdmin(user)) deny();
    const { results } = await env.DB.prepare(`SELECT r.*, (SELECT COUNT(*) FROM sends s WHERE s.recipient_id = r.id) AS send_count FROM recipients r ORDER BY company`).all();
    return { recipients: results };
  }
  if (!isAdmin(user)) deny();
  if (method === 'DELETE') {
    const used = await env.DB.prepare('SELECT COUNT(*) AS n FROM sends WHERE recipient_id = ?1').bind(Number(id)).first();
    if (used.n) bad('This recipient is attached to a story and cannot be removed.');
    await env.DB.prepare('DELETE FROM recipients WHERE id = ?1').bind(Number(id)).run();
    await addEvent(env, { actor: user.email, action: 'recipient_deleted', detail: { id: Number(id) } });
    return { ok: true };
  }
  const v = [clean(b.company, 200), clean(b.contact_name, 200), clean(b.email, 200), clean(b.genres, 300), clean(b.rules, 3000), b.own_release ? 1 : 0, clean(b.source, 300)];
  if (!v[0]) bad('Enter the company name.');
  if (v[2] && !EMAIL_PATTERN.test(v[2])) bad('Check the email address.');
  if (method === 'POST' && !id) {
    const row = await env.DB.prepare('INSERT INTO recipients (company, contact_name, email, genres, rules, own_release, source, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING id')
      .bind(...v, nowIso()).first();
    await addEvent(env, { actor: user.email, action: 'recipient_created', detail: { id: row.id, company: v[0] } });
    return { ok: true, id: row.id };
  }
  await env.DB.prepare('UPDATE recipients SET company = ?1, contact_name = ?2, email = ?3, genres = ?4, rules = ?5, own_release = ?6, source = ?7 WHERE id = ?8').bind(...v, Number(id)).run();
  await addEvent(env, { actor: user.email, action: 'recipient_updated', detail: { id: Number(id), company: v[0] } });
  return { ok: true };
}

async function users(env, user, method, id, b) {
  if (!isAdmin(user)) deny();
  if (method === 'GET') {
    const { results } = await env.DB.prepare(`SELECT u.*, a.last_login, a.must_change, (a.email IS NOT NULL) AS has_password
      FROM users u LEFT JOIN accounts a ON a.email = u.email ORDER BY u.role, u.email`).all();
    return { users: results };
  }
  if (method === 'DELETE') {
    const email = decodeURIComponent(id || '').toLowerCase();
    if (email === user.email) bad('You cannot remove yourself.');
    await env.DB.prepare('DELETE FROM users WHERE email = ?1').bind(email).run();
    await env.DB.prepare('DELETE FROM assignments WHERE email = ?1').bind(email).run();
    await env.DB.prepare('DELETE FROM accounts WHERE email = ?1').bind(email).run();
    await endSessions(env, email);
    await addEvent(env, { actor: user.email, action: 'user_removed', detail: { email } });
    return { ok: true };
  }
  const email = clean(b.email, 200).toLowerCase();
  const role = String(b.role || '');
  if (!EMAIL_PATTERN.test(email)) bad('Enter a valid email address.');
  if (!ROLES.includes(role)) bad('Choose a role.');
  if (email === user.email && role !== 'admin') bad('You cannot remove your own administrator role.');
  const password = typeof b.password === 'string' ? b.password : '';
  const hasAcct = await env.DB.prepare('SELECT 1 FROM accounts WHERE email = ?1').bind(email).first();
  if (!hasAcct && !password) bad('Give the new user a temporary password.');
  if (password) {
    const problem = passwordProblem(password);
    if (problem) bad(problem);
  }
  await env.DB.prepare(`INSERT INTO users (email, name, role, added_at, added_by) VALUES (?1, ?2, ?3, ?4, ?5)
    ON CONFLICT(email) DO UPDATE SET name = ?2, role = ?3`).bind(email, clean(b.name, 200), role, nowIso(), user.email).run();
  if (password) {
    await setPassword(env, email, password, email !== user.email);
    if (email !== user.email) await endSessions(env, email);
  }
  await addEvent(env, { actor: user.email, action: 'user_saved', detail: { email, role, password_set: Boolean(password) } });
  return { ok: true };
}

async function exportRecord(env, user, s) {
  if (!seesAll(user)) deny();
  const d = await detail(env, user, s);
  const chain = await verifyChain(env);
  await addEvent(env, { submission_id: s.id, actor: user.email, action: 'exported', detail: null });
  return new Response(JSON.stringify({ exported_at: nowIso(), exported_by: user.email, ledger: chain, ...d }, null, 2), {
    headers: { 'content-type': 'application/json', 'content-disposition': `attachment; filename="${s.receipt}.json"`, 'cache-control': 'no-store' },
  });
}

// ---------- router ----------

export async function onRequest(context) {
  const { request, env, params, data } = context;
  const user = data.user;
  const parts = (Array.isArray(params.path) ? params.path : [params.path]).filter(Boolean).map(decodeURIComponent);
  const method = request.method;
  const url = new URL(request.url);
  try {
    const [a, b, c, d] = parts;
    if (method === 'GET' && a === 'me') return json(await me(env, user));
    if (method === 'GET' && a === 'counts') {
      const q = seesAll(user)
        ? env.DB.prepare('SELECT stage, COUNT(*) AS n FROM submissions GROUP BY stage')
        : env.DB.prepare('SELECT stage, COUNT(*) AS n FROM submissions WHERE id IN (SELECT submission_id FROM assignments WHERE email = ?1) GROUP BY stage').bind(user.email);
      return json({ counts: Object.fromEntries((await q.all()).results.map(r => [r.stage, r.n])) });
    }
    if (method === 'GET' && a === 'ledger') {
      if (!isAdmin(user) && user.role !== 'legal') deny();
      const chain = await verifyChain(env);
      const { results } = await env.DB.prepare(`SELECT e.id, e.at, e.actor, e.action, e.detail, e.hash, e.prev_hash, s.receipt FROM events e LEFT JOIN submissions s ON s.id = e.submission_id ORDER BY e.id DESC LIMIT 200`).all();
      return json({ chain, events: results });
    }
    if (a === 'files' && b && method === 'GET') return await downloadFile(env, user, b);
    if (a === 'recipients') return json(await recipients(env, user, method, b, method === 'GET' || method === 'DELETE' ? {} : await body(request)));
    if (a === 'users') return json(await users(env, user, method, b, method === 'GET' || method === 'DELETE' ? {} : await body(request)));
    if (a === 'sends' && b && (method === 'PATCH' || method === 'DELETE')) return json(await updateSend(env, user, b, method === 'PATCH' ? await body(request) : {}, method));
    if (a === 'submissions') {
      if (!b && method === 'GET') return json(await listSubmissions(env, user, url));
      const s = await loadSubmission(env, user, b);
      if (!c && method === 'GET') return json(await detail(env, user, s));
      if (c === 'export' && method === 'GET') return await exportRecord(env, user, s);
      if (method !== 'POST') return fail('Not found.', 404);
      if (c === 'files') return json(await uploadFile(env, user, s, request));
      const bd = await body(request);
      if (c === 'stage') return json(await moveStage(env, user, s, bd));
      if (c === 'review') return json(await addReview(env, user, s, bd));
      if (c === 'note') return json(await addNote(env, user, s, bd));
      if (c === 'assign') return json(await assign(env, user, s, bd, false));
      if (c === 'unassign') return json(await assign(env, user, s, bd, true));
      if (c === 'agreement') return json(await agreement(env, user, s, bd));
      if (c === 'package') return json(await packageItem(env, user, s, bd));
      if (c === 'notice' && d === 'preview') return json(await noticePreview(env, user, s, bd));
      if (c === 'notice' && d === 'send') return json(await noticeSend(env, user, s, bd));
      if (c === 'sends') return json(await addSend(env, user, s, bd));
    }
    return fail('Not found.', 404);
  } catch (e) {
    if (e instanceof HttpError) return fail(e.message, e.status);
    console.error(e);
    return fail('Something went wrong on the server. Try again.', 500);
  }
}
