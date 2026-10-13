// Public story submission: stores the files, fingerprints them, issues the
// receipt number, and emails the receipt.
import { ensureSchema, nextReceipt, addEvent, storeFile } from '../../lib/db.js';
import { sha256Hex, canonical, json, fail, nowIso, clean, REG_PATTERN, EMAIL_PATTERN } from '../../lib/util.js';
import { sendMail, template } from '../../lib/mail.js';

const ALLOWED_STORY = /\.(pdf|doc|docx|txt|rtf)$/i;
const ALLOWED_RECORD = /\.(pdf|jpg|jpeg|png)$/i;
const MAX_STORY = 50 * 1024 * 1024;
const MAX_RECORDS_TOTAL = 50 * 1024 * 1024;
const MAX_RECORDS = 10;

export async function onRequestPost({ request, env }) {
  const mode = String(env.SUBMISSIONS_MODE || 'closed');
  if (mode === 'closed') return fail('Submissions are not open yet.', 403);
  if (!env.DB || !env.FILES) return fail('Storage is not connected yet.', 503);
  await ensureSchema(env);

  let form;
  try { form = await request.formData(); } catch { return fail('The form could not be read. Try again.'); }
  if (clean(form.get('website'))) return json({ ok: true }); // filled only by bots

  const f = {
    name: clean(form.get('fname'), 200),
    email: clean(form.get('email'), 200).toLowerCase(),
    phone: clean(form.get('phone'), 50),
    title: clean(form.get('title'), 300),
    whose: clean(form.get('whose'), 100),
    living: clean(form.get('living'), 100),
    era: clean(form.get('era'), 100),
    place: clean(form.get('where'), 200),
    summary: clean(form.get('summary'), 20000),
    regno: clean(form.get('regno'), 40).toUpperCase().replace(/^(TX|PA|VA|SR)U/, '$1u'),
  };
  const consents = ['c-age', 'c-own', 'c-reg', 'c-terms'].every(k => form.get(k) === 'yes');
  const errs = [];
  if (!f.name) errs.push('Enter your full name.');
  if (!EMAIL_PATTERN.test(f.email)) errs.push('Enter a valid email address.');
  if (!f.title) errs.push('Give your story a title.');
  if (!f.whose || !f.living || !f.era || !f.place) errs.push('Complete every required question.');
  if (!REG_PATTERN.test(f.regno)) errs.push('Enter a valid copyright registration number.');
  if (!consents) errs.push('Confirm all four agreement statements.');

  const story = form.get('story');
  if (!(story instanceof File) || !story.size) errs.push('Upload your full story.');
  else if (!ALLOWED_STORY.test(story.name)) errs.push('The story must be a PDF, Word, or text file.');
  else if (story.size > MAX_STORY) errs.push('The story file is larger than 50 MB.');

  const records = form.getAll('files').filter(x => x instanceof File && x.size);
  if (records.length > MAX_RECORDS) errs.push(`Attach no more than ${MAX_RECORDS} supporting records.`);
  if (records.some(r => !ALLOWED_RECORD.test(r.name))) errs.push('Supporting records must be PDF or image files.');
  if (records.reduce((a, r) => a + r.size, 0) > MAX_RECORDS_TOTAL) errs.push('Supporting records are larger than 50 MB in total.');
  if (errs.length) return json({ error: errs.join(' '), errors: errs }, 400);

  const received_at = nowIso();
  const receipt = await nextReceipt(env, received_at);
  const is_test = mode === 'test' ? 1 : 0;

  const ins = await env.DB.prepare(
    `INSERT INTO submissions (receipt, received_at, name, email, phone, title, whose, living, era, place, summary, regno, stage, is_test, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'received', ?13, ?2) RETURNING id`
  ).bind(receipt, received_at, f.name, f.email, f.phone, f.title, f.whose, f.living, f.era, f.place, f.summary, f.regno, is_test).first();
  const submission_id = ins.id;

  const storyFile = await storeFile(env, { submission_id, receipt, kind: 'story', file: story, uploaded_by: f.email });
  const recordFiles = [];
  for (const r of records) recordFiles.push(await storeFile(env, { submission_id, receipt, kind: 'record', file: r, uploaded_by: f.email }));

  const record = {
    receipt, received_at, ...f,
    consents: { age18: true, ownerOrPermission: true, registered: true, terms: true },
    story: { name: storyFile.name, size: storyFile.size, sha256: storyFile.sha256 },
    records: recordFiles.map(r => ({ name: r.name, size: r.size, sha256: r.sha256 })),
  };
  const record_sha256 = await sha256Hex(canonical(record));
  await env.DB.prepare('UPDATE submissions SET story_sha256 = ?1, record_sha256 = ?2 WHERE id = ?3')
    .bind(storyFile.sha256, record_sha256, submission_id).run();

  const dup = await env.DB.prepare('SELECT receipt FROM submissions WHERE story_sha256 = ?1 AND id <> ?2 ORDER BY id LIMIT 1')
    .bind(storyFile.sha256, submission_id).first();

  await addEvent(env, {
    submission_id, actor: f.email, action: 'received',
    detail: { receipt, story_sha256: storyFile.sha256, record_sha256, records: recordFiles.length, test: Boolean(is_test), duplicate_of: dup ? dup.receipt : null },
  });

  const s = { receipt, received_at, name: f.name, title: f.title, regno: f.regno, story_sha256: storyFile.sha256, record_sha256 };
  const t = template('receipt', s);
  const mail = await sendMail(env, { to: f.email, subject: t.subject, text: t.body });
  await env.DB.prepare(
    `INSERT INTO notices (submission_id, kind, to_email, subject, body, sent_at, status, sent_by) VALUES (?1, 'receipt', ?2, ?3, ?4, ?5, ?6, 'system')`
  ).bind(submission_id, f.email, t.subject, t.body, nowIso(), mail.status).run();

  return json({
    ok: true, receipt, received_at, title: f.title, regno: f.regno,
    story_sha256: storyFile.sha256, record_sha256, emailed: mail.status === 'sent', test: Boolean(is_test),
  });
}

export function onRequest() {
  return fail('Use POST.', 405);
}
