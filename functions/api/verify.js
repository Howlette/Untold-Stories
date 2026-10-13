// Public receipt check. Returns only the date and fingerprints, never personal details.
import { json, fail, clean } from '../../lib/util.js';

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const receipt = clean(url.searchParams.get('receipt'), 40).toUpperCase();
  if (!/^UU-\d{4}-\d{6}$/.test(receipt)) return fail('Enter a receipt number in the form UU-2026-000123.');
  const s = await env.DB.prepare('SELECT receipt, received_at, story_sha256, record_sha256 FROM submissions WHERE receipt = ?1')
    .bind(receipt).first();
  if (!s) return json({ found: false }, 404);
  return json({ found: true, ...s });
}
