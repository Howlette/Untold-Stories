// Email through Resend (https://resend.com). If no key is configured the
// notice is still recorded, marked as not sent.

export function mailConfigured(env) {
  return Boolean(env.RESEND_API_KEY && env.MAIL_FROM);
}

export async function sendMail(env, { to, subject, text }) {
  if (!mailConfigured(env)) return { status: 'not sent: email not configured' };
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, text, reply_to: env.MAIL_REPLY_TO || undefined }),
  });
  if (res.ok) {
    const data = await res.json().catch(() => ({}));
    return { status: 'sent', id: data.id || '' };
  }
  const err = await res.text().catch(() => '');
  return { status: `failed: ${res.status} ${err.slice(0, 200)}` };
}

const SITE = 'https://dev.limitedseries.net';

// Draft wording. All notice text goes to legal counsel before launch.
export function template(kind, s) {
  const head = `Receipt number: ${s.receipt}\nStory title: ${s.title}\n`;
  switch (kind) {
    case 'receipt':
      return {
        subject: `We received your story: ${s.receipt}`,
        body: `Dear ${s.name},\n\nWe received your story. Keep this email as your receipt.\n\n${head}` +
          `Received: ${s.received_at} (Coordinated Universal Time)\nCopyright registration number: ${s.regno}\n` +
          `Story file fingerprint (SHA-256): ${s.story_sha256}\nSubmission record fingerprint (SHA-256): ${s.record_sha256}\n\n` +
          `You can check this receipt at any time at ${SITE}/verify/\n\nUntold Stories and Unsung Heroes`,
      };
    case 'not_selected':
      return {
        subject: `Your story submission: ${s.receipt}`,
        body: `Dear ${s.name},\n\nThank you for sharing "${s.title}" with us. Your story was not selected this cycle. ` +
          `You remain free to share it anywhere else.\n\n${head}\nUntold Stories and Unsung Heroes`,
      };
    case 'selected':
      return {
        subject: `Your story has been selected: ${s.receipt}`,
        body: `Dear ${s.name},\n\nWe are pleased to tell you that "${s.title}" has been selected for development.\n\n` +
          `Before any development begins, we need two signed documents from you: an acknowledgement and a rights agreement. ` +
          `We will send both for signature separately. Selection does not guarantee production.\n\n${head}\nUntold Stories and Unsung Heroes`,
      };
    case 'signing_request':
      return {
        subject: `Documents to sign: ${s.receipt}`,
        body: `Dear ${s.name},\n\nPlease review and sign the acknowledgement and the rights agreement for "${s.title}". ` +
          `Development begins only after both are signed.\n\n[Signing links]\n\n${head}\nUntold Stories and Unsung Heroes`,
      };
    case 'milestone':
      return {
        subject: `An update on your story: ${s.receipt}`,
        body: `Dear ${s.name},\n\n[Milestone]\n\n${head}\nUntold Stories and Unsung Heroes`,
      };
    case 'closing':
      return {
        subject: `Your story file is closed: ${s.receipt}`,
        body: `Dear ${s.name},\n\nWe have closed the file for "${s.title}".\n\n[Outcome]\n\n` +
          `We keep records for the period set by our legal counsel.\n\n${head}\nUntold Stories and Unsung Heroes`,
      };
    default:
      return { subject: `About your story: ${s.receipt}`, body: `Dear ${s.name},\n\n\n\n${head}` };
  }
}
