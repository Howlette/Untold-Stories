# Untold Stories and Unsung Heroes

Story submission website and admin back end for "Untold Stories and Unsung Heroes," a limited series of stories based on true events.

## Sites

- Review site: https://dev.limitedseries.net (not indexed by search engines)
- Admin site: https://admin.limitedseries.net (email and password sign-in)
- Receipt check: https://dev.limitedseries.net/verify/
- Future public site: https://untoldunsung.com

## Layout

- `public/` static pages: the main site, `verify/`, and `admin/` (served only at the admin address)
- `functions/` server code run by Cloudflare Pages Functions
  - `api/submit.js` receives a story, stores the files, fingerprints them, and issues the receipt number
  - `api/verify.js` public receipt check (date and fingerprints only)
  - `api/admin/[[path]].js` admin API: review, selection, notices, rights sign-off, proposal package, recipients, tracking
  - `_middleware.js` routes by address, serves the admin sign-in page, and checks the session on every admin request
- `lib/` shared code: database schema, event history chain, password sign-in and sessions, email
- `wrangler.toml` bindings and settings Cloudflare uses at deploy

## Cloudflare services

- Pages project `untold-stories`, deployed on push to `main`
- D1 database `untold-stories` (binding `DB`); tables are created on first use
- R2 bucket `untold-stories-files` (binding `FILES`); files are written once and never replaced
- Email through Resend (https://resend.com) once the `RESEND_API_KEY` secret and `MAIL_FROM` setting are added; until then notices are recorded but not sent

## Settings in wrangler.toml

- `SUBMISSIONS_MODE`: `test` (submissions accepted and marked as tests), `open`, or `closed`
- `OWNER_EMAIL`: the first administrator
- `OWNER_PASSWORD_HASH`: the first administrator's starting password, stored only as a hash and used once
- `ADMIN_HOSTS`: the admin address

## Admin sign-in

- Passwords are stored as PBKDF2-SHA256 hashes; sessions last 12 hours in a secure cookie.
- Five wrong passwords lock an account for 15 minutes.
- Administrators add users under Users with a temporary password; the user must choose a new one at first sign-in.
- Everyone can change their own password under My account.

## Status

- The public form is in test mode until legal counsel approves the terms.
- The submission terms and notice wording are drafts pending review by legal counsel.
