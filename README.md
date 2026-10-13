# Untold Stories and Unsung Heroes

Story submission website and admin back end for "Untold Stories and Unsung Heroes," a limited series of stories based on true events.

## Sites

- Review site: https://dev.limitedseries.net (not indexed by search engines)
- Admin site: https://admin.limitedseries.net (sign-in through Cloudflare Access)
- Receipt check: https://dev.limitedseries.net/verify/
- Future public site: https://untoldunsung.com

## Layout

- `public/` static pages: the main site, `verify/`, and `admin/` (served only at the admin address)
- `functions/` server code run by Cloudflare Pages Functions
  - `api/submit.js` receives a story, stores the files, fingerprints them, and issues the receipt number
  - `api/verify.js` public receipt check (date and fingerprints only)
  - `api/admin/[[path]].js` admin API: review, selection, notices, rights sign-off, proposal package, recipients, tracking
  - `_middleware.js` routes by address and checks the admin sign-in on every admin request
- `lib/` shared code: database schema, event history chain, sign-in check, email
- `wrangler.toml` bindings and settings Cloudflare uses at deploy

## Cloudflare services

- Pages project `untold-stories`, deployed on push to `main`
- D1 database `untold-stories` (binding `DB`); tables are created on first use
- R2 bucket `untold-stories-files` (binding `FILES`); files are written once and never replaced
- Access application "Untold Unsung Admin" on admin.limitedseries.net; the people allowed to sign in are set in its policy
- Email through Resend (https://resend.com) once the `RESEND_API_KEY` secret and `MAIL_FROM` setting are added; until then notices are recorded but not sent

## Settings in wrangler.toml

- `SUBMISSIONS_MODE`: `test` (submissions accepted and marked as tests), `open`, or `closed`
- `OWNER_EMAIL`: emails that become administrators on first sign-in
- `ADMIN_HOSTS`: the admin address

## Status

- The public form is in test mode until legal counsel approves the terms.
- The submission terms and notice wording are drafts pending review by legal counsel.
