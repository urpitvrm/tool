# Authentication and access control

This document describes how Sentinel SOC authenticates users, verifies email addresses, manages sessions and enforces permissions. All behaviour described here is enforced by the API. The React app only mirrors it to keep the interface tidy.

## Summary

| Area | Design |
|---|---|
| Passwords | Argon2id. At least 12 characters with upper- and lower-case letters, a number and a special character. Must not contain the username or email, repeat a character 4+ times, or match a common breached password. The last 5 passwords cannot be reused. |
| Second factor | A 6-digit email code is required for every sign-in. Codes are generated with `crypto.randomInt`, valid for 5 minutes, allow 5 attempts, can be resent after 60 seconds, and are single use. At most 5 codes per account are issued per 15 minutes. |
| OTP storage | Only `HMAC-SHA256(SECRET_KEY, challengeId:code)` is stored. Codes are never logged or returned by the API. |
| Sessions | Short-lived access JWT (15 min, `aud=siem-access`, bound to a session id) plus an opaque 256-bit refresh token. Only the refresh token's SHA-256 hash is stored in `user_sessions`. Refresh tokens rotate on every use; reuse of a rotated token revokes the session. |
| Browser storage | Both tokens are HttpOnly, `SameSite=Strict` cookies (`Secure` in production). Nothing is stored in `localStorage`. The access cookie is scoped to `/api`, the refresh cookie to `/api/v1/auth`. |
| CSRF | Double-submit token: the readable `siem_csrf` cookie must be echoed in the `X-CSRF-Token` header on every state-changing request. API clients that authenticate with `Authorization: Bearer` and send no cookies are exempt. |
| Revocation | Every request checks that the session is still active, so logout, "sign out everywhere", password reset, deactivation and administrator revocation take effect immediately. |
| Lockout | 5 failed sign-ins (wrong password or an exhausted code) lock the account for 15 minutes. The user is emailed; an administrator can unlock early. |
| Rate limits | Per IP and per account/challenge on every authentication endpoint (see below), plus the existing global API limit. |
| RBAC | Permissions are the union of the user's primary role and any additional roles (`user_roles`). They are loaded per request and enforced by `requirePermission` on every protected route. |
| Audit | Sign-ins, failures, lockouts, OTP and password events, session revocations and all user administration actions are written to `audit_logs`. Every sign-in attempt is also recorded in `login_history`. |

## Workflows

### Sign-in

1. `POST /auth/login` with username or email and password.
2. The API checks, in order: account exists (an unknown account still runs a password hash to equalise timing), lock state, password, account status, and that an email address exists.
3. The API emails a `LOGIN` code (or an `EMAIL_VERIFICATION` code if the address is not yet verified) and returns a challenge: id, masked destination, expiry and resend time. **No session exists yet.**
4. `POST /auth/verify-login-otp` (or `/auth/verify-email`) with the challenge id and code. The attempt is counted atomically before the code is compared, and the code is consumed with a conditional update, so concurrent or replayed submissions cannot succeed twice.
5. On success the API creates a `user_sessions` row, sets the cookies, records `login_history`, and returns the profile with its roles and permissions.
6. If the IP address and device family (browser + OS) have not signed in successfully in the last 90 days, a *suspicious sign-in* email is sent. With `AUTH_NOTIFY_EVERY_LOGIN=true`, a *new sign-in* email is sent for every sign-in.

"Keep me signed in" issues a 30-day persistent refresh cookie. Otherwise the session lasts 12 hours and uses a browser-session cookie.

### Session refresh

When an access token expires, the app calls `POST /auth/refresh-token`. The refresh token is rotated atomically. If a client presents a token that has already been rotated away (for example a stolen copy), the whole session is revoked and the event is audited.

### Forgot and reset password

1. `POST /auth/forgot-password` with an email address. The response is always identical. For an address with no eligible account, the API creates a **decoy** challenge: a real database row whose hash can never match. A wrong code and a resend therefore behave exactly the same as for a real account. The real email is sent in the background so response time doesn't reveal anything either.
2. `POST /auth/verify-reset-otp` exchanges a valid `PASSWORD_RESET` code for a 10-minute, single-use reset token (only its hash is stored). Reset codes cannot be used for sign-in and vice versa.
3. `POST /auth/reset-password` with the reset token and the new password. The policy and reuse checks run *before* the token is consumed, so a rejected password doesn't burn it. On success all sessions are revoked, the lock state is cleared, and a *password changed* email is sent.

### Change password

`POST /auth/change-password` verifies the current password, enforces the policy and reuse rules, revokes every **other** session (configurable), audits the change and emails a notification.

### Invitations (administrator-created users)

1. An administrator with `admin:users` calls `POST /users` with full name, email, username, primary role and optional additional roles. The account is created in `invited` status with **no password**.
2. The user receives a single-use invitation link (72 hours; only the token hash is stored).
3. On `/accept-invitation`, the user chooses a password. Following the link proves ownership of the mailbox, so the email is marked verified with a timestamp and the account becomes `active`. With `AUTH_INVITE_REQUIRES_APPROVAL=true` it becomes `pending_approval` until an administrator activates it.
4. If an administrator later changes a user's email address, it becomes unverified. The next sign-in sends an `EMAIL_VERIFICATION` code to the new address, and verifying it also completes that sign-in.

### Forced password change

`POST /users/:id/force-password-change` sets `force_password_change`. Until the user changes their password, every API call except `/auth/me`, `/auth/change-password`, `/auth/sessions`, `/auth/logout(-all)` and `/auth/refresh-token` returns `403 PASSWORD_CHANGE_REQUIRED`, and the app redirects to `/change-password`.

### First Super Administrator

The old open `/auth/register` endpoint has been removed (it now returns `410`). There are two supported ways to create the first administrator:

* **CLI (recommended):** run this on the server:
  ```bash
  cd backend
  npm run admin -- create-super-admin --username admin --email admin@example.com --name "Jane Admin"
  # prompts for the password (no echo); or set ADMIN_PASSWORD for automation
  ```
  The operator has server access, so the email address is trusted as verified.
* **Browser:** set a long random `AUTH_SETUP_TOKEN` in the server environment, open `/setup`, and enter the token, your details and a password. The email address is verified by code before the account is activated. Setup is possible only while the users table is empty; concurrent attempts are serialised with a table lock. Remove `AUTH_SETUP_TOKEN` afterwards.

Other CLI commands: `set-email` (add an email address to an existing account; required for accounts created before this release), `unlock`, and `reset-password` (sets a new password, revokes sessions and forces a change at next sign-in).

## Account states

`invited` → `active` (or `pending_approval` → `active`), `pending_verification` (first administrator during browser setup) → `active`, `active` ⇄ `deactivated`. Only `active` accounts can sign in or use sessions. Deactivation revokes all sessions immediately. The last active Super Administrator cannot be deactivated or demoted, and administrators cannot deactivate themselves.

## API reference

All paths are under `/api/v1`. Error responses are `{ "error": "message", "code": "MACHINE_CODE", ... }`.

### Public (rate-limited)

| Method & path | Body | Result |
|---|---|---|
| `GET /auth/csrf` | — | `{ csrf_token }` and sets the `siem_csrf` cookie |
| `GET /auth/setup-status` | — | `{ setup_required, browser_setup_enabled }` |
| `POST /auth/setup` | `setup_token, full_name, username, email, password` | `201 { status: "email_verification_required", challenge }` |
| `POST /auth/login` | `identifier, password, remember?` | `{ status: "otp_required" \| "email_verification_required", challenge }` · `401 INVALID_CREDENTIALS` · `423 ACCOUNT_LOCKED` · `403 ACCOUNT_DEACTIVATED / ACCOUNT_PENDING / EMAIL_REQUIRED` · `503 SMTP_NOT_CONFIGURED` |
| `POST /auth/verify-login-otp` | `challenge_id, otp` | `{ status: "authenticated", user }` + cookies · `400 OTP_INCORRECT (attempts_remaining) / OTP_EXPIRED` · `429 OTP_ATTEMPTS_EXCEEDED` |
| `POST /auth/verify-email` | `challenge_id, otp` | as above, or `{ status: "pending_approval" }` |
| `POST /auth/resend-otp` | `challenge_id` | `{ challenge }` (new id; the old code stops working) · `429 OTP_RESEND_COOLDOWN (retry_after)` · `429 OTP_RATE_LIMITED` |
| `POST /auth/forgot-password` | `email` | always `{ message, challenge }` |
| `POST /auth/verify-reset-otp` | `challenge_id, otp` | `{ reset_token, expires_in }` |
| `POST /auth/reset-password` | `reset_token, password, confirm_password` | `{ message }` · `422 PASSWORD_POLICY / PASSWORD_REUSED` · `400 RESET_TOKEN_INVALID` |
| `POST /auth/invitation` | `token` | invitation details (username, role, masked email) |
| `POST /auth/accept-invitation` | `token, password` | `{ status, message }` |
| `POST /auth/password-policy` | `password, username?, email?` | `{ valid, problems }` (nothing stored) |
| `POST /auth/refresh-token` | — (refresh cookie) | rotates cookies · `401 SESSION_EXPIRED` |
| `POST /auth/logout` | — | revokes the current session and clears cookies |

### Authenticated

| Method & path | Notes |
|---|---|
| `GET /auth/me` | Profile, roles, permissions, `force_password_change`, current `session_id` |
| `POST /auth/change-password` | `current_password, new_password, confirm_password` |
| `POST /auth/logout-all` | Revokes every session of the user |
| `GET /auth/sessions` | Active sessions (device, IP, created, last used, expiry, `current`) |
| `DELETE /auth/sessions/:id` | Revoke one of your sessions |
| `GET /auth/login-history?limit=` | Your recent sign-in events |

### User administration (`admin:users`)

`GET /users`, `POST /users` (invite), `GET|PATCH /users/:id`, `POST /users/:id/activate`, `/deactivate`, `/unlock`, `/force-password-change` (`{ revoke_sessions? }`), `/resend-invitation`, `GET|DELETE /users/:id/sessions`, `GET /users/:id/login-history`, `GET /roles` (with permissions), `GET /permissions`.

## Rate limits

| Endpoint | Per IP | Per account / challenge |
|---|---|---|
| login | 10 / min | 20 / 15 min per identifier |
| verify OTP (login, email, reset) | 20 / min | 10 / 15 min per challenge (plus 5 attempts per code) |
| resend OTP | 6 / min | 10 / 15 min per challenge; 5 codes / 15 min per account and purpose |
| forgot password | 10 / 15 min | 3 / 15 min per email |
| reset, setup, invitations, change password | 20 / 15 min | — |
| refresh | 60 / min | — |

`AUTH_RATE_LIMIT_MULTIPLIER` scales these limits for automated tests only; keep it at 1 in production.

## Roles

Existing roles are kept (they are referenced by id). The requested defaults map as follows:

| Requested | Role in the application |
|---|---|
| Super Admin | Super Administrator |
| Admin | Security Administrator (everything except `admin:users`) |
| Security Analyst | Security Analyst |
| SOC Analyst | SOC Analyst *(new)*: dashboards, events, incidents, agents, reports (read) |
| Auditor | Auditor *(new)*: read-only dashboards, events, agents, compliance, reports, plus `audit:read` |
| Report Viewer | Report Viewer *(new)*: dashboards and reports (read) |
| Read Only User | Read Only Analyst (all `*:read` permissions) |

SOC Manager, Threat Hunter and Compliance Analyst remain available.

## Database

Migration `003_authentication` makes these changes:

* **`users`:** adds `full_name`, `email` (case-insensitive unique), `email_verified(_at)`, `status`, `failed_login_attempts`, `locked_until`, `last_login_at`, `force_password_change`, `password_changed_at`, `invited_by` and `updated_at`. `password_hash` becomes nullable for invited users. A trigger keeps the legacy `disabled` flag derived from `status`.
* **`otp_verifications`:** UUID challenges for `LOGIN`, `EMAIL_VERIFICATION`, `PASSWORD_RESET` and `INVITATION`, with hash, expiry, attempts, resend time, consumed/invalidated timestamps and the reset-grant hash.
* **`user_sessions`:** the previous `sessions` table, renamed and extended (it stored JWT hashes but was never checked; its old rows are marked revoked). Adds the refresh and previous token hashes, device, IP, user agent, remember flag, last use and revocation details.
* **`login_history`:** every sign-in attempt and outcome, including IP address, user agent and device.
* **`password_history`:** previous password hashes, seeded with each user's current hash.

An hourly job deletes unusable OTP challenges (24 h after expiry), sessions 7 days after they end, and login history older than `AUTH_LOGIN_HISTORY_DAYS` (365).

## Email

Templates live in `backend/src/templates/`: `layout.html`, `loginOtp.html`, `emailVerification.html`, `passwordReset.html`, `accountInvitation.html` and `securityNotification.html`. The security notification template covers account activated, account deactivated, password changed, new sign-in, suspicious sign-in and account locked. Every message has an HTML and a plain-text part, shows the platform name and a security warning, and includes the support contact. That contact comes from `SUPPORT_CONTACT`, which administrators can override by saving the application setting `auth.support_contact`. Values are HTML-escaped.

If SMTP is not configured, sign-in fails with `503 SMTP_NOT_CONFIGURED`, because codes cannot be delivered. For local development without a mail server, either point SMTP at a local mail catcher (for example Mailpit) or set `AUTH_LOGIN_OTP_ENABLED=false`. Never use that setting in production; the server logs a warning if you do.
