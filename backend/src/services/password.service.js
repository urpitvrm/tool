import { config } from '../config/index.js';
import { audit } from '../config/db.js';
import * as users from '../models/user.model.js';
import * as otpModel from '../models/otp.model.js';
import { assertPasswordPolicy, hashPassword, verifyPassword } from '../utils/password.js';
import { randomToken, sha256 } from '../utils/token.js';
import { issueDecoy, issueOtp, PURPOSES, verifyOtp } from './otp.service.js';
import { revokeAllSessions } from './session.service.js';
import { loginDetails, sendSecurityNotice } from './auth-email.service.js';
import { smtpConfigured } from './email.service.js';

const fail = (status, code, message) => Object.assign(new Error(message), { status, code });
const GENERIC = 'If an active account uses that email address, a reset code has been sent.';

/** Reject the new password if it matches one of the last N passwords. */
async function assertNotReused(userId, password) {
  for (const hash of await users.recentPasswordHashes(userId, config.auth.passwordHistory)) {
    if (await verifyPassword(hash, password)) throw fail(422, 'PASSWORD_REUSED', `Choose a password you have not used for your last ${config.auth.passwordHistory} passwords.`);
  }
}

/** `revoke`: 'all' sessions, 'others' (keep `keepSessionId`), or 'none'. */
async function storePassword(user, password, client, { revoke, keepSessionId = null, reason }) {
  assertPasswordPolicy(password, { username: user.username, email: user.email });
  await assertNotReused(user.id, password);
  await users.setPassword(user.id, await hashPassword(password));
  const revoked = revoke === 'none' ? 0 : await revokeAllSessions(user.id, reason, revoke === 'others' ? keepSessionId : null);
  sendSecurityNotice(user, 'password_changed', loginDetails(client));
  return revoked;
}

/**
 * Always returns the same response shape (with a challenge id) so callers cannot learn whether
 * the email belongs to an account.
 */
export async function forgotPassword(email, client) {
  // Configuration problems are the same for every address, so reporting them reveals nothing.
  if (!smtpConfigured()) throw fail(503, 'SMTP_NOT_CONFIGURED', 'Email delivery is not configured on the server. Contact your administrator.');
  const user = await users.findByEmail(email);
  if (!user || user.status !== 'active' || !user.email_verified) return { message: GENERIC, challenge: await issueDecoy(client) };
  try {
    // Sent in the background so response time does not reveal whether the account exists.
    const challenge = await issueOtp(user, PURPOSES.PASSWORD_RESET, { client, background: true });
    await audit(user, 'auth.password_reset_requested', {});
    const { destination: _hidden, ...rest } = challenge;
    return { message: GENERIC, challenge: rest };
  } catch (error) {
    if (error.code === 'SMTP_NOT_CONFIGURED') throw error;
    // Rate limits and delivery failures are not revealed for this endpoint either.
    console.error(`Password reset code not sent: ${error.code || error.message}`);
    return { message: GENERIC, challenge: await issueDecoy(client) };
  }
}

/** Verify the reset code and exchange it for a short-lived, single-use reset grant. */
export async function verifyResetOtp({ challengeId, otp }) {
  const challenge = await verifyOtp(challengeId, PURPOSES.PASSWORD_RESET, otp);
  const grant = randomToken();
  await otpModel.setGrant(challenge.id, sha256(grant), config.auth.resetGrantMinutes);
  return { reset_token: grant, expires_in: config.auth.resetGrantMinutes * 60 };
}

export async function resetPassword({ resetToken, password }, client) {
  const open = await otpModel.findOpenGrant(sha256(resetToken));
  if (!open) throw fail(400, 'RESET_TOKEN_INVALID', 'This reset request has expired. Start again.');
  const user = await users.findById(open.user_id);
  if (!user || user.status !== 'active') throw fail(400, 'RESET_TOKEN_INVALID', 'This reset request has expired. Start again.');
  // Validate first so a weak password does not burn the grant.
  assertPasswordPolicy(password, { username: user.username, email: user.email });
  await assertNotReused(user.id, password);
  if (!(await otpModel.consumeGrant(sha256(resetToken)))) throw fail(400, 'RESET_TOKEN_INVALID', 'This reset request has expired. Start again.');
  const revoked = await storePassword(user, password, client, { revoke: 'all', reason: 'password_reset' });
  await audit(user, 'auth.password_reset', { sessions_revoked: revoked });
  return { message: 'Password updated. Sign in with your new password.' };
}

export async function changePassword(user, sessionId, { currentPassword, newPassword }, client) {
  const account = await users.findAuthById(user.id);
  if (!(await verifyPassword(account.password_hash, currentPassword))) {
    await audit(user, 'auth.password_change_failed', { reason: 'bad_current_password' });
    throw fail(400, 'CURRENT_PASSWORD_INCORRECT', 'Your current password is incorrect.');
  }
  if (currentPassword === newPassword) throw fail(422, 'PASSWORD_REUSED', 'The new password must be different from the current one.');
  const revoked = await storePassword(account, newPassword, client, {
    reason: 'password_changed', keepSessionId: sessionId,
    revoke: config.auth.revokeOtherSessionsOnPasswordChange ? 'others' : 'none',
  });
  await audit(user, 'auth.password_changed', { other_sessions_revoked: revoked });
  return { message: 'Password changed.', other_sessions_revoked: revoked };
}

/** Invitation acceptance sets the first password (see user.service). */
export async function setInitialPassword(user, password) {
  assertPasswordPolicy(password, { username: user.username, email: user.email });
  await users.setPassword(user.id, await hashPassword(password));
}
