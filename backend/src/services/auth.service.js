import { config } from '../config/index.js';
import { audit, pool } from '../config/db.js';
import * as users from '../models/user.model.js';
import * as sessionModel from '../models/session.model.js';
import { burnPasswordCheck, hashPassword, assertPasswordPolicy, verifyPassword } from '../utils/password.js';
import { safeEqual } from '../utils/token.js';
import { issueOtp, PURPOSES, verifyOtp } from './otp.service.js';
import { startSession } from './session.service.js';
import { loginDetails, sendSecurityNotice } from './auth-email.service.js';

const fail = (status, code, message, extra = {}) => Object.assign(new Error(message), { status, code, ...extra });
const INVALID = () => fail(401, 'INVALID_CREDENTIALS', 'Invalid username/email or password.');
const STATUS_ERRORS = {
  deactivated: () => fail(403, 'ACCOUNT_DEACTIVATED', 'This account is deactivated. Contact your administrator.'),
  invited: () => fail(403, 'ACCOUNT_PENDING', 'This account has not been activated yet. Use the invitation email to finish setup.'),
  pending_verification: () => fail(403, 'ACCOUNT_PENDING', 'This account has not finished email verification.'),
  pending_approval: () => fail(403, 'ACCOUNT_PENDING_APPROVAL', 'This account is waiting for administrator approval.'),
};

const event = (client, fields) => sessionModel.recordLoginEvent({ ip: client.ip, userAgent: client.userAgent, device: client.device, ...fields });

/** Payload returned by /auth/me and after sign-in. */
export async function profile(userId, sessionId) {
  const user = await users.findById(userId);
  const [roles, permissions] = await Promise.all([users.rolesForUser(userId), users.permissionsForUser(userId)]);
  return {
    id: user.id, username: user.username, full_name: user.full_name, email: user.email, email_verified: user.email_verified,
    status: user.status, role_id: user.role_id, role: user.role, roles, permissions,
    force_password_change: user.force_password_change, last_login_at: user.last_login_at, password_changed_at: user.password_changed_at,
    session_id: sessionId,
  };
}

async function countFailure(user, client, reason) {
  const result = await users.recordFailedLogin(user.id, config.auth.maxFailedLogins, config.auth.lockMinutes);
  await event(client, { userId: user.id, email: user.email, status: 'failed', reason });
  if (result.locked && result.failed_login_attempts === config.auth.maxFailedLogins) {
    await audit(user, 'auth.account_locked', { reason });
    sendSecurityNotice(user, 'account_locked', loginDetails(client, { 'Locked until': `${new Date(result.locked_until).toISOString().slice(0, 16).replace('T', ' ')} UTC` }));
  }
  return result;
}

/**
 * Step 1: verify credentials and account state, then email a code.
 * No session exists until the code is verified.
 */
export async function login({ identifier, password, remember }, client) {
  const user = await users.findAuthByIdentifier(identifier);
  if (!user) {
    await burnPasswordCheck(password);
    await event(client, { identifier, status: 'failed', reason: 'unknown_account' });
    throw INVALID();
  }
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    await event(client, { userId: user.id, email: user.email, status: 'locked', reason: 'account_locked' });
    throw fail(423, 'ACCOUNT_LOCKED', 'This account is temporarily locked after repeated failed sign-in attempts. Try again later.', { lockedUntil: user.locked_until });
  }
  if (!(await verifyPassword(user.password_hash, password))) {
    const result = await countFailure(user, client, 'bad_password');
    if (result.locked) throw fail(423, 'ACCOUNT_LOCKED', 'Too many failed attempts. This account is temporarily locked.', { lockedUntil: result.locked_until });
    throw INVALID();
  }
  if (user.status !== 'active') {
    await event(client, { userId: user.id, email: user.email, status: 'failed', reason: `status_${user.status}` });
    throw (STATUS_ERRORS[user.status] || INVALID)();
  }
  if (!user.email) {
    await event(client, { userId: user.id, status: 'failed', reason: 'no_email' });
    throw fail(403, 'EMAIL_REQUIRED', 'This account has no email address for sign-in verification. Ask an administrator to add one.');
  }

  if (!config.auth.loginOtpEnabled) return completeLogin(user, { remember, client, method: 'password_only' });

  // An unverified address is verified as part of sign-in: the code goes to it and proves ownership.
  const purpose = user.email_verified ? PURPOSES.LOGIN : PURPOSES.EMAIL_VERIFICATION;
  const challenge = await issueOtp(user, purpose, { client, remember: Boolean(remember) });
  await event(client, { userId: user.id, email: user.email, status: 'otp_sent', reason: purpose.toLowerCase() });
  return { status: purpose === PURPOSES.LOGIN ? 'otp_required' : 'email_verification_required', challenge };
}

async function handleOtpError(error, client) {
  if (error.userId && (error.exhausted || error.code === 'OTP_ATTEMPTS_EXCEEDED')) {
    const user = await users.findById(error.userId);
    if (user) await countFailure(user, client, 'otp_attempts_exceeded');
  } else if (error.userId) {
    await event(client, { userId: error.userId, status: 'failed', reason: 'otp_incorrect' });
  }
  throw error;
}

/** Step 2: verify the login code and create the session. */
export async function verifyLoginOtp({ challengeId, otp }, client) {
  const challenge = await verifyOtp(challengeId, PURPOSES.LOGIN, otp).catch((error) => handleOtpError(error, client));
  const user = await users.findAuthById(challenge.user_id);
  return completeLogin(user, { remember: challenge.remember, client, method: 'email_otp' });
}

/** Verify an email-verification code; marks the address verified and finishes sign-in or setup. */
export async function verifyEmail({ challengeId, otp }, client) {
  const challenge = await verifyOtp(challengeId, PURPOSES.EMAIL_VERIFICATION, otp).catch((error) => handleOtpError(error, client));
  const user = await users.findAuthById(challenge.user_id);
  await users.markEmailVerified(user.id);
  if (user.status === 'pending_verification') {
    await users.setStatus(user.id, config.auth.inviteRequiresApproval && user.role !== 'Super Administrator' ? 'pending_approval' : 'active');
  }
  await audit(user, 'auth.email_verified', {});
  const fresh = await users.findAuthById(user.id);
  if (fresh.status !== 'active') return { status: 'pending_approval', message: 'Email verified. An administrator must approve the account before you can sign in.' };
  return completeLogin(fresh, { remember: challenge.remember, client, method: 'email_verification' });
}

async function completeLogin(user, { remember, client, method }) {
  if (user.status !== 'active') throw (STATUS_ERRORS[user.status] || INVALID)();
  const [known, prior] = await Promise.all([
    sessionModel.isKnownDevice(user.id, client.ip, client.device), sessionModel.hasPriorSuccess(user.id),
  ]);
  const tokens = await startSession(user, { remember: Boolean(remember), client });
  await users.recordSuccessfulLogin(user.id);
  await event(client, { userId: user.id, email: user.email, status: 'success', reason: method });
  await audit(user, 'auth.login', { method, session_id: tokens.session.id });
  if (prior && !known) sendSecurityNotice(user, 'suspicious_login', loginDetails(client));
  else if (config.auth.notifyEveryLogin) sendSecurityNotice(user, 'new_login', loginDetails(client));
  return { status: 'authenticated', tokens, user: await profile(user.id, tokens.session.id) };
}

// ---- First Super Admin setup -------------------------------------------------------------------

export async function setupStatus() {
  const count = await users.countUsers();
  return { setup_required: count === 0, browser_setup_enabled: count === 0 && Boolean(config.auth.setupToken) };
}

/**
 * Browser setup is possible only while no users exist AND the operator supplied AUTH_SETUP_TOKEN.
 * The address is verified by OTP before the account becomes active.
 */
export async function setupSuperAdmin({ setupToken, fullName, username, email, password }, client) {
  if (!config.auth.setupToken) throw fail(403, 'SETUP_DISABLED', 'Browser setup is disabled. Create the first administrator with the CLI (npm run admin -- create-super-admin).');
  if (!safeEqual(setupToken, config.auth.setupToken)) {
    await event(client, { identifier: username, status: 'failed', reason: 'bad_setup_token' });
    throw fail(403, 'SETUP_TOKEN_INVALID', 'The setup token is incorrect.');
  }
  assertPasswordPolicy(password, { username, email });
  const roleId = await users.getBootstrapRoleId();
  if (!roleId) throw new Error('Super Administrator role is not configured');
  const passwordHash = await hashPassword(password);
  const client2 = await pool.connect();
  let created;
  try {
    await client2.query('BEGIN');
    await client2.query('LOCK TABLE users IN EXCLUSIVE MODE'); // serializes concurrent setup attempts
    const { rows } = await client2.query('SELECT COUNT(*)::int AS n FROM users');
    if (rows[0].n > 0) throw fail(409, 'SETUP_COMPLETE', 'Setup is already complete. Sign in instead.');
    created = await users.insertUser({ username, fullName, email, passwordHash, roleId, status: 'pending_verification' }, client2);
    await client2.query('COMMIT');
  } catch (error) {
    await client2.query('ROLLBACK');
    throw error;
  } finally {
    client2.release();
  }
  const user = await users.findById(created.id);
  await audit(user, 'auth.bootstrap', { method: 'browser_setup' });
  return { status: 'email_verification_required', challenge: await issueOtp(user, PURPOSES.EMAIL_VERIFICATION, { client }) };
}
